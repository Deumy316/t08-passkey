import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, g, jsonify, request, send_file, abort
from webauthn import (generate_registration_options, generate_authentication_options,
                      verify_registration_response, verify_authentication_response,
                      options_to_json, base64url_to_bytes)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
    ResidentKeyRequirement, UserVerificationRequirement, PublicKeyCredentialDescriptor)

ROOT = Path(__file__).resolve().parent


def create_app(db_path=None):
    app = Flask(__name__)
    production = os.getenv('APP_ENV') == 'production'
    origin = os.getenv('APP_ORIGIN', 'http://localhost:5008')
    rp = os.getenv('RP_ID', 'localhost')
    parsed = urlparse(origin)
    if parsed.hostname != rp or parsed.path or parsed.query or parsed.fragment:
        raise RuntimeError('APP_ORIGIN must be an origin whose hostname equals RP_ID')
    if production and parsed.scheme != 'https':
        raise RuntimeError('Production requires HTTPS APP_ORIGIN and RP_ID')
    if not production and origin != 'http://localhost:5008':
        raise RuntimeError('Development uses http://localhost:5008 only')
    app.config.update(MAX_CONTENT_LENGTH=32768, TRUSTED_HOSTS=[rp])
    path = Path(db_path) if db_path else ROOT / 'instance' / 'passkeys.sqlite3'
    path.parent.mkdir(parents=True, exist_ok=True)
    cookie = '__Host-t08-passkey-session' if production else 't08_passkey_session'

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(path, timeout=10, isolation_level=None)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
        return g.db

    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials(
          id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
          public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, name TEXT NOT NULL,
          created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
          device TEXT NOT NULL, backed_up INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, csrf TEXT NOT NULL, user_id TEXT REFERENCES users(id), expires REAL NOT NULL, grant_action TEXT, grant_target TEXT, grant_until REAL);
        CREATE TABLE IF NOT EXISTS challenges(session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
          kind TEXT NOT NULL, challenge BLOB NOT NULL, expires REAL NOT NULL, payload TEXT NOT NULL);
        ''')
        g.db.close()
        g.pop('db')

    @app.teardown_appcontext
    def close(_):
        if 'db' in g:
            g.db.close()

    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def new_session(uid=None):
        if getattr(g, 'sid', None):
            db().execute('DELETE FROM sessions WHERE id=?', (g.sid,))
        token = secrets.token_urlsafe(32)
        g.sid = digest(token)
        db().execute('INSERT INTO sessions(id,csrf,user_id,expires) VALUES(?,?,?,?)',
                     (g.sid, secrets.token_urlsafe(32), uid, time.time()+3600))
        g.cookie_token = token
        g.session = db().execute('SELECT * FROM sessions WHERE id=?', (g.sid,)).fetchone()

    @app.before_request
    def security():
        if not request.path.startswith('/api/'):
            return
        db().execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
        db().execute('DELETE FROM challenges WHERE expires<?', (time.time(),))
        g.sid = digest(request.cookies.get(cookie, ''))
        g.session = db().execute('SELECT * FROM sessions WHERE id=?', (g.sid,)).fetchone()
        if request.path == '/api/session' and request.method == 'GET' and not g.session:
            new_session()
        if not g.session:
            abort(401, '세션이 없습니다. 새로고침 후 로그인하세요.')
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            if request.headers.get('Origin') != origin or not secrets.compare_digest(
                    request.headers.get('X-CSRF-Token', ''), g.session['csrf']):
                abort(403, 'Origin 또는 CSRF 검증 실패')
            if not request.is_json:
                abort(415, 'JSON 요청이 필요합니다.')

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if production:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if hasattr(g, 'cookie_token'):
            response.set_cookie(cookie, g.cookie_token, httponly=True, secure=production,
                                samesite='Strict', max_age=3600, path='/')
        if request.path.startswith('/api/'):
            # Never log request bodies, cookies, CSRF tokens or full challenges.
            app.logger.info('%s %s status=%s', request.method, request.path, response.status_code)
        return response

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(415)
    def error(e):
        return jsonify(error=e.description), e.code

    def data():
        value = request.get_json()
        if not isinstance(value, dict):
            abort(400, 'JSON 객체가 필요합니다.')
        return value

    def logged_in():
        if not g.session['user_id']:
            abort(401, '로그인이 필요합니다.')
        return g.session['user_id']

    def owner(value):
        uid = logged_in()
        if value is not None and value != uid:
            abort(403, '다른 계정의 자료에는 접근할 수 없습니다.')
        return uid

    def save_challenge(kind, options, payload):
        db().execute('INSERT OR REPLACE INTO challenges VALUES(?,?,?,?,?)',
                     (g.sid, kind, options.challenge, time.time()+120, json.dumps(payload)))
        app.logger.info('challenge kind=%s fingerprint=%s', kind,
                        hashlib.sha256(options.challenge).hexdigest()[:16])
        return app.response_class(options_to_json(options), mimetype='application/json')

    def consume(kind):
        # DELETE RETURNING is atomic: concurrent requests cannot reuse a challenge.
        row = db().execute('DELETE FROM challenges WHERE session_id=? RETURNING *', (g.sid,)).fetchone()
        if not row or row['kind'] != kind or row['expires'] < time.time():
            abort(400, 'challenge가 만료되었거나 이미 사용되었습니다.')
        return row, json.loads(row['payload'])

    def grant(action, target=''):
        row = db().execute('UPDATE sessions SET grant_action=NULL,grant_target=NULL,grant_until=NULL '
            'WHERE id=? AND grant_action=? AND grant_target=? AND grant_until>? RETURNING id',
            (g.sid, action, target, time.time())).fetchone()
        if not row:
            abort(403, '이 작업을 위해 패스키로 다시 본인 인증하세요.')

    @app.get('/')
    def index():
        return send_file(ROOT / 'index.html')

    @app.get('/api/session')
    def session_info():
        user = db().execute('SELECT id,name FROM users WHERE id=?', (g.session['user_id'],)).fetchone()
        return jsonify(csrf=g.session['csrf'], user=dict(user) if user else None)

    @app.post('/api/register/options')
    def register_options():
        body = data()
        name = str(body.get('name', '')).strip()
        label = str(body.get('label', '')).strip()
        if not 1 <= len(label) <= 60:
            abort(400, '패스키 이름은 1~60자입니다.')
        if body.get('mode') == 'add':
            uid = logged_in()
            grant('add')
            name = db().execute('SELECT name FROM users WHERE id=?', (uid,)).fetchone()['name']
        elif body.get('mode') == 'new':
            if g.session['user_id']:
                abort(409, '새 계정은 로그아웃 후 만드세요.')
            if not re.fullmatch(r'[a-zA-Z0-9_-]{3,32}', name):
                abort(400, '계정 이름은 영문·숫자·밑줄·하이픈 3~32자입니다.')
            if db().execute('SELECT 1 FROM users WHERE name=?', (name,)).fetchone():
                abort(409, '이미 있는 계정입니다. 로그인하세요.')
            uid = secrets.token_hex(16)
        else:
            abort(400, '등록 모드를 지정하세요.')
        ids = db().execute('SELECT id FROM credentials WHERE user_id=?', (uid,)).fetchall()
        options = generate_registration_options(rp_id=rp, rp_name='T08 비공개 공간',
            user_id=bytes.fromhex(uid), user_name=name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=r['id']) for r in ids])
        return save_challenge('register', options, dict(uid=uid, name=name, label=label, mode=body['mode']))

    @app.post('/api/register/verify')
    def register_verify():
        row, pending = consume('register')
        if pending['mode'] == 'add' and logged_in() != pending['uid']:
            abort(403)
        try:
            result = verify_registration_response(credential=data()['credential'],
                expected_challenge=row['challenge'], expected_rp_id=rp,
                expected_origin=origin, require_user_verification=True)
        except Exception:
            abort(400, '패스키 등록 검증 실패. 다시 시작하세요.')
        conn = db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            if pending['mode'] == 'new':
                conn.execute('INSERT INTO users VALUES(?,?)', (pending['uid'], pending['name']))
                for n in range(1, 4):
                    conn.execute('INSERT INTO notes VALUES(?,?,?)', (secrets.token_hex(12), pending['uid'],
                        f"{pending['name']} 전용 가상 메모 {n}: 연습 프로젝트 {secrets.token_hex(4)}"))
            conn.execute('INSERT INTO credentials(id,user_id,public_key,sign_count,name,device,backed_up) VALUES(?,?,?,?,?,?,?)',
                (result.credential_id, pending['uid'], result.credential_public_key, result.sign_count,
                 pending['label'], result.credential_device_type.value, int(result.credential_backed_up)))
            new_session(pending['uid'])
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            abort(409, '계정 또는 패스키가 이미 등록되어 있습니다.')
        return jsonify(ok=True), 201

    @app.post('/api/auth/options')
    def auth_options():
        body = data()
        action = body.get('action', 'login')
        if action not in ('login', 'add', 'delete'):
            abort(400)
        uid = None if action == 'login' else logged_in()
        target = str(body.get('target', '')) if action == 'delete' else ''
        ids = db().execute('SELECT id FROM credentials WHERE user_id=?', (uid,)).fetchall() if uid else []
        options = generate_authentication_options(rp_id=rp,
            allow_credentials=[PublicKeyCredentialDescriptor(id=r['id']) for r in ids],
            user_verification=UserVerificationRequirement.REQUIRED)
        return save_challenge('auth', options, dict(uid=uid, action=action, target=target))

    @app.post('/api/auth/verify')
    def auth_verify():
        row, pending = consume('auth')
        try:
            cred = data()['credential']
            cid = base64url_to_bytes(cred['id'])
        except Exception:
            abort(400, '잘못된 인증 응답입니다.')
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        key = conn.execute('SELECT * FROM credentials WHERE id=?', (cid,)).fetchone()
        if not key:
            conn.rollback()
            abort(401, '등록되지 않았거나 삭제된 패스키입니다.')
        if pending['uid'] and key['user_id'] != pending['uid']:
            conn.rollback()
            abort(403, '다른 계정의 패스키입니다.')
        try:
            handle = cred['response'].get('userHandle')
            if handle and base64url_to_bytes(handle) != bytes.fromhex(key['user_id']):
                raise ValueError('userHandle mismatch')
            result = verify_authentication_response(credential=cred,
                expected_challenge=row['challenge'], expected_rp_id=rp, expected_origin=origin,
                credential_public_key=key['public_key'], credential_current_sign_count=key['sign_count'],
                require_user_verification=True)
        except Exception:
            conn.rollback()
            abort(400, '서명 또는 WebAuthn 인증 검증 실패')
        conn.execute('UPDATE credentials SET sign_count=?,device=?,backed_up=? WHERE id=?',
            (result.new_sign_count, result.credential_device_type.value, int(result.credential_backed_up), cid))
        if pending['action'] == 'login':
            new_session(key['user_id'])
        else:
            conn.execute('UPDATE sessions SET grant_action=?,grant_target=?,grant_until=? WHERE id=?',
                (pending['action'], pending['target'], time.time()+120, g.sid))
        conn.commit()
        return jsonify(ok=True)

    @app.post('/api/cancel')
    def cancel():
        db().execute('DELETE FROM challenges WHERE session_id=?', (g.sid,))
        db().execute('UPDATE sessions SET grant_action=NULL,grant_target=NULL,grant_until=NULL WHERE id=?', (g.sid,))
        return jsonify(ok=True)

    @app.post('/api/logout')
    def logout():
        new_session()
        return jsonify(ok=True)

    @app.route('/api/notes', methods=['GET', 'POST'])
    def notes():
        uid = owner(request.args.get('account_id'))
        if request.method == 'POST':
            owner(data().get('account_id'))
        return jsonify(notes=[dict(r) for r in db().execute('SELECT id,body FROM notes WHERE user_id=?', (uid,))])

    @app.get('/api/accounts/<account_id>/notes')
    def account_notes(account_id):
        owner(account_id)
        return notes()

    @app.get('/api/notes/<note_id>')
    def note(note_id):
        logged_in()
        row = db().execute('SELECT * FROM notes WHERE id=?', (note_id,)).fetchone()
        if not row:
            abort(404)
        owner(row['user_id'])
        return jsonify(id=row['id'], body=row['body'])

    @app.get('/api/passkeys')
    def passkeys():
        uid = logged_in()
        return jsonify(passkeys=[dict(r) for r in db().execute(
            'SELECT lower(hex(id)) id,name,created FROM credentials WHERE user_id=? ORDER BY created', (uid,))])

    @app.delete('/api/passkeys/<key_id>')
    def delete_key(key_id):
        uid = logged_in()
        grant('delete', key_id)
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT user_id FROM credentials WHERE lower(hex(id))=?', (key_id,)).fetchone()
        if not row or row['user_id'] != uid:
            conn.rollback()
            abort(403, '본인 패스키만 삭제할 수 있습니다.')
        if conn.execute('SELECT count(*) FROM credentials WHERE user_id=?', (uid,)).fetchone()[0] <= 1:
            conn.rollback()
            abort(409, '마지막 패스키는 삭제할 수 없습니다.')
        conn.execute('DELETE FROM credentials WHERE lower(hex(id))=?', (key_id,))
        conn.commit()
        return jsonify(ok=True)

    return app


if __name__ == '__main__':
    import logging
    from waitress import serve
    logging.basicConfig(level=logging.INFO)
    serve(create_app(), host='127.0.0.1', port=5008)
