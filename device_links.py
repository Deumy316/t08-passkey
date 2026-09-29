"""Two-device enrollment. Pending public keys never authenticate until PC approval."""
import hashlib
import secrets
import sqlite3
import time

import qrcode
from qrcode.image.svg import SvgPathFillImage
from flask import g, jsonify, abort, send_file
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
    ResidentKeyRequirement, UserVerificationRequirement, PublicKeyCredentialDescriptor)


def setup_device_links(app, db, data, logged_in, grant, save_challenge, consume, origin, rp, root):
    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS device_links (
          id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
          user_id TEXT NOT NULL REFERENCES users(id),
          pc_session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
          phone_session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
          expires REAL NOT NULL, state TEXT NOT NULL,
          credential_id BLOB, public_key BLOB, sign_count INTEGER,
          label TEXT, device TEXT, backed_up INTEGER, code TEXT, binding TEXT);
        ''')

    def get_link(link_id, side=None, states=None):
        row = db().execute('SELECT * FROM device_links WHERE id=?', (link_id,)).fetchone()
        if not row:
            abort(404, '연결 요청이 없거나 세션이 종료되었습니다.')
        if side == 'pc':
            if logged_in() != row['user_id'] or g.sid != row['pc_session']:
                abort(403, '요청을 만든 PC 세션에서만 처리할 수 있습니다.')
        elif side == 'phone':
            if g.sid != row['phone_session']:
                abort(403, '연결된 기기 세션이 아닙니다.')
        elif g.sid not in (row['pc_session'], row['phone_session']):
            abort(403)
        if row['expires'] <= time.time():
            abort(409, '연결 요청이 만료되었습니다. PC에서 다시 시작하세요.')
        if states and row['state'] not in states:
            abort(409, '이미 처리되거나 취소된 연결 요청입니다.')
        return row

    def approval_target(link_id):
        row = get_link(link_id, 'pc', ('pending',))
        return row['id'] + ':' + row['binding']

    @app.get('/link-device')
    def page():
        return send_file(root / 'link-device.html')

    @app.post('/api/device-links')
    def create():
        uid = logged_in()
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        grant('link-create')
        # Only one live link per creator session. Replacing it revokes the old one.
        conn.execute("DELETE FROM device_links WHERE pc_session=? OR expires<?", (g.sid, time.time()))
        token = secrets.token_urlsafe(32)
        link_id = secrets.token_hex(16)
        expires = time.time()+300
        conn.execute('INSERT INTO device_links(id,token_hash,user_id,pc_session,expires,state) VALUES(?,?,?,?,?,?)',
            (link_id, hashlib.sha256(token.encode()).hexdigest(), uid, g.sid, expires, 'open'))
        conn.commit()
        # Fragment is not sent to HTTP/access logs. Token is exchanged once via POST.
        url = origin + '/link-device#' + token
        svg = qrcode.make(url, image_factory=SvgPathFillImage).to_string(encoding='unicode')
        return jsonify(id=link_id, url=url, qr=svg, expires=expires), 201

    @app.post('/api/device-links/claim')
    def claim():
        token = data().get('token', '')
        if not isinstance(token, str) or not 40 <= len(token) <= 100:
            abort(400, '올바른 연결 링크가 필요합니다.')
        if g.session['user_id']:
            abort(409, '새 기기에서는 로그아웃한 상태로 링크를 여세요.')
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute("UPDATE device_links SET phone_session=?,state='claimed' "
            "WHERE token_hash=? AND state='open' AND expires>? RETURNING id,user_id,expires",
            (g.sid, hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        if not row:
            abort(409, '링크가 만료되었거나 이미 사용되었습니다.')
        name = conn.execute('SELECT name FROM users WHERE id=?', (row['user_id'],)).fetchone()['name']
        conn.commit()
        return jsonify(id=row['id'], account=name, expires=row['expires'])

    @app.get('/api/device-links/<link_id>')
    def status(link_id):
        row = get_link(link_id)
        return jsonify(state=row['state'], code=row['code'], label=row['label'], expires=row['expires'])

    @app.post('/api/device-links/<link_id>/options')
    def options(link_id):
        label = str(data().get('label', '')).strip()
        if not 1 <= len(label) <= 60:
            abort(400, '패스키 이름은 1~60자입니다.')
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        row = get_link(link_id, 'phone', ('claimed',))
        user = conn.execute('SELECT name FROM users WHERE id=?', (row['user_id'],)).fetchone()
        ids = conn.execute('SELECT id FROM credentials WHERE user_id=?', (row['user_id'],)).fetchall()
        opts = generate_registration_options(rp_id=rp, rp_name='T08 비공개 공간',
            user_id=bytes.fromhex(row['user_id']), user_name=user['name'],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=k['id']) for k in ids])
        response = save_challenge('device-link', opts, dict(link_id=link_id, label=label))
        conn.commit()
        return response

    @app.post('/api/device-links/<link_id>/verify')
    def verify(link_id):
        challenge, pending = consume('device-link')
        if pending['link_id'] != link_id:
            abort(400, '다른 연결 요청의 challenge입니다.')
        get_link(link_id, 'phone', ('claimed',))
        try:
            result = verify_registration_response(credential=data()['credential'],
                expected_challenge=challenge['challenge'], expected_rp_id=rp,
                expected_origin=origin, require_user_verification=True)
        except Exception:
            abort(400, '패스키 등록 검증에 실패했습니다.')
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        get_link(link_id, 'phone', ('claimed',))
        if conn.execute('SELECT 1 FROM credentials WHERE id=?', (result.credential_id,)).fetchone():
            abort(409, '이미 등록된 패스키입니다.')
        # Immutable after this transition; approval authentication targets this exact key.
        binding = hashlib.sha256(result.credential_id + result.credential_public_key).hexdigest()
        code = secrets.token_hex(6).upper()
        code = '-'.join(code[i:i+4] for i in range(0, 12, 4))
        conn.execute("UPDATE device_links SET state='pending',credential_id=?,public_key=?,sign_count=?,"
            'label=?,device=?,backed_up=?,code=?,binding=? WHERE id=?',
            (result.credential_id, result.credential_public_key, result.sign_count, pending['label'],
             result.credential_device_type.value, int(result.credential_backed_up), code, binding, link_id))
        conn.commit()
        return jsonify(state='pending', code=code)

    @app.post('/api/device-links/<link_id>/approve')
    def approve(link_id):
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        row = get_link(link_id, 'pc', ('pending',))
        grant('link-approve', row['id'] + ':' + row['binding'])
        try:
            conn.execute('INSERT INTO credentials(id,user_id,public_key,sign_count,name,device,backed_up) VALUES(?,?,?,?,?,?,?)',
                (row['credential_id'], row['user_id'], row['public_key'], row['sign_count'],
                 row['label'], row['device'], row['backed_up']))
        except sqlite3.IntegrityError:
            abort(409, '이미 등록된 패스키입니다.')
        conn.execute("UPDATE device_links SET state='approved',public_key=NULL WHERE id=?", (link_id,))
        conn.commit()
        return jsonify(ok=True)

    @app.post('/api/device-links/<link_id>/cancel')
    def cancel_device_link(link_id):
        conn = db()
        conn.execute('BEGIN IMMEDIATE')
        get_link(link_id, states=('open', 'claimed', 'pending'))
        conn.execute("UPDATE device_links SET state='cancelled',public_key=NULL WHERE id=?", (link_id,))
        conn.commit()
        return jsonify(ok=True)

    return approval_target
