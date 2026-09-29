"""Software authenticator fixtures only; never imported by the application.
Keys stay in test-process memory. Verification is the real webauthn library.
"""
import base64
import hashlib
import json
import secrets
import sqlite3
from pathlib import Path
import unittest
from contextlib import closing

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from app import create_app


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


class Authenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = secrets.token_bytes(32)
        self.counter = 0
        self.handle = None

    def response(self, opts, registration=False, bad=False, origin='http://localhost:5008', uv=True, rp='localhost'):
        client = json.dumps(dict(type='webauthn.create' if registration else 'webauthn.get',
            challenge=opts['challenge'], origin=origin, crossOrigin=False)).encode()
        self.counter += 1
        flags = (5 if uv else 1) | (64 if registration else 0)
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + self.counter.to_bytes(4,'big')
        response = dict(clientDataJSON=b64(client))
        if registration:
            self.handle = opts['user']['id']
            pub = self.key.public_key().public_numbers()
            cose = cbor2.dumps({1:2,3:-7,-1:1,-2:pub.x.to_bytes(32,'big'),-3:pub.y.to_bytes(32,'big')})
            auth += bytes(16) + len(self.id).to_bytes(2,'big') + self.id + cose
            response['attestationObject'] = b64(cbor2.dumps(dict(fmt='none',attStmt={},authData=auth)))
            response['transports'] = ['internal']
        else:
            signing_key = ec.generate_private_key(ec.SECP256R1()) if bad else self.key
            signature = signing_key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
            response.update(authenticatorData=b64(auth), signature=b64(signature), userHandle=self.handle)
        return dict(id=b64(self.id),rawId=b64(self.id),type='public-key',response=response,clientExtensionResults={})


class SecurityTests(unittest.TestCase):
    def test_required_flows(self):
        path = Path('instance') / ('test-'+secrets.token_hex(8)+'.sqlite3')
        app = create_app(path)
        app.testing = True
        a, b, guest = app.test_client(), app.test_client(), app.test_client()

        def check(r, code, label):
            self.assertEqual(r.status_code, code, (label,r.get_json()))
            print(f'{label}: HTTP {code}; session/token=[REDACTED]')
            return r.get_json()

        def post(client, route, body={}, code=200, method='POST'):
            token = client.get('/api/session').json['csrf']
            return check(client.open('/api/'+route, method=method,json=body,
                headers={'Origin':'http://localhost:5008','X-CSRF-Token':token}),code,route)

        def enroll(client, name, key, mode='new'):
            opts = post(client,'register/options',dict(mode=mode,name=name,label=name+' key'))
            response = key.response(opts,True)
            self.assertEqual(set(response['response']), {'clientDataJSON','attestationObject','transports'})
            post(client,'register/verify',dict(credential=response),201)
            return response

        def auth(client,key,action='login',target='',code=200,**kwargs):
            opts=post(client,'auth/options',dict(action=action,target=target))
            response=key.response(opts,**kwargs)
            post(client,'auth/verify',dict(credential=response),code)
            return response

        try:
            check(guest.get('/api/notes'),401,'anonymous private API')
            ka,kb,k2=Authenticator(),Authenticator(),Authenticator()
            enroll(a,'demo-a',ka); enroll(b,'demo-b',kb)
            ua=a.get('/api/session').json['user']['id']; ub=b.get('/api/session').json['user']['id']
            na=check(a.get('/api/notes'),200,'A own notes')['notes']
            nb=check(b.get('/api/notes'),200,'B own notes')['notes']
            self.assertEqual(len(na),3); self.assertEqual(len(nb),3)
            for client,other,notes in [(a,ub,nb),(b,ua,na)]:
                check(client.get('/api/accounts/'+other+'/notes'),403,'other account URL')
                check(client.get('/api/notes?account_id='+other),403,'tampered query')
                check(client.get('/api/notes/'+notes[0]['id']),403,'other note ID')
                post(client,'notes',{'account_id':other},403)
            for url in ['/', '/static/passkeys.js', '/api/session']:
                response=guest.get(url)
                self.assertEqual(response.status_code,200)
                for n in na+nb:
                    self.assertNotIn(n['body'],response.get_data(as_text=True))
                response.close()
            print('Public HTML/JS/session: HTTP 200; no private note content')
            post(a,'register/options',dict(mode='add',label='blocked'),403)
            post(guest,'register/options',dict(mode='new',name='demo-a',label='blocked'),409)
            post(guest,'register/options',dict(mode='new',name='cancel-me',label='cancel'))
            post(guest,'cancel')
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM users').fetchone()[0],2)
            print('Cancellation: no incomplete account stored')
            auth(a,ka,'add'); enroll(a,'second',k2,'add')
            keys=check(a.get('/api/passkeys'),200,'two passkeys')['passkeys']
            self.assertEqual(len(keys),2)
            auth(a,k2,'delete',ka.id.hex())
            post(a,'passkeys/'+ka.id.hex(),{},200,'DELETE')
            old_cookie=a.get_cookie('t08_passkey_session').value
            post(a,'logout')
            replay=app.test_client(); replay.set_cookie('t08_passkey_session',old_cookie)
            check(replay.get('/api/notes'),401,'logged-out session replay')
            response=auth(a,k2)
            post(a,'auth/verify',dict(credential=response),400)
            post(a,'logout'); auth(a,ka,code=401); auth(a,k2)
            auth(a,k2,'delete',k2.id.hex())
            post(a,'passkeys/'+k2.id.hex(),{},409,'DELETE')
            post(a,'logout')
            auth(a,k2,code=400,bad=True)
            auth(a,k2,code=400,origin='https://evil.example')
            auth(a,k2,code=400,uv=False)
            auth(a,k2,code=400,rp='evil.example')
            first=post(guest,'auth/options'); second=post(guest,'auth/options')
            self.assertNotEqual(first['challenge'],second['challenge'])
            post(guest,'auth/verify',dict(credential=kb.response(first)),400)
            opts=post(guest,'auth/options')
            with closing(sqlite3.connect(path)) as conn:
                conn.execute('UPDATE challenges SET expires=0')
                conn.commit()
            post(guest,'auth/verify',dict(credential=kb.response(opts)),400)
            r1=post(guest,'register/options',dict(mode='new',name='temp-a',label='temp'))
            r2=post(guest,'register/options',dict(mode='new',name='temp-a',label='temp'))
            self.assertNotEqual(r1['challenge'],r2['challenge'])
            post(guest,'cancel')
            print('Registration/authentication challenges differ per request; expiry and old challenge rejected')
            check(b.post('/api/logout',json={},headers={'Origin':'http://localhost:5008'}),403,'missing CSRF')
            with closing(sqlite3.connect(path)) as conn:
                public_key=conn.execute('SELECT public_key FROM credentials LIMIT 1').fetchone()[0]
                self.assertIsInstance(cbor2.loads(public_key),dict)
                self.assertNotIn(-4,cbor2.loads(public_key))
            print('Stored COSE public key verified; no private-key parameter; real hardware NOT TESTED')
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
