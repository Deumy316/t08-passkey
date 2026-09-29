"""Focused software-authenticator tests; no live DB, browser or iPhone involved."""
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
from contextlib import closing
import unittest
from unittest.mock import patch

from app import create_app
from test_security import Authenticator, b64


class DeviceLinkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'APP_ENV':'development',
            'APP_ORIGIN':'http://localhost:5008','RP_ID':'localhost'})
        self.env.start()
        self.path = Path('instance') / ('link-test-'+secrets.token_hex(8)+'.sqlite3')
        self.app = create_app(self.path)
        self.app.testing = True
        self.pc, self.phone = self.app.test_client(), self.app.test_client()
        self.old, self.new = Authenticator(), Authenticator()
        opts = self.post(self.pc, 'register/options', dict(mode='new',name='demo-a',label='PC'))
        self.post(self.pc,'register/verify',dict(credential=self.old.response(opts,True)),201)

    def tearDown(self):
        self.path.unlink(missing_ok=True)
        self.env.stop()

    def post(self, client, route, body=None, code=200):
        csrf = client.get('/api/session').json['csrf']
        response = client.post('/api/'+route,json=body or {},headers={
            'Origin':'http://localhost:5008','X-CSRF-Token':csrf})
        self.assertEqual(response.status_code,code,(route,response.json))
        print(f'{route.rsplit("/",1)[-1]}: HTTP {code}; token/session=[REDACTED]')
        return response.json

    def auth(self,client,key,action='login',target='',code=200):
        opts=self.post(client,'auth/options',dict(action=action,target=target))
        self.post(client,'auth/verify',dict(credential=key.response(opts)),code)

    def start(self):
        self.auth(self.pc,self.old,'link-create')
        result=self.post(self.pc,'device-links',code=201)
        self.assertTrue(result['url'].startswith('http://localhost:5008/link-device#'))
        self.assertIn('<svg',result['qr'])
        token=result['url'].split('#')[1]
        with closing(sqlite3.connect(self.path)) as conn:
            saved=conn.execute('SELECT token_hash FROM device_links WHERE id=?',(result['id'],)).fetchone()[0]
            self.assertEqual(saved,hashlib.sha256(token.encode()).hexdigest())
            self.assertNotIn(token,repr(conn.execute('SELECT * FROM device_links').fetchall()))
        return result['id'],token

    def pending(self):
        link,token=self.start()
        claimed=self.post(self.phone,'device-links/claim',dict(token=token))
        self.assertEqual(claimed['account'],'demo-a')
        opts=self.post(self.phone,f'device-links/{link}/options',dict(label='iPhone'))
        self.assertEqual(opts['excludeCredentials'][0]['id'],b64(self.old.id))
        response=self.new.response(opts,True)
        result=self.post(self.phone,f'device-links/{link}/verify',dict(credential=response))
        self.assertEqual(result['code'],self.pc.get('/api/device-links/'+link).json['code'])
        return link,token,response

    def test_approval_and_inactive_key(self):
        self.post(self.pc,'device-links',code=403)
        link,token,response=self.pending()
        self.assertEqual(len(self.pc.get('/api/passkeys').json['passkeys']),1)
        self.assertEqual(self.phone.get('/api/notes').status_code,401)
        self.assertIsNone(self.phone.get('/api/session').json['user'])
        self.auth(self.phone,self.new,code=401)
        self.post(self.pc,f'device-links/{link}/approve',code=403)
        self.post(self.phone,f'device-links/{link}/approve',code=401)
        other=self.app.test_client()
        self.auth(other,self.old)
        self.post(other,'auth/options',dict(action='link-approve',target=link),403)
        self.post(self.phone,f'device-links/{link}/verify',dict(credential=response),400)
        self.auth(self.pc,self.old,'link-approve',link)
        self.post(self.pc,f'device-links/{link}/approve')
        self.assertEqual(len(self.pc.get('/api/passkeys').json['passkeys']),2)
        self.post(self.pc,f'device-links/{link}/approve',code=409)
        self.post(self.phone,'device-links/claim',dict(token=token),409)
        self.assertEqual(self.phone.get('/api/notes').status_code,401)
        self.auth(self.phone,self.new)
        self.assertEqual(len(self.phone.get('/api/notes').json['notes']),3)
        # Existing credential still works; enrollment never rotates the PC session.
        self.post(self.pc,'logout'); self.auth(self.pc,self.old)

    def test_expiry_cancel_and_session_binding(self):
        link,token=self.start()
        self.post(self.phone,'device-links/claim',dict(token=token))
        self.post(self.app.test_client(),'device-links/claim',dict(token=token),409)
        opts=self.post(self.phone,f'device-links/{link}/options',dict(label='new'))
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute('UPDATE challenges SET expires=0'); conn.commit()
        self.post(self.phone,f'device-links/{link}/verify',dict(credential=self.new.response(opts,True)),400)
        self.post(self.pc,f'device-links/{link}/cancel')
        self.post(self.phone,f'device-links/{link}/options',dict(label='new'),409)
        link,token,_=self.pending()
        self.auth(self.pc,self.old,'link-approve',link)
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute('UPDATE device_links SET expires=0 WHERE id=?',(link,)); conn.commit()
        self.post(self.pc,f'device-links/{link}/approve',code=409)
        self.assertEqual(len(self.pc.get('/api/passkeys').json['passkeys']),1)
        link,token=self.start()
        self.post(self.pc,'logout')
        self.post(self.phone,'device-links/claim',dict(token=token),409)

    def test_exact_pending_request_and_verification(self):
        link,token,_=self.pending()
        self.auth(self.pc,self.old,'link-approve',link)
        self.post(self.pc,f'device-links/{link}/cancel')
        self.post(self.pc,f'device-links/{link}/approve',code=409)
        link,token=self.start()
        self.post(self.phone,'device-links/claim',dict(token=token))
        for kwargs in ({'uv':False},{'origin':'https://evil.example'},{'rp':'evil.example'}):
            opts=self.post(self.phone,f'device-links/{link}/options',dict(label='new'))
            self.post(self.phone,f'device-links/{link}/verify',dict(credential=self.new.response(opts,True,**kwargs)),400)
        opts=self.post(self.phone,f'device-links/{link}/options',dict(label='new'))
        self.post(self.phone,f'device-links/{link}/verify',dict(credential=self.new.response(opts,True)))
        self.post(self.pc,f'device-links/{link}/approve',code=403)
        self.post(self.phone,f'device-links/{link}/options',dict(label='replacement'),409)
        self.assertEqual(len(self.pc.get('/api/passkeys').json['passkeys']),1)


if __name__ == '__main__':
    unittest.main()
