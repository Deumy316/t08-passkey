"""Print public-key evidence only. Never query sessions or challenge tokens."""
import sqlite3
from pathlib import Path
from contextlib import closing

path = Path(__file__).resolve().parent / 'instance' / 'passkeys.sqlite3'
if not path.exists():
    raise SystemExit('먼저 서버를 실행하고 패스키를 등록하세요.')
with closing(sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)) as conn:
    for name, created, public_key in conn.execute(
            'SELECT name,created,hex(public_key) FROM credentials ORDER BY created'):
        print(f'name={name} created={created} COSE_public_key_hex={public_key}')
