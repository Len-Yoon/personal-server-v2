"""공식 Postgres 초기화 중 로컬 socket으로만 실습 role을 생성함. 비밀값 비출력."""
import os
from pathlib import Path
import subprocess

def literal(value):
    return "'" + value.replace("'", "''") + "'"

def main():
    database=os.environ['POSTGRES_DB']
    if database not in ('notes','notes_restore'): raise RuntimeError('허용되지 않은 DB')
    secrets={r:Path('/bootstrap/'+r).read_text().strip() for r in ('owner','app','backup')}
    sql='\n'.join(f'CREATE ROLE notes_{r} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {literal(p)};' for r,p in secrets.items())
    sql+=f'''\nALTER DATABASE {database} OWNER TO notes_owner;
REVOKE ALL ON DATABASE {database} FROM PUBLIC;
GRANT CONNECT ON DATABASE {database} TO notes_app, notes_backup;
ALTER SCHEMA public OWNER TO notes_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO notes_app, notes_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE notes_owner IN SCHEMA public GRANT SELECT ON TABLES TO notes_backup;
'''
    proc=subprocess.run(['psql','-v','ON_ERROR_STOP=1','-U','postgres','-d',database],input=sql,text=True,capture_output=True)
    if proc.returncode: raise RuntimeError('실습 DB role 초기화 실패 (상세 비출력)')
if __name__=='__main__': main()
