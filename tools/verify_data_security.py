"""V2 데이터 실제 DB 권한·통신·admission 거부 검증. 비밀값 비출력."""
import sys,json,copy,uuid
import lab,data_lab as d
from inspect import cleandoc as dedent

def main():
    lab.guard();result={}
    code="""import sys,json,psycopg,os,pathlib
    p=psycopg.connect(host=os.environ['PGHOST'],dbname=os.environ['PGDATABASE'],user='notes_app',password=pathlib.Path('/auth/password').read_text(),connect_timeout=3)
    r={}
    for name,sql in [('schema_version_dml','UPDATE public.schema_version SET version=version'),('ddl','CREATE TABLE public.forbidden_test (id integer)')]:
     try:
      p.execute(sql);r[name]='ALLOWED'
     except psycopg.errors.InsufficientPrivilege:r[name]='DENIED'
     finally:p.rollback()
    print(json.dumps(r))
    """
    result['app_role']=json.loads(d.execute(d.NAMESPACES[0],'notes-api',dedent(code)));assert all(v=='DENIED' for v in result['app_role'].values())
    pg=json.loads(lab.k('-n',d.NAMESPACES[1],'get','pod','postgres-0','-o','json'))['status']['podIP']
    code="""import socket,json,sys
    try:
     s=socket.create_connection((sys.stdin.read(),5432),timeout=2);s.close();print('ALLOWED')
    except (TimeoutError,OSError):print('BLOCKED')
    """
    result['cross_namespace_db']=d.execute(d.NAMESPACES[0],'notes-api',dedent(code),pg).strip();assert result['cross_namespace_db']=='BLOCKED'
    base=d.owned(d.NAMESPACES[0],'deployment','notes-api')['spec']['template']
    for change in ('image_tag','token','zero_cpu','owner_removed'):
     p={'apiVersion':'v1','kind':'Pod','metadata':{'name':'v2-data-dryrun-'+uuid.uuid4().hex[:8],'namespace':d.NAMESPACES[0],**copy.deepcopy(base['metadata'])},'spec':copy.deepcopy(base['spec'])}
     if change=='image_tag':p['spec']['containers'][0]['image']='localhost:5001/v2-notes-api:latest'
     if change=='token':p['spec']['automountServiceAccountToken']=True
     if change=='zero_cpu':p['spec']['containers'][0]['resources']['requests']['cpu']='0'
     if change=='owner_removed':p['metadata']['labels'].pop(lab.OWNER)
     try:lab.k('create','--dry-run=server','-f','-',stdin=json.dumps(p))
     except RuntimeError as e:
      if 'v2-data-workloads' not in str(e):raise
      result[change]='REJECTED'
     else:raise RuntimeError('데이터 정책 오설정 허용')
    # 실제 backup role로 DML을 시도하되 BEGIN/ROLLBACK으로 절대 commit하지 않음.
    cj=d.owned(d.NAMESPACES[0],'cronjob','notes-backup');spec=copy.deepcopy(cj['spec']['jobTemplate']['spec']);spec['backoffLimit']=0
    cmd="""import sys,json;sys.path.insert(0,'/opt/data_backup');import backup
    with backup.authenticated_env('backup') as env:
     attempts=backup.wait_database(env)
     r=backup.pg(['psql','-X','--no-password','-At','-c','SELECT count(*) FROM public.notes'],env)
     assert backup.pg(['psql','-X','--no-password','-At','-c',"SELECT has_table_privilege('notes_backup','public.notes','INSERT')"],env)=='f'
     try:backup.pg(['psql','-X','--no-password','-v','ON_ERROR_STOP=1','-c',"BEGIN; INSERT INTO public.notes(id,title) VALUES ('11111111-1111-1111-1111-111111111111','denied'); ROLLBACK;"],env)
     except RuntimeError:print(json.dumps({'select':'ALLOWED','insert':'DENIED','ready_attempts':attempts}))
     else:raise RuntimeError('backup INSERT allowed')
    """
    spec['template']['spec']['containers'][0]['command']=['python3','-c',dedent(cmd)]
    name='v2-data-permissions-'+uuid.uuid4().hex[:8];ns=d.NAMESPACES[0]
    j={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':ns,'labels':{lab.OWNER:lab.VALUE}},'spec':spec}
    x=json.loads(lab.k('create','-f','-','-o','json',stdin=json.dumps(j)));uid=x['metadata']['uid']
    try:
     lab.k('-n',ns,'wait','--for=condition=complete','job/'+name,'--timeout=60s')
     result['backup_role']=json.loads(lab.k('-n',ns,'logs','job/'+name));assert result['backup_role']['insert']=='DENIED'
    finally:
     x=d.owned(ns,'job',name);assert x['metadata']['uid']==uid
     lab.k('delete','--raw',f'/apis/batch/v1/namespaces/{ns}/jobs/{name}','-f','-',stdin=json.dumps({'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'propagationPolicy':'Foreground'}))
    (lab.LOCAL/'data-security-verification.json').write_text(json.dumps({'result':'PASS','source_commit':lab.run(['git','rev-parse','HEAD']).strip(),'checks':result},indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
