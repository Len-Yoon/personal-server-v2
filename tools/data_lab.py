"""V2 데이터 실습의 소유·namespace·파일·수동 Job 경계를 고정함."""
import argparse,base64,copy,hashlib,json,os,re,stat,sys,time,uuid
from pathlib import Path
import lab
from secret_files import preflight_password,commit_password,create_private,read_private
NAMESPACES=('v2-data-dev','v2-data-restore')
OWNER=lab.OWNER

def owned(ns,kind,name):
    if ns not in NAMESPACES:raise RuntimeError('데이터 실습 namespace 불일치')
    lab.namespace_guard(ns)
    obj=json.loads(lab.k('-n',ns,'get',kind,name,'-o','json'))
    if obj['metadata'].get('labels',{}).get(OWNER)!=lab.VALUE:raise RuntimeError('데이터 자원 소유 불일치')
    return obj

def preflight(environment,revision):
    path=lab.APPLICATIONS[environment][2]
    if lab.run(['git','rev-parse','HEAD']).strip()!=revision or lab.run(['git','status','--porcelain','--',path]).strip():raise RuntimeError('커밋된 데이터 명세만 적용함')
    objects=lab.decode_objects(lab.k('create','--dry-run=client','--validate=false','-f','-','-o','json',stdin=lab.k('kustomize',path)))
    cluster={'ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding'}
    allowed={'Service','ServiceAccount','StatefulSet','Deployment','PersistentVolumeClaim','CronJob','NetworkPolicy','ResourceQuota'}
    expected_ns=lab.APPLICATIONS[environment][3]
    for obj in objects:
        kind,m=obj['kind'],obj['metadata'];ns=m.get('namespace')
        if m.get('labels',{}).get(OWNER)!=lab.VALUE:raise RuntimeError('데이터 선언 소유 불일치')
        if environment=='data-policy':
            if kind not in cluster or m['name']!='v2-data-workloads' or ns:raise RuntimeError('데이터 cluster 정책 범위 불일치')
            s=obj['spec']
            if kind=='ValidatingAdmissionPolicy' and (s.get('matchConditions')!=[{'name':'data-namespaces','expression':"request.namespace in ['v2-data-dev', 'v2-data-restore']"}] or s.get('failurePolicy')!='Fail' or s.get('paramKind') or s.get('matchConstraints',{}).get('objectSelector')):raise RuntimeError('데이터 정책 고정 범위 불일치')
            if kind=='ValidatingAdmissionPolicyBinding' and (s.get('policyName')!='v2-data-workloads' or s.get('validationActions')!=['Deny'] or s.get('paramRef')):raise RuntimeError('데이터 Binding 불일치')
        elif kind not in allowed or ns!=expected_ns:raise RuntimeError('데이터 선언 종류/namespace 불일치')
        if ns:lab.namespace_guard(ns)
        lab.refuse_foreign(kind,m['name'],ns)

def credentials():
    lab.guard();plans=[]
    for ns in NAMESPACES:
        lab.namespace_guard(ns)
        # 모든 role은 별도 임의 비밀번호. 파일/Secret 불일치 시 생성·교체하지 않음.
        roleplans={}
        for role in ('admin','owner','app','backup','token'):
            path=lab.LOCAL/(ns+'-'+role)
            name={'admin':'notes-db-admin','owner':'notes-db-owner','app':'notes-db-app','backup':'notes-db-backup','token':'notes-api-token'}[role]
            existing=lab.credential_secret(ns,name)
            plan=preflight_password(path,existing.get('data',{}) if existing else None,('password',))
            roleplans[role]=(plan,existing,name);plans.append((ns,name,plan,existing))
        # 합성 Secret은 개별 role 파일과 일치해야 하며 원본 파일이 유실되면 위에서 거부함.
        composed={'notes-db-bootstrap':{r:roleplans[r][0].string_data['password'] for r in ('admin','owner','app','backup')},'notes-api-auth':{'password':roleplans['app'][0].string_data['password'],'token':roleplans['token'][0].string_data['password']}}
        for name,data in composed.items():
            old=lab.credential_secret(ns,name)
            if old and {k:base64.b64decode(v).decode() for k,v in old.get('data',{}).items()}!=data:raise RuntimeError('기존 합성 Secret 불일치')
            plans.append((ns,name,data,old))
    for ns,name,plan,old in plans:
        if not isinstance(plan,dict):commit_password(plan)
    for ns,name,plan,old in plans:
        current=lab.credential_secret(ns,name)
        if old:
            if not current or current['metadata']['uid']!=old['metadata']['uid'] or current.get('data')!=old.get('data'):raise RuntimeError('Secret 검증 후 교체 감지')
            continue
        if current:raise RuntimeError('Secret 생성 경합')
        data=plan if isinstance(plan,dict) else plan.string_data
        lab.k('create','-f','-',stdin=json.dumps({'apiVersion':'v1','kind':'Secret','metadata':{'name':name,'namespace':ns,'labels':{OWNER:lab.VALUE}},'type':'Opaque','stringData':data}))
    print('데이터 실습 자격 증명 준비 PASS (값 비출력)')

def pod(ns,name):
    deployment=owned(ns,'deployment',name)
    selector=deployment['spec']['selector']['matchLabels']
    pods=json.loads(lab.k('-n',ns,'get','pods','-l',','.join(k+'='+v for k,v in selector.items()),'-o','json'))['items']
    healthy=[p for p in pods if not p['metadata'].get('deletionTimestamp') and p['status'].get('phase')=='Running' and all(c['ready'] for c in p['status'].get('containerStatuses',[]))]
    if len(healthy)!=1:raise RuntimeError('유일한 준비 Pod 필요')
    p=healthy[0]
    if p['metadata'].get('labels',{}).get(OWNER)!=lab.VALUE or not any(r.get('kind')=='ReplicaSet' for r in p['metadata'].get('ownerReferences',[])):raise RuntimeError('Pod 소유 불일치')
    return p['metadata']['name']

def execute(ns,deployment,code,stdin=None):
    return lab.k('-n',ns,'exec','-i',pod(ns,deployment),'--','python3','-c',code,stdin=stdin)

def run_job(action,backup_id=None):
    lab.guard()
    if action not in ('backup','restore'):raise RuntimeError('허용되지 않은 Job')
    ns=NAMESPACES[0] if action=='backup' else NAMESPACES[1]
    cj=owned(NAMESPACES[0],'cronjob','notes-backup')
    template=copy.deepcopy(cj['spec']['jobTemplate']['spec']);template['ttlSecondsAfterFinished']=3600
    spec=template['template']['spec'];spec['nodeSelector']={'kubernetes.io/hostname':'k3d-ps-v2-agent-'+('0' if action=='backup' else '1')}
    if action=='restore':
        template['backoffLimit']=0
        if not backup_id or not re.fullmatch(r'[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}',backup_id):raise RuntimeError('백업 ID 불일치')
        template['template']['metadata']['labels']['app.kubernetes.io/name']='notes-restore'
        c=spec['containers'][0];c['command']=['python3','/opt/data_backup/backup.py','restore','--backup-id',backup_id]
        for e in c['env']:
            e['value']={'PGHOST':'postgres-restore','PGDATABASE':'notes_restore','PGUSER':'notes_owner'}.get(e['name'],e['value'])
        next(v for v in spec['volumes'] if v['name']=='auth')['secret']['secretName']='notes-db-owner'
    name='v2-data-'+action+'-'+uuid.uuid4().hex[:10]
    job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':ns,'labels':{OWNER:lab.VALUE}},'spec':template}
    for claim in ('postgres-data','notes-backups'):owned(ns,'pvc',claim)
    result=json.loads(lab.k('create','-f','-','-o','json',stdin=json.dumps(job)))
    uid=result['metadata']['uid']
    try:
        deadline=time.monotonic()+330
        while time.monotonic()<deadline:
            current=owned(ns,'job',name)
            if current['metadata']['uid']!=uid:raise RuntimeError('Job UID 변경')
            if current['status'].get('succeeded'):
                output=lab.k('-n',ns,'logs','job/'+name)
                return json.loads(output.strip())
            if any(c['type']=='Failed' and c['status']=='True' for c in current['status'].get('conditions',[])):raise RuntimeError('DB Job 실패 (자격 증명 보호로 로그 비출력)')
            time.sleep(1)
        raise RuntimeError('DB Job 시간 초과')
    finally:
        current=owned(ns,'job',name)
        if current['metadata']['uid']!=uid:raise RuntimeError('정리 시 Job UID 변경')
        lab.k('delete','--raw',f'/apis/batch/v1/namespaces/{ns}/jobs/{name}','-f','-',stdin=json.dumps({'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':uid}}))

def export_backup(backup_id):
    lab.guard()
    if not re.fullmatch(r'[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}',backup_id):raise RuntimeError('백업 ID 불일치')
    code="""import sys,json,base64,os;sys.path.insert(0,'/opt/data_backup');import backup
with backup.locked_root('/backups/archives') as root:
 m,fd=backup.checked_archive(root,sys.stdin.read())
 if m['size']>64*1024*1024:raise RuntimeError('실습 반출 64MiB 상한')
 with os.fdopen(fd,'rb') as f:data=f.read()
 print(json.dumps({'manifest':m,'dump':base64.b64encode(data).decode()}))
"""
    payload=json.loads(execute(NAMESPACES[0],'backup-transfer',code,backup_id))
    m=payload['manifest'];data=base64.b64decode(payload['dump'],validate=True)
    if m['id']!=backup_id or len(data)!=m['size'] or hashlib.sha256(data).hexdigest()!=m['sha256']:raise RuntimeError('반출 백업 불일치')
    parent=lab.LOCAL/'data-backups'
    if not parent.exists():parent.mkdir(mode=0o700)
    if parent.is_symlink() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('호스트 반출 디렉터리 권한 불일치')
    destination=parent/backup_id;destination.mkdir(mode=0o700)
    create_private(destination/'database.dump',data);create_private(destination/'manifest.json',(json.dumps(m)+'\n').encode())
    return destination


def read_archive(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>64*1024*1024:raise RuntimeError('반출 파일 권한/크기 불일치')
        result=f.read(64*1024*1024+1);after=os.fstat(f.fileno())
        if len(result)!=before.st_size or (before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('반출 파일 변경 감지')
        return result

def import_backup(directory):
    lab.guard();directory=Path(directory)
    if directory.parent!=lab.LOCAL/'data-backups' or directory.is_symlink() or directory.stat().st_uid!=os.getuid() or directory.stat().st_mode&0o777!=0o700:raise RuntimeError('고정 반출 경로만 반입 가능')
    m=json.loads(read_private(directory/'manifest.json'));data=read_archive(directory/'database.dump')
    if m['id']!=directory.name or not re.fullmatch(r'[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}',m['id']) or hashlib.sha256(data).hexdigest()!=m['sha256'] or len(data)!=m['size']:raise RuntimeError('반입 checksum 불일치')
    code="""import sys,json,os,base64,hashlib;sys.path.insert(0,'/opt/data_backup');import backup
x=json.load(sys.stdin);m=x['manifest'];data=base64.b64decode(x['dump'],validate=True)
if not backup.ID_PATTERN.fullmatch(m['id']) or hashlib.sha256(data).hexdigest()!=m['sha256'] or len(data)!=m['size']:raise RuntimeError('checksum')
with backup.locked_root('/backups/archives') as root:
 import shutil,uuid
 d=root/('.partial-import-'+uuid.uuid4().hex);d.mkdir(mode=0o700)
 try:
  if (root/m['id']).exists():raise RuntimeError('기존 백업 덮어쓰기 거부')
  for n,b in [('database.dump',data),('manifest.json',json.dumps(m).encode())]:
   fd=os.open(d/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
  fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  d.rename(root/m['id'])
  fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  _,fd=backup.checked_archive(root,m['id']);os.close(fd)
 finally:
  if d.exists():shutil.rmtree(d)
print('import PASS')
"""
    execute(NAMESPACES[1],'backup-transfer',code,json.dumps({'manifest':m,'dump':base64.b64encode(data).decode()}))
    return m['id']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['credentials','backup','export','import','restore']);parser.add_argument('--backup-id');parser.add_argument('--directory');a=parser.parse_args()
    if a.command=='credentials':credentials()
    elif a.command=='backup':print(json.dumps(run_job('backup')))
    elif a.command=='export':print(export_backup(a.backup_id))
    elif a.command=='import':print(import_backup(a.directory))
    else:print(json.dumps(run_job('restore',a.backup_id)))
