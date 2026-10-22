"""별도 notes DB의 백업·반출·빈DB 복원·실측 RTO/RPO와 원본 보존 검증."""
import argparse,copy,hashlib,json,time,uuid
from datetime import datetime,timezone
import lab,data_lab as data
from verify_security import preserved
REPORT=lab.LOCAL/'data-verification.json'

def api(ns,method='GET',path='/notes',body=None,auth=True):
    code='''import urllib.request,urllib.error,json,pathlib,sys
x=json.load(sys.stdin);h={'Content-Type':'application/json'}
if x['auth']:h['Authorization']='Bearer '+pathlib.Path('/auth/token').read_text().strip()
r=urllib.request.Request('http://127.0.0.1:8000'+x['path'],headers=h,method=x['method'],data=None if x['body'] is None else json.dumps(x['body']).encode())
try:
 with urllib.request.urlopen(r,timeout=15) as f: print(json.dumps({'status':f.status,'body':json.loads(f.read() or b'null')}))
except urllib.error.HTTPError as e: print(json.dumps({'status':e.code,'body':json.loads(e.read())}))
'''
    result=json.loads(data.execute(ns,'notes-api',code,json.dumps({'method':method,'path':path,'body':body,'auth':auth})))
    return result

def rows(ns):
    page=0;values=[]
    while True:
        r=api(ns,path=f'/notes?limit=100&offset={page}')
        if r['status']!=200:raise RuntimeError('notes 조회 실패')
        values+=r['body']
        if len(r['body'])<100:return values
        page+=100
        if page>100000:raise RuntimeError('검증 데이터 상한')

def fingerprint(values):return hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def restore_scale(replicas,uid):
    current=data.owned(data.NAMESPACES[1],'deployment','notes-api')
    if current['metadata']['uid']!=uid:raise RuntimeError('복구 API UID 변경')
    lab.k('-n',data.NAMESPACES[1],'patch','deployment','notes-api','--type=json','-p',json.dumps([{'op':'test','path':'/metadata/uid','value':uid},{'op':'replace','path':'/spec/replicas','value':replicas}]))
    if replicas:lab.k('-n',data.NAMESPACES[1],'rollout','status','deployment/notes-api','--timeout=120s')

def exercise():
    lab.guard()
    if REPORT.exists():raise RuntimeError('기존 복원 증거 존재. 덮어쓰기 대신 기본 검증 실행 필요')
    source,target=data.NAMESPACES
    before=preserved()
    report={'result':'FAIL','source_commit':lab.run(['git','rev-parse','HEAD']).strip()}
    restored_api=data.owned(target,'deployment','notes-api');uid=restored_api['metadata']['uid']
    if restored_api['spec']['replicas']!=0:raise RuntimeError('복구 API는 복원 전 정지 상태여야 함')
    source_pvc=data.owned(source,'pvc','postgres-data')['metadata']['uid'];restore_pvc=data.owned(target,'pvc','postgres-data')['metadata']['uid']
    if source_pvc==restore_pvc:raise RuntimeError('원본/복구 PVC 동일')
    try:
        assert api(source,auth=False)['status']==401
        assert api(source,'POST',body={'title':'','body':'bad'})['status']==422
        made=api(source,'POST',body={'title':'V2 복원 검증 '+uuid.uuid4().hex[:8],'body':'한글·인용부호 \' " ; DROP TABLE notes; 는 데이터로 보존'})
        assert made['status']==201
        id=made['body']['id']
        assert api(source,'PUT','/notes/'+id,{'title':'V2 CRUD 검증','body':'수정 후 복원 비교'})['status']==200
        assert api(source,path='/notes/'+id)['status']==200
        temp=api(source,'POST',body={'title':'삭제 검증'})['body']['id']
        assert api(source,'DELETE','/notes/'+temp)['status']==204
        assert api(source,path='/notes/'+temp)['status']==404
        expected=rows(source);expected_hash=fingerprint(expected)
        backup=data.run_job('backup');backup_id=backup['id']
        assert fingerprint(rows(source))==expected_hash,'백업 중 source 변경 감지'
        directory=data.export_backup(backup_id)
        data.import_backup(directory)
        marker=api(source,'POST',body={'title':'백업 이후 RPO marker '+uuid.uuid4().hex[:8]})['body']
        source_hash=fingerprint(rows(source));incident=datetime.now(timezone.utc)
        started=time.monotonic();restoration=data.run_job('restore',backup_id)
        restore_scale(1,uid)
        assert api(target,path='/ready')['status']==200
        actual=rows(target)
        assert fingerprint(actual)==expected_hash
        assert marker['id'] not in [r['id'] for r in actual]
        rto=time.monotonic()-started
        # 복구 DB에도 실제 DML 가능하고 schema_version DML은 금지됨을 별도 권한 검사함.
        test=api(target,'POST',body={'title':'복원 후 DML 검증'})['body']['id']
        assert api(target,'DELETE','/notes/'+test)['status']==204
        assert fingerprint(rows(target))==expected_hash
        assert fingerprint(rows(source))==source_hash
        # 비어 있지 않은 대상의 두 번째 복원을 반드시 거부함.
        try:data.run_job('restore',backup_id)
        except RuntimeError as error:
            if 'DB Job 실패' not in str(error):raise
        else:raise RuntimeError('비어 있지 않은 DB에 재복원 허용')
        report.update({'result':'PASS','backup_id':backup_id,'backup_sha256':backup['sha256'],'backup_rows':len(expected),'restored_rows':len(actual),'restored_hash':expected_hash,'source_hash':source_hash,'lost_marker_id':marker['id'],'lost_rows_observed':1,'rto_seconds':round(rto,3),'rto_scope':'빈 PostgreSQL DB 준비 이후 restore Job 시작부터 API /ready·데이터 일치까지 (환경 설치 제외)','backup_snapshot_window':[backup['snapshot_window_start'],backup['completed_at']],'rpo_loss_window_upper_seconds':round((incident-datetime.fromisoformat(backup['snapshot_window_start'])).total_seconds(),3),'rpo_scope':'백업 이후 marker 1행 미복원 확인, snapshot 시작 하한 기준 손실 시간창 상한. 1시간 주기는 목표이며 보장 아님','source_pvc_uid':source_pvc,'restore_pvc_uid':restore_pvc,'preserved_resources':before,'nonempty_restore_rejected':True,'host_backup':str(directory)})
    finally:
        restore_scale(0,uid)
        report['preserved_resources_after']=preserved()
        REPORT.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print('V2 CRUD·백업·0600반출·빈DB복원·정합성·RTO/RPO·원본보존 PASS')

def check():
    lab.guard();report=json.loads(REPORT.read_text())
    if report['result']!='PASS':raise RuntimeError('기존 복원 검증 실패, 명시 복구 필요')
    source,target=data.NAMESPACES
    assert data.owned(source,'pvc','postgres-data')['metadata']['uid']==report['source_pvc_uid']
    assert data.owned(target,'pvc','postgres-data')['metadata']['uid']==report['restore_pvc_uid']
    assert api(source,path='/ready')['status']==200
    assert fingerprint(rows(source))==report['source_hash']
    obj=data.owned(target,'deployment','notes-api');uid=obj['metadata']['uid']
    if obj['spec']['replicas']!=0:raise RuntimeError('기존 복구 API 실행 상태 인수 거부')
    try:
        restore_scale(1,uid);assert fingerprint(rows(target))==report['restored_hash']
    finally:restore_scale(0,uid)
    assert preserved()==report['preserved_resources_after']
    output={'result':'PASS','source_commit':lab.run(['git','rev-parse','HEAD']).strip(),'backup_id':report['backup_id'],'source_and_restore_preserved':True}
    (lab.LOCAL/'data-main-verification.json').write_text(json.dumps(output,indent=2)+'\n')
    print('V2 데이터 복원 증거·현재 API·원본 보존 재검증 PASS')
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--exercise',action='store_true');args=parser.parse_args()
    exercise() if args.exercise else check()
