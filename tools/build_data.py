"""V2 API·Postgres 도구를 ARM64로 빌드하고 registry digest를 잠금."""
import hashlib,json
from pathlib import Path
import lab

def main():
    lab.guard()
    images={}
    bases={'api':'python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70','postgres':'postgres:17-bookworm@sha256:858bb5e98eed02eb8cafbcdc007f9a65d1b613972028944a8ec2133ccaf80d27'}
    for kind,paths,file,context in [('api',['apps/notes-api'],'apps/notes-api/Dockerfile','apps/notes-api'),('postgres',['tools/data_image','tools/data_backup'],'tools/data_image/Dockerfile','.')]:
        h=hashlib.sha256()
        for directory in paths:
            for p in sorted((lab.ROOT/directory).rglob('*')):
                if p.is_file() and '__pycache__' not in p.parts:
                    h.update(str(p.relative_to(lab.ROOT)).encode()+b'\0'+p.read_bytes())
        tag='localhost:5001/v2-'+('notes-api' if kind=='api' else 'data-postgres')+':'+h.hexdigest()[:16]
        lab.docker('build','--platform','linux/arm64','--build-arg',('PYTHON_BASE' if kind=='api' else 'POSTGRES_BASE')+'='+bases[kind],'-f',file,'-t',tag,context,capture=False)
        lab.docker('push',tag,capture=False)
        inspected=json.loads(lab.docker('image','inspect',tag))[0]
        if inspected['Architecture']!='arm64':raise RuntimeError('ARM64 이미지 불일치')
        image=next(d for d in inspected['RepoDigests'] if d.startswith(tag.split(':')[0]+':5001/'))
        images[kind]={'image':image,'base':bases[kind],'source_sha256':h.hexdigest(),'architecture':'arm64'}
    (lab.ROOT/'platforms/data/images.lock.json').write_text(json.dumps(images,indent=2)+'\n')
    print('V2 data 이미지 digest 잠금 PASS')
if __name__=='__main__':main()
