# Personal Server V2 · Kubernetes Platform Lab

맥북의 격리된 환경에서 Kubernetes·GitOps·장애 진단·복구를 단계별로 연습하는 프로젝트임.

| 구분 | 범위 | 비고 |
|---|---|---|
| V1 | [personal-server](https://github.com/Len-Yoon/personal-server)의 실제 서비스 운영·유지보수 | 기존 저장소·운영 구성 보존 |
| V2 | 맥북 로컬 Kubernetes 운영 실습 | V1 전체 복제·즉시 대체 아님 |
| 현재 상태 | root/self·Book·Portal·YouTube·관측 GitOps·서비스 연계·Loki 로그 수집 검증 완료 | Loki·trace는 후속 |
| 운영 보호 | N100 접속·동기화·이미지 반입·배포·운영 데이터 사용 제외 | 별도 명시 승인 전 금지 |

## 개발 방향

기존 Book의 검증된 이미지를 실습용 데이터로 실행하는 안을 우선 검토함. 앱 소스는 V1에서 관리하고 V2는 플랫폼·배포 설정·실습 도구·증적을 관리함. 이미지 저장소·아키텍처·버전·인증 방식은 설계에서 확정해야 함.

첫 개발 범위는 별도 k3d, 개발/검증 namespace, Kustomize, Argo CD, 자원·배포·스케줄링 장애 실습임. 승인된 설계에 따라 명세·실행 도구를 구현함.

[개발 계획](docs/20261021_V2_개발계획.md) · [로컬 실습 가이드](docs/20261021_V2_로컬실습_운영가이드.md) · [검증 기록](docs/20261021_V2_검증기록.md) · [GitOps·관측 기록](docs/20261021_V2_GitOps전환_지표관측_검증기록.md) · [에이전트 작업 기준](AGENTS.md)

## localhost 접속

```sh
python3 tools/lab.py serve
```

| 대상 | 주소 | 비고 |
|---|---|---|
| Portal 개발 / 검증 | http://127.0.0.1:8000 / http://127.0.0.1:8090 | 파일함·Book·YouTube 연결 |
| YouTube 개발 / 검증 | http://127.0.0.1:8002 / http://127.0.0.1:8092 | 별도 PVC·쓰기 인증 |
| Book 개발 | http://localhost:8080 | 쓰기 비밀번호 .local/dev-password |
| Book 검증 | http://localhost:8081 | 쓰기 비밀번호 .local/verify-password |
| Argo CD | https://localhost:8082 | admin / .local/argocd-password, 자체 서명 인증서 |
| Grafana | http://localhost:8083/d/v2-platform-lab | admin / .local/grafana-password |
| Grafana 로그 | http://localhost:8083/d/v2-logs | 환경·서비스별 Loki 로그 검색 |
| Prometheus | http://localhost:8084 | 지표·targets·내부 alert 조회 |

정상 배포는 `lab.py gitops` 또는 `lab.py sync`로 수행함. 기존 Argo에 Helm upgrade를 반복하지 않음. 최초 설치·이미지 빌드·배포는 로컬 실습 가이드에 따름. 포워딩 프로세스를 유지해야 접속 가능하며 localhost 주소만 입력해서 클러스터가 자동 시작되지는 않음. 비밀번호 파일 내용은 Git·로그에 기록하지 않음.

## 검증과 현재 한계

정적 안전 경계 검증과 실제 로컬 실행 증거를 구분해 검증 기록에 보관함. 자동 장애 회귀 검증은 사용자의 직접 진단 경험·물리 HA·다른 환경 백업 복원 검증을 뜻하지 않음. GitHub 저장·병합·CI와 로컬 수동 GitOps 동기화·N100 운영 배포를 구분함.

Portal·YouTube 통합 범위와 제한은 [서비스 통합 기록](docs/20261021_V2_서비스통합_검증기록.md)에 정리함. 로그인 정보는 Git 제외 `.local/V2_로그인정보.md`에만 저장됨.

[Loki·Alloy 로그 수집 기록](docs/20261021_V2_로그수집_검증기록.md) · 표준 Pod 로그만 수집하며, 보안 이벤트 파일·호스트 로그는 포함하지 않음.
