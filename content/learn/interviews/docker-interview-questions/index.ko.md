---
title: "Docker 면접 질문 상위 20개와 답변 (2026년판)"
description: "컨테이너, 이미지, 네트워킹, 볼륨, Docker Compose 및 프로덕션 모범 사례를 다루는 20개의 고급 Docker 질문으로 시니어 DevOps 면접을 준비하세요."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["docker 면접 질문", "시니어 devops 면접", "컨테이너화 질문", "docker 면접 답변", "docker compose 면접", "dockerfile 모범 사례", "컨테이너 오케스트레이션 면접", "docker 네트워킹 질문", "devops 엔지니어 면접", "docker 프로덕션 질문"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker 면접 질문 상위 20개와 답변 (2026년판)",
    "description": "컨테이너, 이미지, 네트워킹 및 프로덕션 모범 사례를 다루는 시니어 DevOps 역할을 위한 고급 Docker 면접 질문.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Docker는 모든 DevOps, SRE 또는 백엔드 엔지니어링 역할에서 필수적인 기술이 되었습니다. 시니어 레벨 면접관은 `docker run`을 넘어서는 역량을 기대합니다 — 이미지 레이어링, 네트워킹 내부 구조, 보안 강화, 프로덕션 수준의 오케스트레이션 패턴을 이해하고 있는지 보고 싶어합니다. 이 가이드에는 시니어 및 리드 레벨 면접에서 가장 자주 묻는 20개의 질문과 깊이를 보여주는 상세한 답변이 포함되어 있습니다.

**면접 전에 명령어를 빠르게 복습해야 하나요?** [Docker Captain's Log 치트시트](/cheatsheets/docker-container-commands/)를 북마크하세요.

---

## 핵심 개념

<details>
<summary><strong>1. 컨테이너와 가상 머신의 차이점은 무엇인가요?</strong></summary>
<br>

**가상 머신**은 하이퍼바이저 위에서 자체 커널, 드라이버 및 시스템 라이브러리를 포함한 전체 게스트 OS를 실행합니다. 각 VM은 완전히 격리되지만 상당한 리소스를 소비합니다 (GB 단위의 RAM, 부팅에 수 분).

**컨테이너**는 호스트 OS 커널을 공유하고 Linux 네임스페이스와 cgroups를 사용하여 프로세스를 격리합니다. 애플리케이션과 그 종속성만 패키징합니다 — 별도의 커널이 없습니다. 이로 인해 컨테이너는 경량(MB 단위)이고, 빠르게 시작되며(밀리초), 높은 이식성을 가집니다.

핵심 차이점: VM은 **하드웨어**를 가상화하고, 컨테이너는 **운영 체제**를 가상화합니다.
</details>

<details>
<summary><strong>2. Docker 이미지 레이어란 무엇이며 어떻게 작동하나요?</strong></summary>
<br>

Docker 이미지는 일련의 **읽기 전용 레이어**로 구축됩니다. Dockerfile의 각 명령어(`FROM`, `RUN`, `COPY` 등)가 새로운 레이어를 생성합니다. 레이어는 유니온 파일시스템(예: OverlayFS)을 사용하여 쌓입니다.

컨테이너가 실행되면 Docker는 위에 얇은 **쓰기 가능 레이어**(컨테이너 레이어)를 추가합니다. 런타임에 수행된 변경은 이 쓰기 가능 레이어에만 영향을 미칩니다 — 기본 이미지 레이어는 변경되지 않습니다.

이 아키텍처는 다음을 가능하게 합니다:
- **캐싱**: 레이어가 변경되지 않았으면 Docker는 빌드 시 캐시에서 재사용합니다.
- **공유**: 동일한 이미지의 여러 컨테이너가 읽기 전용 레이어를 공유하여 디스크 공간을 절약합니다.
- **효율성**: 수정된 레이어만 레지스트리에서 풀하거나 푸시하면 됩니다.
</details>

<details>
<summary><strong>3. Dockerfile에서 CMD와 ENTRYPOINT의 차이점은 무엇인가요?</strong></summary>
<br>

둘 다 컨테이너가 시작될 때 무엇을 실행할지 정의하지만, 동작이 다릅니다:

- **CMD**는 런타임에 완전히 재정의할 수 있는 기본 인수를 제공합니다. `docker run myimage /bin/bash`를 실행하면 CMD가 대체됩니다.
- **ENTRYPOINT**는 항상 실행되는 메인 실행 파일을 정의합니다. 런타임 인수가 대체되지 않고 추가됩니다.

모범 사례: 메인 프로세스에는 `ENTRYPOINT`를, 기본 인수에는 `CMD`를 사용합니다:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

`docker run myimage --port 3000`을 실행하면 `python app.py --port 3000`이 실행됩니다.
</details>

<details>
<summary><strong>4. 멀티 스테이지 빌드란 무엇이며 왜 중요한가요?</strong></summary>
<br>

멀티 스테이지 빌드는 단일 Dockerfile에서 여러 `FROM` 문을 사용합니다. 각 `FROM`은 새로운 빌드 스테이지를 시작하며, 한 스테이지에서 다른 스테이지로 아티팩트를 선택적으로 복사할 수 있습니다.

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

이렇게 하면 컴파일된 바이너리만 포함하는 최종 이미지가 생성됩니다 — 빌드 도구도, 소스 코드도, 중간 파일도 없습니다. 결과적으로 공격 표면이 줄어든 극적으로 작은 이미지(종종 10-100배 작은)가 됩니다.
</details>

<details>
<summary><strong>5. Dockerfile에서 COPY와 ADD의 차이점은 무엇인가요?</strong></summary>
<br>

둘 다 빌드 컨텍스트에서 이미지로 파일을 복사하지만, `ADD`에는 추가 기능이 있습니다:
- `ADD`는 로컬 `.tar` 아카이브를 자동으로 추출할 수 있습니다.
- `ADD`는 URL에서 파일을 다운로드할 수 있습니다.

그러나 Docker 모범 사례에서는 명시적이고 예측 가능한 `COPY`를 거의 모든 경우에 사용할 것을 권장합니다. `ADD`는 특별히 tar 추출이 필요한 경우에만 사용하세요. 파일 다운로드에는 `ADD`를 사용하지 마세요 — 대신 `RUN curl` 또는 `RUN wget`을 사용하여 다운로드 레이어가 적절히 캐시되도록 하세요.
</details>

## 네트워킹

<details>
<summary><strong>6. Docker의 네트워킹 모드(bridge, host, none, overlay)를 설명하세요.</strong></summary>
<br>

- **Bridge** (기본값): 호스트에 개인 내부 네트워크를 생성합니다. 같은 브리지의 컨테이너는 IP 또는 컨테이너 이름으로 통신할 수 있습니다. 외부로의 트래픽은 포트 매핑(`-p`)이 필요합니다.
- **Host**: 네트워크 격리를 제거합니다. 컨테이너가 호스트의 네트워크 스택을 직접 공유합니다. 포트 매핑이 필요 없지만 격리도 없습니다. 성능이 중요한 애플리케이션에 유용합니다.
- **None**: 네트워크가 전혀 없습니다. 컨테이너에는 루프백 인터페이스만 있습니다. 배치 작업이나 보안에 민감한 워크로드에 사용됩니다.
- **Overlay**: 여러 Docker 호스트에 걸쳐 있습니다 (Swarm/Kubernetes에서 사용). 다른 머신의 컨테이너가 VXLAN 터널링을 사용하여 같은 네트워크에 있는 것처럼 통신할 수 있습니다.
</details>

<details>
<summary><strong>7. 컨테이너 간 통신은 어떻게 작동하나요?</strong></summary>
<br>

사용자 정의 브리지 네트워크에서 컨테이너는 Docker의 내장 DNS 리졸버를 통해 **컨테이너 이름으로** 서로에 도달할 수 있습니다. DNS 서버는 모든 컨테이너 내부의 `127.0.0.11`에서 실행됩니다.

기본 브리지 네트워크에서는 DNS 확인을 **사용할 수 없습니다** — 컨테이너는 IP 주소로만 통신할 수 있으며, IP가 동적으로 할당되므로 신뢰할 수 없습니다.

모범 사례: 항상 커스텀 브리지 네트워크(`docker network create mynet`)를 생성하고 컨테이너를 연결하세요. 컨테이너 간 통신에 기본 브리지를 사용하지 마세요.
</details>

<details>
<summary><strong>8. EXPOSE와 포트 공개의 차이점은 무엇인가요?</strong></summary>
<br>

Dockerfile의 `EXPOSE`는 순수하게 **문서화**입니다 — Dockerfile을 읽는 사람에게 애플리케이션이 특정 포트에서 수신 대기한다고 알려줍니다. 실제로 포트를 열거나 매핑하지는 않습니다.

포트 공개(`-p 8080:80`)는 실제로 호스트 포트를 컨테이너 포트에 매핑하는 네트워크 규칙을 생성하여 컨테이너 외부에서 서비스에 접근할 수 있게 합니다.

`EXPOSE` 지시문에 없는 포트도 공개할 수 있으며, `EXPOSE`만으로는 `-p` 없이 아무것도 하지 않습니다.
</details>

## 볼륨 및 스토리지

<details>
<summary><strong>9. Docker 마운트의 세 가지 유형은 무엇인가요?</strong></summary>
<br>

1. **볼륨** (`docker volume create`): Docker가 관리하며 `/var/lib/docker/volumes/`에 저장됩니다. 영구 데이터(데이터베이스)에 가장 적합합니다. 컨테이너 제거 후에도 유지됩니다. 호스트 간 이식 가능합니다.
2. **바인드 마운트** (`-v /host/path:/container/path`): 특정 호스트 디렉토리를 컨테이너에 매핑합니다. 호스트 경로가 존재해야 합니다. 개발(라이브 코드 리로드)에 가장 적합합니다. 이식성이 없습니다.
3. **tmpfs 마운트** (`--tmpfs /tmp`): 호스트 메모리에만 저장됩니다. 디스크에 기록되지 않습니다. 지속되어서는 안 되는 민감한 데이터(시크릿, 세션 토큰)에 가장 적합합니다.
</details>

<details>
<summary><strong>10. 데이터베이스 컨테이너의 데이터를 어떻게 유지하나요?</strong></summary>
<br>

데이터베이스의 데이터 디렉토리에 마운트된 **이름 있는 볼륨**을 사용합니다:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

데이터는 컨테이너 재시작 및 제거 후에도 유지됩니다. 데이터베이스 버전을 업그레이드할 때 이전 컨테이너를 중지하고, 같은 볼륨으로 새 컨테이너를 시작한 다음 새 버전이 데이터 마이그레이션을 처리하도록 합니다.

프로덕션 데이터베이스에 바인드 마운트를 사용하지 마세요 — 볼륨은 더 나은 I/O 성능을 가지며 Docker의 스토리지 드라이버가 관리합니다.
</details>

## 보안

<details>
<summary><strong>11. 프로덕션에서 Docker 컨테이너를 어떻게 보호하나요?</strong></summary>
<br>

핵심 강화 사례:
- **비-root로 실행**: Dockerfile에서 `USER` 지시문을 사용합니다. 애플리케이션 프로세스를 root로 실행하지 마세요.
- **최소 베이스 이미지 사용**: `ubuntu` 대신 `alpine`, `distroless` 또는 `scratch`를 사용합니다.
- **capability 제거**: `--cap-drop ALL --cap-add <필요한-것만>`을 사용합니다.
- **읽기 전용 파일시스템**: `--read-only`를 사용하고 특정 쓰기 가능 경로만 마운트합니다.
- **새로운 권한 없음**: `--security-opt=no-new-privileges`를 사용합니다.
- **이미지 스캔**: `docker scout`, Trivy 또는 Snyk를 사용하여 베이스 이미지 및 종속성의 취약점을 탐지합니다.
- **이미지 서명**: Docker Content Trust(`DOCKER_CONTENT_TRUST=1`)를 사용하여 이미지 진위를 확인합니다.
- **리소스 제한**: `--memory`, `--cpus`를 사용하여 리소스 고갈을 방지합니다.
</details>

<details>
<summary><strong>12. Docker rootless 모드란 무엇인가요?</strong></summary>
<br>

Docker rootless 모드는 호스트에서 root 권한 없이 사용자 네임스페이스 내에서 Docker 데몬과 컨테이너를 완전히 실행합니다. 이는 Docker의 주요 보안 우려를 제거합니다: 데몬이 root로 실행되며 컨테이너 탈출이 호스트에 대한 root 접근을 의미한다는 것입니다.

rootless 모드에서는 공격자가 컨테이너에서 탈출하더라도 Docker를 실행하는 비특권 사용자의 권한만 얻습니다. 트레이드오프는 일부 기능(1024 미만 포트 바인딩 등)에 추가 구성이 필요하다는 것입니다.
</details>

## Docker Compose 및 오케스트레이션

<details>
<summary><strong>13. docker-compose up과 docker-compose run의 차이점은 무엇인가요?</strong></summary>
<br>

- `docker compose up`: `docker-compose.yml`에 정의된 **모든** 서비스를 시작하고, 네트워크/볼륨을 생성하며, `depends_on` 순서를 준수합니다. 일반적으로 전체 스택을 올리는 데 사용됩니다.
- `docker compose run <서비스> <명령>`: 일회성 명령으로 **단일** 서비스를 시작합니다. 기본적으로 종속 서비스를 시작하지 않습니다 (포트 매핑은 `--service-ports`, 정리는 `--rm` 사용). 마이그레이션, 테스트 또는 관리 작업 실행에 사용됩니다.
</details>

<details>
<summary><strong>14. depends_on은 어떻게 작동하며 한계는 무엇인가요?</strong></summary>
<br>

`depends_on`은 **시작 순서**를 제어합니다 — 서비스 A가 서비스 B 전에 시작되도록 보장합니다. 그러나 컨테이너가 **시작**되기만을 기다리며, 내부 애플리케이션이 **준비**되기를 기다리지 않습니다.

예를 들어, 데이터베이스 컨테이너는 몇 초 만에 시작될 수 있지만 PostgreSQL은 초기화에 추가 시간이 필요합니다. 앱 컨테이너가 시작되고 즉시 연결에 실패합니다.

해결책: `depends_on`을 `condition`과 헬스 체크와 함께 사용합니다:

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. Docker Swarm과 Kubernetes 중 언제 무엇을 선택하나요?</strong></summary>
<br>

**Docker Swarm**: Docker에 내장되어 있으며 추가 설정이 필요 없습니다. 단순함이 중요한 소규모에서 중규모 배포에 가장 적합합니다. 동일한 Docker Compose 파일을 사용합니다. Kubernetes에 비해 제한된 에코시스템과 커뮤니티. 전담 플랫폼 엔지니어가 없는 팀에 적합합니다.

**Kubernetes**: 대규모 컨테이너 오케스트레이션의 산업 표준. 오토스케일링, 롤링 업데이트, 서비스 메시, 커스텀 리소스 정의 및 대규모 에코시스템(Helm, Istio, ArgoCD)을 지원합니다. 더 높은 복잡성과 학습 곡선. 대규모, 다중 팀, 멀티 클라우드 배포에 필요합니다.

경험 법칙: 20개 미만의 서비스와 소규모 팀이라면 Swarm으로 충분합니다. 그 이상이면 Kubernetes에 투자할 가치가 있습니다.
</details>

## 프로덕션 및 문제 해결

<details>
<summary><strong>16. Docker 이미지 크기를 어떻게 줄이나요?</strong></summary>
<br>

1. **멀티 스테이지 빌드 사용** — 빌드 도구를 최종 이미지에서 제외합니다.
2. **최소 베이스 이미지 사용** — `ubuntu`(~75MB) 대신 `alpine`(~5MB)을 사용합니다.
3. **RUN 명령 결합** — 각 `RUN`은 레이어를 생성합니다. `&&`로 명령을 연결하고 같은 레이어에서 정리합니다.
4. **.dockerignore 사용** — 빌드 컨텍스트에서 `node_modules`, `.git`, 테스트 파일, 문서를 제외합니다.
5. **변경 빈도별로 레이어 정렬** — 캐시 히트를 최대화하기 위해 드물게 변경되는 레이어(종속성)를 자주 변경되는 레이어(소스 코드) 전에 배치합니다.
</details>

<details>
<summary><strong>17. 컨테이너가 계속 재시작됩니다. 어떻게 디버깅하나요?</strong></summary>
<br>

단계별 접근:
1. `docker ps -a` — 종료 코드를 확인합니다. 종료 코드 137 = OOM 킬. 종료 코드 1 = 애플리케이션 오류.
2. `docker logs <container>` — 스택 트레이스나 오류 메시지를 위해 애플리케이션 로그를 읽습니다.
3. `docker inspect <container>` — `State.OOMKilled`, 리소스 제한, 환경 변수를 확인합니다.
4. `docker run -it --entrypoint /bin/sh <image>` — 환경을 수동으로 디버깅하기 위해 대화형 셸을 시작합니다.
5. `docker stats` — 컨테이너가 메모리나 CPU 제한에 도달하는지 확인합니다.
6. `docker events` 확인 — 데몬에서 킬 시그널이나 OOM 이벤트를 찾습니다.
</details>

<details>
<summary><strong>18. docker stop과 docker kill의 차이점은 무엇인가요?</strong></summary>
<br>

- `docker stop`은 메인 프로세스(PID 1)에 **SIGTERM**을 보내고 유예 기간(기본 10초)을 기다립니다. 프로세스가 종료되지 않으면 Docker가 SIGKILL을 보냅니다. 이를 통해 애플리케이션이 정상적인 종료(연결 닫기, 버퍼 플러시, 상태 저장)를 수행할 수 있습니다.
- `docker kill`은 즉시 **SIGKILL**을 보냅니다. 프로세스가 정리 기회 없이 종료됩니다. 컨테이너가 응답하지 않을 때만 사용하세요.

모범 사례: 프로덕션에서는 항상 `docker stop`을 사용하세요. 애플리케이션이 SIGTERM을 올바르게 처리하는지 확인하세요.
</details>

<details>
<summary><strong>19. Docker에서 시크릿을 어떻게 관리하나요?</strong></summary>
<br>

이미지에 시크릿을 포함시키지 **절대** 마세요 (Dockerfile의 ENV, .env 파일의 COPY). 이미지 레이어에 남아 `docker history`로 볼 수 있습니다.

성숙도 수준별 접근:
- **기본**: 런타임에 `--env-file`로 시크릿을 전달합니다 (파일은 이미지에 포함되지 않음).
- **더 좋음**: Docker Swarm 시크릿이나 Kubernetes 시크릿을 사용합니다 (환경 변수가 아닌 파일로 마운트).
- **최적**: 외부 시크릿 관리자(HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)를 사용하고 사이드카 또는 init 컨테이너를 통해 런타임에 시크릿을 주입합니다.
</details>

<details>
<summary><strong>20. Docker 헬스 체크란 무엇이며 왜 중요한가요?</strong></summary>
<br>

헬스 체크는 Docker가 컨테이너 내부에서 주기적으로 실행하여 애플리케이션이 실제로 작동하는지 확인하는 명령입니다 — 단순히 프로세스가 실행 중인 것이 아닙니다.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

헬스 체크 없이 Docker는 프로세스가 살아있는지(PID가 존재하는지)만 알 수 있습니다. 헬스 체크가 있으면 Docker는 애플리케이션이 **건강한지**(요청에 응답하는지) 알 수 있습니다. 이는 다음에 중요합니다:
- **로드 밸런서**: 건강한 컨테이너에만 트래픽을 라우팅합니다.
- **오케스트레이터**: 건강하지 않은 컨테이너를 자동으로 재시작합니다.
- **depends_on**: 프로세스 시작이 아닌 실제 준비 완료를 기다립니다.
</details>
