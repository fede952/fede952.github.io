---
title: "Linux SysAdmin 면접: 프로세스, 권한 및 네트워킹"
description: "시니어 SysAdmin 및 DevOps 역할을 위한 필수 Linux 시스템 관리 면접 질문 20선. 파일 권한, 프로세스 관리, systemd, 네트워킹 및 문제 해결을 다룹니다."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin 면접: 프로세스, 권한 및 네트워킹",
    "description": "권한, 프로세스, systemd 및 네트워킹에 관한 필수 Linux 시스템 관리 면접 질문 20선.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Linux 시스템 관리는 현대 인프라의 기반입니다. SysAdmin, DevOps, SRE 또는 클라우드 엔지니어 역할의 면접이든, 사용자 관리, 프로세스 문제 해결, 네트워크 구성, 서버 보안 등을 모두 명령줄에서 수행하는 능력을 테스트받게 됩니다. 이 가이드는 시니어 후보자를 주니어와 구분하는 20가지 질문을 실제 운영 경험을 보여주는 답변과 함께 다룹니다.

**빠른 명령어 참조가 필요하세요?** 준비하는 동안 [Linux SysAdmin 치트시트](/cheatsheets/linux-sysadmin-permissions/)를 열어두세요.

---

## 파일 권한 및 소유권

<details>
<summary><strong>1. Linux 권한 모델(rwx, 8진수 표기법, 특수 비트)을 설명하세요.</strong></summary>
<br>

모든 파일에는 세 가지 권한 계층이 있습니다: **소유자**, **그룹**, **기타**. 각 계층은 **읽기(r=4)**, **쓰기(w=2)**, **실행(x=1)**을 가질 수 있습니다.

8진수 표기법은 이를 결합합니다: `chmod 755` = rwxr-xr-x (소유자: 전체, 그룹/기타: 읽기+실행).

**특수 비트**:
- **SUID(4000)**: 파일이 실행하는 사용자가 아닌 파일 소유자로 실행됩니다. 예: `/usr/bin/passwd`는 root로 실행되어 사용자가 자신의 비밀번호를 변경할 수 있게 합니다.
- **SGID(2000)**: 파일에서는 그룹 소유자로 실행됩니다. 디렉토리에서는 새 파일이 디렉토리의 그룹을 상속합니다.
- **Sticky bit(1000)**: 디렉토리에서 파일 소유자만 자신의 파일을 삭제할 수 있습니다. 대표적인 예: `/tmp`.
</details>

<details>
<summary><strong>2. 하드 링크와 소프트 링크의 차이점은 무엇인가요?</strong></summary>
<br>

- **하드 링크**: inode(디스크의 실제 데이터)에 대한 직접 참조입니다. 같은 파일에 대한 여러 하드 링크는 동일한 inode 번호를 공유합니다. 하나의 하드 링크를 삭제해도 다른 것에는 영향을 미치지 않습니다 — 모든 하드 링크가 제거될 때까지 데이터가 유지됩니다. 파일 시스템 경계를 넘을 수 없습니다. 디렉토리에 링크할 수 없습니다.
- **소프트 링크(심볼릭 링크)**: 파일 경로에 대한 포인터(바로가기와 같음)입니다. 자체 inode를 가집니다. 대상 파일이 삭제되면 심볼릭 링크는 댕글링 링크가 됩니다. 파일 시스템을 넘을 수 있습니다. 디렉토리에 링크할 수 있습니다.

`ls -li`를 사용하여 inode 번호를 확인하고 하드 링크 관계를 확인합니다.
</details>

<details>
<summary><strong>3. 개발자가 공유 디렉토리에 쓸 수 없습니다. 어떻게 진단하고 해결하나요?</strong></summary>
<br>

진단 단계:
1. `ls -la /shared/` — 소유권 및 권한 확인.
2. `id developer` — 사용자가 속한 그룹 확인.
3. `getfacl /shared/` — 표준 권한을 재정의할 수 있는 ACL 확인.

일반적인 해결 방법:
- 사용자를 디렉토리 그룹에 추가: `sudo usermod -aG devteam developer`.
- 디렉토리에 SGID를 설정하여 새 파일이 그룹을 상속하도록: `chmod g+s /shared/`.
- ACL이 필요한 경우: `setfacl -m u:developer:rwx /shared/`.
- umask가 그룹 쓰기를 차단하지 않는지 확인(`umask` 명령으로 확인).
</details>

<details>
<summary><strong>4. umask란 무엇이며 파일 생성에 어떤 영향을 미치나요?</strong></summary>
<br>

`umask`는 새 파일과 디렉토리에서 **제거되는** 기본 권한을 정의합니다. 최대 권한에서 빼는 비트 마스크입니다.

- 파일의 기본 최대값: 666 (기본적으로 실행 권한 없음).
- 디렉토리의 기본 최대값: 777.
- `umask 022`일 때: 파일은 644(rw-r--r--), 디렉토리는 755(rwxr-xr-x)를 얻습니다.
- `umask 077`일 때: 파일은 600(rw-------), 디렉토리는 700(rwx------)을 얻습니다.

시스템 전체는 `/etc/profile`에서, 사용자별로는 `~/.bashrc`에서 설정합니다. 보안에 중요 — 느슨한 umask는 민감한 파일을 권한 없는 사용자에게 노출시킬 수 있습니다.
</details>

## 프로세스 관리

<details>
<summary><strong>5. 프로세스, 스레드, 데몬의 차이를 설명하세요.</strong></summary>
<br>

- **프로세스**: 자체 메모리 공간, PID, 파일 디스크립터, 환경을 가진 실행 중인 프로그램의 인스턴스입니다. `fork()` 또는 `exec()`로 생성됩니다.
- **스레드**: 프로세스 내의 경량 실행 단위입니다. 스레드는 동일한 메모리 공간과 파일 디스크립터를 공유하지만 자체 스택과 레지스터를 가집니다. 프로세스보다 빠르게 생성됩니다.
- **데몬**: 제어 터미널 없이 실행되는 백그라운드 프로세스입니다. 일반적으로 부팅 시 시작되어 계속 실행되며 서비스를 제공합니다(sshd, nginx, cron). 관례적으로 `d` 접미사로 명명됩니다.
</details>

<details>
<summary><strong>6. 좀비 프로세스란 무엇이며 어떻게 처리하나요?</strong></summary>
<br>

**좀비**는 실행을 마쳤지만 부모 프로세스가 `wait()`을 호출하여 종료 상태를 읽지 않았기 때문에 프로세스 테이블에 여전히 항목이 있는 프로세스입니다. PID 슬롯 외에는 리소스를 소비하지 않습니다.

좀비 식별: `ps aux | grep Z` — 상태 `Z`(defunct)로 표시됩니다.

좀비를 **kill할 수 없습니다** — 이미 죽어 있습니다. 제거하려면:
1. 부모 프로세스에 `SIGCHLD` 전송: `kill -s SIGCHLD <parent_pid>`.
2. 부모가 무시하면, 부모 프로세스를 kill하면 좀비가 고아가 되어 `init`(PID 1)에 의해 입양됩니다. Init은 자동으로 `wait()`을 호출하여 정리합니다.

많은 수의 좀비는 보통 자식을 수거하지 않는 버그가 있는 부모 프로세스를 나타냅니다.
</details>

<details>
<summary><strong>7. Linux 시그널을 설명하세요. SIGTERM, SIGKILL, SIGHUP은 무엇인가요?</strong></summary>
<br>

시그널은 프로세스에 전송되는 소프트웨어 인터럽트입니다:

- **SIGTERM(15)**: 정중한 종료 요청입니다. 프로세스가 이를 잡아서 리소스를 정리하고 정상적으로 종료할 수 있습니다. `kill <pid>`가 기본으로 전송하는 것입니다.
- **SIGKILL(9)**: 강제 종료입니다. 잡거나, 차단하거나, 무시할 수 없습니다. 커널이 프로세스를 즉시 종료합니다. 최후의 수단으로만 사용 — 정리 불가능합니다.
- **SIGHUP(1)**: 역사적으로 "전화 끊김"입니다. 많은 데몬(nginx, Apache)이 SIGHUP을 받으면 재시작 대신 설정을 다시 로드합니다.
- **SIGINT(2)**: 인터럽트, Ctrl+C로 전송됩니다.
- **SIGSTOP/SIGCONT(19/18)**: 프로세스 일시 중지 및 재개.
</details>

<details>
<summary><strong>8. CPU를 너무 많이 소비하는 프로세스를 어떻게 찾아 종료하나요?</strong></summary>
<br>

1. 프로세스 식별: `top -o %CPU` 또는 `ps aux --sort=-%cpu | head -10`.
2. 세부 정보 확인: `ls -l /proc/<pid>/exe`로 실제 바이너리 확인.
3. 무엇을 하는지 확인: `strace -p <pid>`로 시스템 콜, `lsof -p <pid>`로 열린 파일 확인.
4. 정상 중지: `kill <pid>` (SIGTERM) — 정리를 허용.
5. 강제 중지: `kill -9 <pid>` (SIGKILL) — SIGTERM이 실패한 경우에만.
6. 재발 방지: systemd로 관리되는 경우 서비스 unit 파일에 `CPUQuota=50%` 설정.
</details>

## Systemd 및 서비스

<details>
<summary><strong>9. systemd란 무엇이며 SysVinit과 어떻게 다른가요?</strong></summary>
<br>

**SysVinit**: `/etc/init.d/`의 셸 스크립트를 사용하는 순차적 부팅 프로세스입니다. 서비스가 정의된 런레벨에서 하나씩 시작됩니다. 느린 부팅 시간. 단순하지만 의존성 처리가 제한적입니다.

**systemd**: unit 파일을 사용하는 병렬 부팅 프로세스입니다. 의존성, 소켓 활성화, 온디맨드 서비스 시작, 리소스 제어를 위한 cgroups, 로깅을 위한 journald를 지원합니다. 훨씬 빠른 부팅. 서비스, 타이머, 마운트, 소켓, 타겟을 관리합니다.

systemd는 RHEL, Ubuntu, Debian, Fedora, SUSE, Arch의 기본 init 시스템입니다.
</details>

<details>
<summary><strong>10. 커스텀 systemd 서비스를 어떻게 만드나요?</strong></summary>
<br>

`/etc/systemd/system/myapp.service`에 unit 파일을 생성합니다:

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

그런 다음: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

주요 `Type` 값: `simple`(기본값, 메인 프로세스가 포그라운드에서 실행), `forking`(프로세스가 백그라운드로 포크, `PIDFile` 필요), `oneshot`(한 번 실행 후 종료), `notify`(프로세스가 sd_notify를 통해 준비 상태를 알림).
</details>

<details>
<summary><strong>11. systemd로 부팅 성능을 어떻게 분석하나요?</strong></summary>
<br>

- `systemd-analyze` — 총 부팅 시간.
- `systemd-analyze blame` — 시작 시간순으로 정렬된 서비스 목록.
- `systemd-analyze critical-chain` — 중요 부팅 경로의 트리.
- `systemd-analyze plot > boot.svg` — 부팅 시퀀스의 시각적 타임라인 생성.
- `journalctl -b -p err` — 현재 부팅의 오류.

부팅 속도를 높이려면: 불필요한 서비스 비활성화(`systemctl disable`), 서비스를 소켓 활성화로 전환(온디맨드 시작), blame 출력에서 느린 서비스 식별.
</details>

## 네트워킹

<details>
<summary><strong>12. TCP 3-way 핸드셰이크를 설명하세요.</strong></summary>
<br>

1. **SYN**: 클라이언트가 초기 시퀀스 번호와 함께 SYN 패킷을 서버에 전송합니다.
2. **SYN-ACK**: 서버가 SYN-ACK로 응답하여 클라이언트의 SYN을 확인하고 자체 시퀀스 번호를 전송합니다.
3. **ACK**: 클라이언트가 서버의 시퀀스 번호를 확인하는 ACK를 전송합니다. 연결이 수립됩니다.

종료는 4-way 핸드셰이크를 사용합니다: FIN → ACK → FIN → ACK (각 측이 독립적으로 연결의 절반을 닫음).

디버그: `ss -tuln`(수신 포트), `ss -tulnp`(프로세스 이름 포함), `tcpdump -i eth0 port 80`(패킷 캡처).
</details>

<details>
<summary><strong>13. TCP와 UDP의 차이점은 무엇인가요?</strong></summary>
<br>

- **TCP**(Transmission Control Protocol): 연결 지향, 신뢰성 있는, 순서가 보장된 전달. 핸드셰이크, 확인 응답, 재전송을 사용합니다. 높은 오버헤드. HTTP, SSH, FTP, 데이터베이스에 사용됩니다.
- **UDP**(User Datagram Protocol): 비연결, 비신뢰성, 순서 보장 없음. 핸드셰이크 없음, 확인 응답 없음. 낮은 오버헤드, 낮은 지연. DNS, DHCP, VoIP, 스트리밍, 게임에 사용됩니다.

핵심 통찰: "비신뢰성"이 나쁘다는 뜻이 아닙니다 — 필요한 경우 애플리케이션이 신뢰성을 처리한다는 뜻입니다. DNS는 쿼리가 작고 빠르기 때문에 UDP를 사용합니다. 응답이 손실되면 클라이언트가 단순히 다시 보냅니다.
</details>

<details>
<summary><strong>14. 서버가 외부 IP에 도달할 수 없습니다. 어떻게 문제를 해결하나요?</strong></summary>
<br>

계층별 접근법:
1. **L1 - 물리**: `ip link show` — 인터페이스가 활성화되어 있나요?
2. **L2 - 데이터 링크**: `ip neighbor show` — ARP 테이블이 채워져 있나요?
3. **L3 - 네트워크**: `ip route show` — 기본 게이트웨이가 있나요? `ping <gateway>` — 도달할 수 있나요?
4. **L3 - 외부**: `ping 8.8.8.8` — IP로 인터넷에 도달할 수 있나요?
5. **L7 - DNS**: `nslookup google.com` — DNS 해석이 작동하나요? `/etc/resolv.conf` 확인.
6. **방화벽**: `iptables -L -n` 또는 `nft list ruleset` — 아웃바운드 연결이 차단되었나요?
7. **경로 추적**: `traceroute 8.8.8.8` — 경로가 어디서 끊기나요?
</details>

## 스토리지 및 파일 시스템

<details>
<summary><strong>15. inode란 무엇인가요?</strong></summary>
<br>

inode는 파일에 대한 메타데이터를 저장하는 데이터 구조입니다: 권한, 소유권, 크기, 타임스탬프, 디스크의 데이터 블록에 대한 포인터. 모든 파일과 디렉토리에는 inode가 있습니다.

중요한 점은 **파일 이름은 inode에 저장되지 않습니다** — 디렉토리 항목에 저장되며, 이름을 inode 번호에 매핑합니다. 이것이 하드 링크가 작동하는 이유입니다: 여러 디렉토리 항목이 동일한 inode를 가리킬 수 있습니다.

inode가 부족하면(디스크 여유 공간이 있더라도) 새 파일을 만들 수 없습니다. `df -i`로 확인합니다. 일반적인 원인: 수백만 개의 작은 파일(메일 큐, 캐시 디렉토리).
</details>

<details>
<summary><strong>16. 다운타임 없이 LVM 논리 볼륨을 어떻게 확장하나요?</strong></summary>
<br>

1. 사용 가능한 공간 확인: `vgdisplay` — 여유 PE(physical extents) 확인.
2. 여유 공간이 없으면 새 물리 디스크 추가: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. 논리 볼륨 확장: `lvextend -L +10G /dev/myvg/mylv`.
4. 파일 시스템 크기 조정(ext4/XFS는 온라인):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

마운트 해제 불필요. 다운타임 없음. 이것이 원시 파티션에 대한 LVM의 주요 장점 중 하나입니다.
</details>

## 보안 및 하드닝

<details>
<summary><strong>17. su, sudo, sudoers의 차이점은 무엇인가요?</strong></summary>
<br>

- **su**(switch user): 다른 사용자로 완전히 전환합니다. `su -`는 대상 사용자의 환경을 로드합니다. 대상 사용자의 비밀번호가 필요합니다.
- **sudo**(superuser do): 다른 사용자(보통 root)로 단일 명령을 실행합니다. **호출자의** 비밀번호가 필요합니다. 누가 무엇을 실행했는지 감사 로그를 제공합니다.
- **sudoers**(`/etc/sudoers`): 누가 sudo를 사용할 수 있고 어떤 명령을 실행할 수 있는지 정의하는 구성 파일입니다. `visudo`(구문 검증)로 안전하게 편집합니다.

모범 사례: 직접 root 로그인을 비활성화합니다(sshd_config에서 `PermitRootLogin no`). 대신 관리자에게 sudo 접근 권한을 부여합니다 — 책임 추적(누가 무엇을 했는지 기록)과 세밀한 제어를 제공합니다.
</details>

<details>
<summary><strong>18. SSH 서버를 어떻게 하드닝하나요?</strong></summary>
<br>

필수 `/etc/ssh/sshd_config` 변경사항:
- `PermitRootLogin no` — 직접 root 로그인 방지.
- `PasswordAuthentication no` — 키 기반 인증 강제.
- `PubkeyAuthentication yes` — SSH 키 활성화.
- `Port 2222` — 기본 포트에서 변경(자동 스캔 감소).
- `MaxAuthTries 3` — 인증 시도 제한.
- `AllowUsers deploy admin` — 특정 사용자 화이트리스트.
- `ClientAliveInterval 300` — 유휴 세션 연결 해제.
- `fail2ban` 설치 — 로그인 실패 후 IP 자동 차단.
</details>

## 스크립팅 및 자동화

<details>
<summary><strong>19. Bash에서 $?, $$, $!, $@의 차이점은 무엇인가요?</strong></summary>
<br>

- **$?** — 마지막 명령의 종료 상태(0 = 성공, 0이 아닌 값 = 실패).
- **$$** — 현재 셸의 PID.
- **$!** — 마지막 백그라운드 프로세스의 PID.
- **$@** — 스크립트에 전달된 모든 인수(각각 별도의 단어로).
- **$#** — 인수의 수.
- **$0** — 스크립트 자체의 이름.
- **$1, $2, ...** — 개별 위치 인수.

일반적인 패턴: `command && echo "success" || echo "fail"`은 `$?`를 암시적으로 사용합니다.
</details>

<details>
<summary><strong>20. 최근 7일 이내에 수정된 100MB보다 큰 모든 파일을 찾는 원라이너를 작성하세요.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

분석:
- `find /` — 루트에서 검색.
- `-type f` — 파일만(디렉토리 제외).
- `-size +100M` — 100메가바이트보다 큰 것.
- `-mtime -7` — 최근 7일 이내에 수정된 것.
- `-exec ls -lh {} \;` — 각 결과에 대해 사람이 읽을 수 있는 크기를 표시.
- `2>/dev/null` — 권한 거부 오류를 억제.

정렬 포함 대안: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
