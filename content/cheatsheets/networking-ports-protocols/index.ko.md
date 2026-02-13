---
title: "인터넷 지도: 네트워크 포트, 프로토콜 및 상태 코드"
description: "TCP/IP, OSI 모델, 주요 포트(SSH, HTTP, DNS), HTTP 상태 코드의 시각적 가이드. DevOps와 해커를 위한 참고서."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "인터넷 지도: 네트워크 포트, 프로토콜 및 상태 코드",
    "description": "TCP/IP, OSI 모델, 주요 포트(SSH, HTTP, DNS), HTTP 상태 코드의 시각적 가이드. DevOps와 해커를 위한 참고서.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 주요 포트

네트워크의 모든 서비스는 포트에서 수신 대기합니다. 반드시 외워야 할 포트들입니다.

### 잘 알려진 포트 (0–1023)

| 포트 | 프로토콜 | 서비스 | 비고 |
|------|----------|--------|------|
| 20 | TCP | FTP 데이터 | 능동 모드 데이터 전송 |
| 21 | TCP | FTP 제어 | 명령 및 인증 |
| 22 | TCP | SSH / SFTP | 보안 셸 및 파일 전송 |
| 23 | TCP | Telnet | 비암호화 원격 접속 (사용 지양) |
| 25 | TCP | SMTP | 이메일 발송 |
| 53 | TCP/UDP | DNS | 도메인 이름 확인 |
| 67/68 | UDP | DHCP | 동적 IP 할당 |
| 80 | TCP | HTTP | 비암호화 웹 트래픽 |
| 110 | TCP | POP3 | 이메일 수신 |
| 143 | TCP | IMAP | 이메일 수신 (서버 측) |
| 443 | TCP | HTTPS | 암호화 웹 트래픽 (TLS) |
| 445 | TCP | SMB | Windows 파일 공유 |
| 587 | TCP | SMTP (TLS) | 보안 이메일 제출 |

### 등록된 포트 (1024–49151)

| 포트 | 프로토콜 | 서비스 | 비고 |
|------|----------|--------|------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle 데이터베이스 리스너 |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | 원격 데스크톱 프로토콜 |
| 5432 | TCP | PostgreSQL | PostgreSQL 데이터베이스 |
| 5900 | TCP | VNC | 가상 네트워크 컴퓨팅 |
| 6379 | TCP | Redis | 인메모리 데이터 저장소 |
| 8080 | TCP | HTTP Alt | 일반적인 개발/프록시 포트 |
| 8443 | TCP | HTTPS Alt | 대체 HTTPS 포트 |
| 27017 | TCP | MongoDB | MongoDB 데이터베이스 |

---

## HTTP 상태 코드

서버가 무슨 일이 일어났는지 알려주는 방법입니다. 범주별로 정리했습니다.

### 1xx — 정보

| 코드 | 이름 | 의미 |
|------|------|------|
| 100 | Continue | 요청 본문을 계속 보내세요 |
| 101 | Switching Protocols | WebSocket으로 업그레이드 |

### 2xx — 성공

| 코드 | 이름 | 의미 |
|------|------|------|
| 200 | OK | 요청 성공 |
| 201 | Created | 리소스 생성됨 (POST 성공) |
| 204 | No Content | 성공, 하지만 반환할 내용 없음 |

### 3xx — 리다이렉션

| 코드 | 이름 | 의미 |
|------|------|------|
| 301 | Moved Permanently | URL이 영구적으로 변경됨 (북마크 업데이트 필요) |
| 302 | Found | 임시 리다이렉트 |
| 304 | Not Modified | 캐시된 버전 사용 |
| 307 | Temporary Redirect | 302와 유사하지만 HTTP 메서드 유지 |
| 308 | Permanent Redirect | 301과 유사하지만 HTTP 메서드 유지 |

### 4xx — 클라이언트 오류

| 코드 | 이름 | 의미 |
|------|------|------|
| 400 | Bad Request | 잘못된 구문 또는 유효하지 않은 데이터 |
| 401 | Unauthorized | 인증 필요 |
| 403 | Forbidden | 인증되었지만 권한 없음 |
| 404 | Not Found | 리소스가 존재하지 않음 |
| 405 | Method Not Allowed | 잘못된 HTTP 메서드 (GET vs POST) |
| 408 | Request Timeout | 서버가 대기 시간 초과 |
| 409 | Conflict | 상태 충돌 (예: 중복) |
| 413 | Payload Too Large | 요청 본문이 제한을 초과 |
| 418 | I'm a Teapot | RFC 2324. 네, 진짜입니다. |
| 429 | Too Many Requests | 요청 속도 제한 |

### 5xx — 서버 오류

| 코드 | 이름 | 의미 |
|------|------|------|
| 500 | Internal Server Error | 일반적인 서버 장애 |
| 502 | Bad Gateway | 업스트림 서버가 잘못된 응답을 보냄 |
| 503 | Service Unavailable | 서버 과부하 또는 유지보수 중 |
| 504 | Gateway Timeout | 업스트림 서버가 시간 내에 응답하지 않음 |

---

## TCP vs UDP

두 가지 전송 계층 프로토콜. 용도에 따라 다른 도구를 사용합니다.

| 특성 | TCP | UDP |
|------|-----|-----|
| 연결 | 연결 지향 (핸드셰이크) | 비연결형 (전송 후 잊기) |
| 신뢰성 | 전달 보장, 순서 보장 | 보장 없음, 순서 없음 |
| 속도 | 느림 (오버헤드) | 빠름 (최소 오버헤드) |
| 헤더 크기 | 20–60 바이트 | 8 바이트 |
| 흐름 제어 | 있음 (윈도잉) | 없음 |
| 사용 사례 | 웹, 이메일, 파일 전송, SSH | DNS, 스트리밍, 게임, VoIP |

### TCP 3방향 핸드셰이크

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### TCP 연결 해제

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## SSL/TLS 핸드셰이크

HTTPS가 암호화된 연결을 수립하는 방법입니다.

```
Client                          Server
  |--- ClientHello ------------->|   Supported ciphers, TLS version, random
  |<-- ServerHello --------------|   Chosen cipher, certificate, random
  |    (verify certificate)      |
  |--- Key Exchange ------------>|   Pre-master secret (encrypted with server's public key)
  |    (both derive session key) |
  |--- Finished (encrypted) --->|   First encrypted message
  |<-- Finished (encrypted) ----|   Server confirms
  |                              |   Encrypted communication begins
```

핵심 개념:
- **비대칭 암호화** (RSA/ECDSA)는 핸드셰이크에만 사용됩니다
- **대칭 암호화** (AES)는 실제 데이터 전송에 사용됩니다 (더 빠름)
- **TLS 1.3**은 핸드셰이크를 1회 왕복으로 줄였습니다 (TLS 1.2에서는 2회)

---

## OSI 모델

물리적 케이블에서 브라우저까지 7개의 계층. 각 계층은 반대편의 동일 계층과 통신합니다.

| 계층 | 이름 | 프로토콜 예시 | 데이터 단위 | 장비 |
|------|------|---------------|-------------|------|
| 7 | 응용 | HTTP, FTP, DNS, SMTP | 데이터 | — |
| 6 | 표현 | SSL/TLS, JPEG, ASCII | 데이터 | — |
| 5 | 세션 | NetBIOS, RPC | 데이터 | — |
| 4 | 전송 | TCP, UDP | 세그먼트/데이터그램 | — |
| 3 | 네트워크 | IP, ICMP, ARP | 패킷 | 라우터 |
| 2 | 데이터 링크 | Ethernet, Wi-Fi, PPP | 프레임 | 스위치 |
| 1 | 물리 | 케이블, 무선, 광섬유 | 비트 | 허브 |

> **암기법 (위에서 아래로):** **응**용 **표**현 **세**션 **전**송 **네**트워크 **데**이터링크 **물**리 — "응표세전네데물"

### TCP/IP 모델 (간소화)

| TCP/IP 계층 | OSI 대응 계층 | 예시 |
|-------------|---------------|------|
| 응용 | 7, 6, 5 | HTTP, DNS, SSH |
| 전송 | 4 | TCP, UDP |
| 인터넷 | 3 | IP, ICMP |
| 네트워크 접근 | 2, 1 | Ethernet, Wi-Fi |

---

## DNS 레코드 유형

도메인 이름이 서비스에 매핑되는 방법입니다.

| 유형 | 용도 | 예시 |
|------|------|------|
| A | 도메인 → IPv4 | `example.com → 93.184.216.34` |
| AAAA | 도메인 → IPv6 | `example.com → 2606:2800:...` |
| CNAME | 다른 도메인의 별칭 | `www.example.com → example.com` |
| MX | 메일 서버 | `example.com → mail.example.com` |
| TXT | 인증, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | 네임서버 위임 | `example.com → ns1.provider.com` |
| SOA | 영역 권한 정보 | 시리얼, 갱신, 재시도, 만료 |
| SRV | 서비스 위치 | `_sip._tcp.example.com` |
| PTR | 역방향 조회 (IP → 도메인) | `34.216.184.93 → example.com` |

---

## SSH 포트 포워딩

SSH를 통해 트래픽을 터널링합니다. 방화벽 뒤의 서비스에 접근할 때 필수적입니다.

```bash
# 로컬 포워딩: localhost:9906을 통해 remote_host:3306에 접근
ssh -L 9906:localhost:3306 user@remote_host

# 리모트 포워딩: localhost:3000을 원격지의 8080으로 노출
ssh -R 8080:localhost:3000 user@remote_host

# 다이나믹 포워딩 (localhost:1080에 SOCKS 프록시)
ssh -D 1080 user@remote_host

# 점프 호스트를 통한 터널링
ssh -J jump_host user@final_host
```

---

## 빠른 참조 테이블

| 항목 | 명령어 / 값 |
|------|-------------|
| 열린 포트 확인 | `ss -tlnp` 또는 `netstat -tlnp` |
| 포트 스캔 | `nmap -sV target` |
| DNS 조회 | `dig example.com A` 또는 `nslookup example.com` |
| 경로 추적 | `traceroute example.com` |
| 연결 테스트 | `ping -c 4 example.com` |
| HTTP 요청 | `curl -I https://example.com` |
| TLS 인증서 확인 | `openssl s_client -connect example.com:443` |
| 패킷 캡처 | `tcpdump -i eth0 port 80` |
