---
title: "Nmap 필드 매뉴얼: 네트워크 정찰 명령어"
description: "네트워크 스캔, 호스트 탐색, 포트 열거, 서비스 탐지, 취약점 평가를 위한 필수 Nmap 명령어. 침투 테스터를 위한 전술적 빠른 참조."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "nmap 명령어", "네트워크 스캔 가이드", "nmap 포트 스캔", "nmap 서비스 탐지", "nmap 스크립트 NSE", "nmap 취약점 스캔", "침투 테스트 명령어"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Nmap 필드 매뉴얼: 네트워크 정찰 명령어",
    "description": "네트워크 스캔, 호스트 탐색, 포트 열거, 취약점 평가를 위한 필수 Nmap 명령어.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## $ System_Init

Nmap은 모든 정찰 활동에서 가장 먼저 로드되는 도구입니다. 공격 표면을 매핑하고, 활성 호스트를 식별하고, 열린 포트를 열거하고, 서비스를 핑거프린팅하고, 취약점을 탐지합니다 — 모두 단일 바이너리에서. 이 필드 매뉴얼은 네트워크 정찰의 각 단계에 대한 정확한 명령어를 제공합니다.

모든 명령어는 승인된 테스트를 가정합니다. 책임감 있게 배포하십시오.

---

## $ Host_Discovery

포트 스캔 전에 네트워크에서 활성 대상을 식별합니다.

### Ping 스윕 (ICMP 에코)

```bash
# ICMP ping을 사용하여 서브넷에서 활성 호스트 탐색
nmap -sn 192.168.1.0/24
```

### ARP 탐색 (로컬 네트워크만)

```bash
# 로컬 LAN에서 호스트 탐색을 위해 ARP 요청 사용 (가장 빠른 방법)
nmap -sn -PR 192.168.1.0/24
```

### 특정 포트의 TCP SYN 탐색

```bash
# 일반 포트로 SYN 패킷을 전송하여 호스트 탐색
nmap -sn -PS22,80,443 10.0.0.0/24
```

### DNS 확인 비활성화 (스캔 속도 향상)

```bash
# 더 빠른 결과를 위해 역방향 DNS 조회 건너뛰기
nmap -sn -n 192.168.1.0/24
```

### 목록 스캔 (패킷 전송 없음)

```bash
# 패킷을 보내지 않고 스캔될 대상 나열
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

열린 포트를 열거하여 대상의 공격 표면을 매핑합니다.

### SYN 스캔 (스텔스 스캔 — 기본값)

```bash
# 반개방 스캔: SYN 전송, SYN/ACK 수신, RST 전송 (핸드셰이크를 완료하지 않음)
sudo nmap -sS 192.168.1.100
```

### TCP 연결 스캔 (루트 불필요)

```bash
# 완전한 TCP 핸드셰이크 스캔 (느리지만 권한 상승 없이 작동)
nmap -sT 192.168.1.100
```

### UDP 스캔

```bash
# 열린 UDP 포트 스캔 (프로토콜 동작으로 인해 느림)
sudo nmap -sU 192.168.1.100
```

### 특정 포트 스캔

```bash
# 특정 포트만 스캔
nmap -p 22,80,443,8080 192.168.1.100

# 포트 범위 스캔
nmap -p 1-1024 192.168.1.100

# 모든 65535개 포트 스캔
nmap -p- 192.168.1.100
```

### 상위 포트 스캔

```bash
# 가장 일반적으로 열려 있는 100개 포트 스캔
nmap --top-ports 100 192.168.1.100
```

### 빠른 스캔 (상위 100개 포트)

```bash
# 신속한 평가를 위해 포트 수를 줄인 빠른 스캔
nmap -F 192.168.1.100
```

---

## $ Service_Detection

각 열린 포트에서 실행 중인 소프트웨어를 식별합니다.

### 버전 탐지

```bash
# 열린 포트를 조사하여 서비스 이름과 버전 결정
nmap -sV 192.168.1.100
```

### 공격적 버전 탐지

```bash
# 탐지 강도 증가 (1-9, 기본값 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### OS 핑거프린팅

```bash
# TCP/IP 스택 분석을 사용하여 대상의 운영 체제 탐지
sudo nmap -O 192.168.1.100
```

### 서비스 + OS 탐지 결합

```bash
# OS 핑거프린팅과 함께 전체 서비스 열거
sudo nmap -sV -O 192.168.1.100
```

### 공격적 스캔 (OS + 버전 + 스크립트 + traceroute)

```bash
# 하나의 플래그로 모든 탐지 기능 활성화
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — 자동화된 취약점 탐지 및 열거.

### 기본 스크립트 실행

```bash
# 안전하고 정보 제공적인 기본 스크립트 세트 실행
nmap -sC 192.168.1.100
```

### 특정 스크립트 실행

```bash
# 이름으로 단일 NSE 스크립트 실행
nmap --script=http-title 192.168.1.100
```

### 스크립트 카테고리 실행

```bash
# 모든 취약점 탐지 스크립트 실행
nmap --script=vuln 192.168.1.100

# 모든 탐색 스크립트 실행
nmap --script=discovery 192.168.1.100

# 인증 서비스에 대한 브루트포스 스크립트 실행
nmap --script=brute 192.168.1.100
```

### HTTP 열거

```bash
# 웹 서버 디렉토리 및 파일 열거
nmap --script=http-enum 192.168.1.100

# 웹 애플리케이션 방화벽 탐지
nmap --script=http-waf-detect 192.168.1.100
```

### SMB 열거

```bash
# SMB 공유 및 사용자 열거 (Windows 네트워크)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### SSL/TLS 분석

```bash
# SSL 인증서 세부 정보 및 암호화 제품군 확인
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

승인된 침투 테스트 중 방화벽과 IDS를 우회합니다.

### 패킷 단편화

```bash
# 간단한 패킷 필터를 우회하기 위해 프로브 패킷을 더 작은 조각으로 분할
sudo nmap -f 192.168.1.100
```

### 디코이 스캔

```bash
# 실제 스캐너를 마스킹하기 위해 위조된 소스 IP 생성
sudo nmap -D RND:10 192.168.1.100
```

### 소스 포트 위조

```bash
# 포트 기반 방화벽 규칙을 우회하기 위해 신뢰할 수 있는 소스 포트 사용
sudo nmap --source-port 53 192.168.1.100
```

### 타이밍 제어

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### 유휴 스캔 (좀비 스캔)

```bash
# IP를 공개하지 않고 스캔하기 위해 제3자 "좀비" 호스트 사용
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

문서화 및 사후 처리를 위해 스캔 결과를 저장합니다.

### 일반 출력

```bash
# 사람이 읽을 수 있는 형식으로 결과 저장
nmap -oN scan_results.txt 192.168.1.100
```

### XML 출력 (도구용)

```bash
# XML 형식으로 결과 저장 (Metasploit 등에서 파싱 가능)
nmap -oX scan_results.xml 192.168.1.100
```

### Grep 가능 출력

```bash
# 스크립팅을 위한 grep 친화적 형식으로 결과 저장
nmap -oG scan_results.gnmap 192.168.1.100
```

### 모든 형식 동시 저장

```bash
# 일반, XML, grep 가능 형식으로 동시에 저장
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

일반적인 작전 시나리오를 위한 복사-붙여넣기 명령 체인.

### 빠른 정찰

```bash
# 대상의 빠른 초기 평가
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### 서비스 탐지를 포함한 전체 포트 스캔

```bash
# 버전 탐지를 포함한 모든 포트의 포괄적 스캔
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### 취약점 평가

```bash
# 서비스 탐지 및 취약점 스크립트
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### 스텔스 정찰 (최소 흔적)

```bash
# 적극적인 모니터링이 있는 환경을 위한 낮은 프로파일 스캔
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
