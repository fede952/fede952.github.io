---
title: "O Mapa da Internet: Portas de Rede, Protocolos e Códigos de Status"
description: "Guia visual de TCP/IP, Modelo OSI, Portas Comuns (SSH, HTTP, DNS) e Códigos de Status HTTP para DevOps e Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["portas comuns cheat sheet", "códigos status http", "tcp vs udp", "modelo osi explicado", "tipos registros dns", "ssh port forwarding"]
draft: false
proficiency: "Intermediate"
aliases: ["/cheatsheets/networking-ports-protocols/"]
---

## Portas Comuns

Todo serviço em uma rede escuta em uma porta. Estas são as que você precisa saber de cor.

### Portas Conhecidas (0–1023)

| Porta | Protocolo | Serviço | Notas |
|-------|-----------|---------|-------|
| 20 | TCP | FTP Data | Transferência de dados em modo ativo |
| 21 | TCP | FTP Control | Comandos e autenticação |
| 22 | TCP | SSH / SFTP | Shell seguro e transferência de arquivos |
| 23 | TCP | Telnet | Acesso remoto sem criptografia (evite) |
| 25 | TCP | SMTP | Envio de email |
| 53 | TCP/UDP | DNS | Resolução de nomes de domínio |
| 67/68 | UDP | DHCP | Atribuição dinâmica de IP |
| 80 | TCP | HTTP | Tráfego web sem criptografia |
| 110 | TCP | POP3 | Recuperação de email |
| 143 | TCP | IMAP | Recuperação de email (lado servidor) |
| 443 | TCP | HTTPS | Tráfego web criptografado (TLS) |
| 445 | TCP | SMB | Compartilhamento de arquivos Windows |
| 587 | TCP | SMTP (TLS) | Envio seguro de email |

### Portas Registradas (1024–49151)

| Porta | Protocolo | Serviço | Notas |
|-------|-----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener do banco Oracle |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Protocolo de Área de Trabalho Remota |
| 5432 | TCP | PostgreSQL | Banco de dados PostgreSQL |
| 5900 | TCP | VNC | Computação de Rede Virtual |
| 6379 | TCP | Redis | Armazenamento de dados em memória |
| 8080 | TCP | HTTP Alt | Porta comum de dev/proxy |
| 8443 | TCP | HTTPS Alt | Porta HTTPS alternativa |
| 27017 | TCP | MongoDB | Banco de dados MongoDB |

---

## Códigos de status HTTP

A forma do servidor te dizer o que aconteceu. Agrupados por categoria.

### 1xx — Informacional

| Código | Nome | Significado |
|--------|------|-------------|
| 100 | Continue | Continue enviando o corpo da requisição |
| 101 | Switching Protocols | Atualizando para WebSocket |

### 2xx — Sucesso

| Código | Nome | Significado |
|--------|------|-------------|
| 200 | OK | Requisição bem-sucedida |
| 201 | Created | Recurso criado (sucesso no POST) |
| 204 | No Content | Sucesso, mas nada para retornar |

### 3xx — Redirecionamento

| Código | Nome | Significado |
|--------|------|-------------|
| 301 | Moved Permanently | URL mudou permanentemente (atualize favoritos) |
| 302 | Found | Redirecionamento temporário |
| 304 | Not Modified | Use a versão em cache |
| 307 | Temporary Redirect | Como 302, mas mantendo o método HTTP |
| 308 | Permanent Redirect | Como 301, mas mantendo o método HTTP |

### 4xx — Erros do Cliente

| Código | Nome | Significado |
|--------|------|-------------|
| 400 | Bad Request | Sintaxe mal formada ou dados inválidos |
| 401 | Unauthorized | Autenticação necessária |
| 403 | Forbidden | Autenticado mas não autorizado |
| 404 | Not Found | Recurso não existe |
| 405 | Method Not Allowed | Verbo HTTP errado (GET vs POST) |
| 408 | Request Timeout | Servidor cansou de esperar |
| 409 | Conflict | Conflito de estado (ex: duplicata) |
| 413 | Payload Too Large | Corpo da requisição excede o limite |
| 418 | I'm a Teapot | RFC 2324. Sim, é real. |
| 429 | Too Many Requests | Limite de requisições atingido |

### 5xx — Erros do Servidor

| Código | Nome | Significado |
|--------|------|-------------|
| 500 | Internal Server Error | Falha genérica do servidor |
| 502 | Bad Gateway | Servidor upstream enviou resposta inválida |
| 503 | Service Unavailable | Servidor sobrecarregado ou em manutenção |
| 504 | Gateway Timeout | Servidor upstream não respondeu a tempo |

---

## TCP vs UDP

Os dois protocolos da camada de transporte. Ferramentas diferentes para trabalhos diferentes.

| Característica | TCP | UDP |
|----------------|-----|-----|
| Conexão | Orientado a conexão (handshake) | Sem conexão (dispara e esquece) |
| Confiabilidade | Entrega garantida, ordenada | Sem garantia, sem ordenação |
| Velocidade | Mais lento (overhead) | Mais rápido (overhead mínimo) |
| Tamanho do cabeçalho | 20–60 bytes | 8 bytes |
| Controle de fluxo | Sim (janelamento) | Não |
| Casos de uso | Web, email, transferência de arquivos, SSH | DNS, streaming, jogos, VoIP |

### Handshake de Três Vias do TCP

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### Encerramento de Conexão TCP

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## Handshake SSL/TLS

Como o HTTPS estabelece uma conexão criptografada.

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

Conceitos-chave:
- **Criptografia assimétrica** (RSA/ECDSA) é usada apenas para o handshake
- **Criptografia simétrica** (AES) é usada para a transferência real de dados (mais rápida)
- **TLS 1.3** reduziu o handshake para 1 ida e volta (vs 2 no TLS 1.2)

---

## O Modelo OSI

Sete camadas, dos cabos físicos ao seu navegador. Cada camada se comunica com sua equivalente no outro lado.

| Camada | Nome | Exemplos de Protocolo | Unidade de Dados | Dispositivos |
|--------|------|-----------------------|-------------------|--------------|
| 7 | Aplicação | HTTP, FTP, DNS, SMTP | Dados | — |
| 6 | Apresentação | SSL/TLS, JPEG, ASCII | Dados | — |
| 5 | Sessão | NetBIOS, RPC | Dados | — |
| 4 | Transporte | TCP, UDP | Segmento/Datagrama | — |
| 3 | Rede | IP, ICMP, ARP | Pacote | Roteador |
| 2 | Enlace de Dados | Ethernet, Wi-Fi, PPP | Quadro | Switch |
| 1 | Física | Cabos, Rádio, Fibra | Bits | Hub |

> **Mnemônico (de cima para baixo):** **A**plicação **A**presentação **S**essão **T**ransporte **R**ede **E**nlace **F**ísica

### Modelo TCP/IP (Simplificado)

| Camada TCP/IP | Equivalente OSI | Exemplos |
|---------------|-----------------|----------|
| Aplicação | 7, 6, 5 | HTTP, DNS, SSH |
| Transporte | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Acesso a Rede | 2, 1 | Ethernet, Wi-Fi |

---

## Tipos de Registros DNS

Como nomes de domínio mapeiam para serviços.

| Tipo | Finalidade | Exemplo |
|------|------------|---------|
| A | Domínio → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domínio → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias para outro domínio | `www.example.com → example.com` |
| MX | Servidor de email | `example.com → mail.example.com` |
| TXT | Verificação, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Delegação de nameserver | `example.com → ns1.provider.com` |
| SOA | Informação de autoridade da zona | Serial, refresh, retry, expire |
| SRV | Localização de serviço | `_sip._tcp.example.com` |
| PTR | Consulta reversa (IP → domínio) | `34.216.184.93 → example.com` |

---

## Encaminhamento de Portas SSH

Tunelar tráfego através do SSH. Essencial para acessar serviços atrás de firewalls.

```bash
# Local forwarding: access remote_host:3306 via localhost:9906
ssh -L 9906:localhost:3306 user@remote_host

# Remote forwarding: expose your localhost:3000 on remote:8080
ssh -R 8080:localhost:3000 user@remote_host

# Dynamic forwarding (SOCKS proxy on localhost:1080)
ssh -D 1080 user@remote_host

# Tunnel through a jump host
ssh -J jump_host user@final_host
```

---

## Tabela de referência rápida

| O que | Comando / Valor |
|-------|-----------------|
| Verificar portas abertas | `ss -tlnp` ou `netstat -tlnp` |
| Escanear portas | `nmap -sV target` |
| Consulta DNS | `dig example.com A` ou `nslookup example.com` |
| Rastrear rota | `traceroute example.com` |
| Testar conectividade | `ping -c 4 example.com` |
| Requisição HTTP | `curl -I https://example.com` |
| Verificar certificado TLS | `openssl s_client -connect example.com:443` |
| Capturar pacotes | `tcpdump -i eth0 port 80` |
