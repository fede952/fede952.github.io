---
title: "O Mapa da Internet: Portas de Rede, Protocolos e Codigos de Status"
description: "Guia visual de TCP/IP, Modelo OSI, Portas Comuns (SSH, HTTP, DNS) e Codigos de Status HTTP para DevOps e Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["portas comuns cheat sheet", "codigos status http", "tcp vs udp", "modelo osi explicado", "tipos registros dns", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "O Mapa da Internet: Portas de Rede, Protocolos e Codigos de Status",
    "description": "Guia visual de TCP/IP, Modelo OSI, Portas Comuns (SSH, HTTP, DNS) e Codigos de Status HTTP para DevOps e Hackers.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Portas Comuns

Todo servico em uma rede escuta em uma porta. Estas sao as que voce precisa saber de cor.

### Portas Conhecidas (0–1023)

| Porta | Protocolo | Servico | Notas |
|-------|-----------|---------|-------|
| 20 | TCP | FTP Data | Transferencia de dados em modo ativo |
| 21 | TCP | FTP Control | Comandos e autenticacao |
| 22 | TCP | SSH / SFTP | Shell seguro e transferencia de arquivos |
| 23 | TCP | Telnet | Acesso remoto sem criptografia (evite) |
| 25 | TCP | SMTP | Envio de email |
| 53 | TCP/UDP | DNS | Resolucao de nomes de dominio |
| 67/68 | UDP | DHCP | Atribuicao dinamica de IP |
| 80 | TCP | HTTP | Trafego web sem criptografia |
| 110 | TCP | POP3 | Recuperacao de email |
| 143 | TCP | IMAP | Recuperacao de email (lado servidor) |
| 443 | TCP | HTTPS | Trafego web criptografado (TLS) |
| 445 | TCP | SMB | Compartilhamento de arquivos Windows |
| 587 | TCP | SMTP (TLS) | Envio seguro de email |

### Portas Registradas (1024–49151)

| Porta | Protocolo | Servico | Notas |
|-------|-----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener do banco Oracle |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Protocolo de Area de Trabalho Remota |
| 5432 | TCP | PostgreSQL | Banco de dados PostgreSQL |
| 5900 | TCP | VNC | Computacao de Rede Virtual |
| 6379 | TCP | Redis | Armazenamento de dados em memoria |
| 8080 | TCP | HTTP Alt | Porta comum de dev/proxy |
| 8443 | TCP | HTTPS Alt | Porta HTTPS alternativa |
| 27017 | TCP | MongoDB | Banco de dados MongoDB |

---

## Codigos de Status HTTP

A forma do servidor te dizer o que aconteceu. Agrupados por categoria.

### 1xx — Informacional

| Codigo | Nome | Significado |
|--------|------|-------------|
| 100 | Continue | Continue enviando o corpo da requisicao |
| 101 | Switching Protocols | Atualizando para WebSocket |

### 2xx — Sucesso

| Codigo | Nome | Significado |
|--------|------|-------------|
| 200 | OK | Requisicao bem-sucedida |
| 201 | Created | Recurso criado (sucesso no POST) |
| 204 | No Content | Sucesso, mas nada para retornar |

### 3xx — Redirecionamento

| Codigo | Nome | Significado |
|--------|------|-------------|
| 301 | Moved Permanently | URL mudou permanentemente (atualize favoritos) |
| 302 | Found | Redirecionamento temporario |
| 304 | Not Modified | Use a versao em cache |
| 307 | Temporary Redirect | Como 302, mas mantendo o metodo HTTP |
| 308 | Permanent Redirect | Como 301, mas mantendo o metodo HTTP |

### 4xx — Erros do Cliente

| Codigo | Nome | Significado |
|--------|------|-------------|
| 400 | Bad Request | Sintaxe mal formada ou dados invalidos |
| 401 | Unauthorized | Autenticacao necessaria |
| 403 | Forbidden | Autenticado mas nao autorizado |
| 404 | Not Found | Recurso nao existe |
| 405 | Method Not Allowed | Verbo HTTP errado (GET vs POST) |
| 408 | Request Timeout | Servidor cansou de esperar |
| 409 | Conflict | Conflito de estado (ex: duplicata) |
| 413 | Payload Too Large | Corpo da requisicao excede o limite |
| 418 | I'm a Teapot | RFC 2324. Sim, e real. |
| 429 | Too Many Requests | Limite de requisicoes atingido |

### 5xx — Erros do Servidor

| Codigo | Nome | Significado |
|--------|------|-------------|
| 500 | Internal Server Error | Falha generica do servidor |
| 502 | Bad Gateway | Servidor upstream enviou resposta invalida |
| 503 | Service Unavailable | Servidor sobrecarregado ou em manutencao |
| 504 | Gateway Timeout | Servidor upstream nao respondeu a tempo |

---

## TCP vs UDP

Os dois protocolos da camada de transporte. Ferramentas diferentes para trabalhos diferentes.

| Caracteristica | TCP | UDP |
|----------------|-----|-----|
| Conexao | Orientado a conexao (handshake) | Sem conexao (dispara e esquece) |
| Confiabilidade | Entrega garantida, ordenada | Sem garantia, sem ordenacao |
| Velocidade | Mais lento (overhead) | Mais rapido (overhead minimo) |
| Tamanho do cabecalho | 20–60 bytes | 8 bytes |
| Controle de fluxo | Sim (janelamento) | Nao |
| Casos de uso | Web, email, transferencia de arquivos, SSH | DNS, streaming, jogos, VoIP |

### Handshake de Tres Vias do TCP

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### Encerramento de Conexao TCP

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

Como o HTTPS estabelece uma conexao criptografada.

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
- **Criptografia assimetrica** (RSA/ECDSA) e usada apenas para o handshake
- **Criptografia simetrica** (AES) e usada para a transferencia real de dados (mais rapida)
- **TLS 1.3** reduziu o handshake para 1 ida e volta (vs 2 no TLS 1.2)

---

## O Modelo OSI

Sete camadas, dos cabos fisicos ao seu navegador. Cada camada se comunica com sua equivalente no outro lado.

| Camada | Nome | Exemplos de Protocolo | Unidade de Dados | Dispositivos |
|--------|------|-----------------------|-------------------|--------------|
| 7 | Aplicacao | HTTP, FTP, DNS, SMTP | Dados | — |
| 6 | Apresentacao | SSL/TLS, JPEG, ASCII | Dados | — |
| 5 | Sessao | NetBIOS, RPC | Dados | — |
| 4 | Transporte | TCP, UDP | Segmento/Datagrama | — |
| 3 | Rede | IP, ICMP, ARP | Pacote | Roteador |
| 2 | Enlace de Dados | Ethernet, Wi-Fi, PPP | Quadro | Switch |
| 1 | Fisica | Cabos, Radio, Fibra | Bits | Hub |

> **Mnemonico (de cima para baixo):** **A**plicacao **A**presentacao **S**essao **T**ransporte **R**ede **E**nlace **F**isica

### Modelo TCP/IP (Simplificado)

| Camada TCP/IP | Equivalente OSI | Exemplos |
|---------------|-----------------|----------|
| Aplicacao | 7, 6, 5 | HTTP, DNS, SSH |
| Transporte | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Acesso a Rede | 2, 1 | Ethernet, Wi-Fi |

---

## Tipos de Registros DNS

Como nomes de dominio mapeiam para servicos.

| Tipo | Finalidade | Exemplo |
|------|------------|---------|
| A | Dominio → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Dominio → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias para outro dominio | `www.example.com → example.com` |
| MX | Servidor de email | `example.com → mail.example.com` |
| TXT | Verificacao, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Delegacao de nameserver | `example.com → ns1.provider.com` |
| SOA | Informacao de autoridade da zona | Serial, refresh, retry, expire |
| SRV | Localizacao de servico | `_sip._tcp.example.com` |
| PTR | Consulta reversa (IP → dominio) | `34.216.184.93 → example.com` |

---

## Encaminhamento de Portas SSH

Tunelar trafego atraves do SSH. Essencial para acessar servicos atras de firewalls.

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

## Tabela de Referencia Rapida

| O que | Comando / Valor |
|-------|-----------------|
| Verificar portas abertas | `ss -tlnp` ou `netstat -tlnp` |
| Escanear portas | `nmap -sV target` |
| Consulta DNS | `dig example.com A` ou `nslookup example.com` |
| Rastrear rota | `traceroute example.com` |
| Testar conectividade | `ping -c 4 example.com` |
| Requisicao HTTP | `curl -I https://example.com` |
| Verificar certificado TLS | `openssl s_client -connect example.com:443` |
| Capturar pacotes | `tcpdump -i eth0 port 80` |
