---
title: "Manual de Campo Nmap: Comandos de Reconhecimento de Rede"
description: "Comandos essenciais do Nmap para varredura de rede, descoberta de hosts, enumeração de portas, detecção de serviços e avaliação de vulnerabilidades. Uma referência tática rápida para pentesters."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "comandos nmap", "guia varredura de rede", "nmap varredura de portas", "nmap detecção de serviços", "nmap scripts NSE", "nmap varredura de vulnerabilidades", "comandos penetration testing"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Manual de Campo Nmap: Comandos de Reconhecimento de Rede",
    "description": "Comandos essenciais do Nmap para varredura de rede, descoberta de hosts, enumeração de portas e avaliação de vulnerabilidades.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## $ System_Init

Nmap é a primeira ferramenta carregada em qualquer atividade de reconhecimento. Ele mapeia a superfície de ataque, identifica hosts ativos, enumera portas abertas, identifica serviços e detecta vulnerabilidades — tudo a partir de um único binário. Este manual de campo fornece os comandos exatos para cada fase do reconhecimento de rede.

Todos os comandos pressupõem testes autorizados. Implemente responsavelmente.

---

## $ Host_Discovery

Identificar alvos ativos na rede antes da varredura de portas.

### Varredura de ping (ICMP echo)

```bash
# Descobrir hosts ativos em uma sub-rede usando ping ICMP
nmap -sn 192.168.1.0/24
```

### Descoberta ARP (apenas rede local)

```bash
# Usar requisições ARP para descoberta de hosts na LAN local (método mais rápido)
nmap -sn -PR 192.168.1.0/24
```

### Descoberta TCP SYN em portas específicas

```bash
# Descobrir hosts enviando pacotes SYN para portas comuns
nmap -sn -PS22,80,443 10.0.0.0/24
```

### Desabilitar resolução DNS (acelerar varreduras)

```bash
# Pular buscas DNS reversas para resultados mais rápidos
nmap -sn -n 192.168.1.0/24
```

### Varredura de lista (nenhum pacote enviado)

```bash
# Listar alvos que seriam varridos sem enviar nenhum pacote
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

Enumerar portas abertas para mapear a superfície de ataque do alvo.

### Varredura SYN (varredura stealth — padrão)

```bash
# Varredura semi-aberta: envia SYN, recebe SYN/ACK, envia RST (nunca completa o handshake)
sudo nmap -sS 192.168.1.100
```

### Varredura TCP connect (não requer root)

```bash
# Varredura completa com handshake TCP (mais lenta mas funciona sem privilégios elevados)
nmap -sT 192.168.1.100
```

### Varredura UDP

```bash
# Varrer portas UDP abertas (mais lenta devido ao comportamento do protocolo)
sudo nmap -sU 192.168.1.100
```

### Varrer portas específicas

```bash
# Varrer apenas portas específicas
nmap -p 22,80,443,8080 192.168.1.100

# Varrer uma faixa de portas
nmap -p 1-1024 192.168.1.100

# Varrer todas as 65535 portas
nmap -p- 192.168.1.100
```

### Varredura de portas principais

```bash
# Varrer as 100 portas mais comumente abertas
nmap --top-ports 100 192.168.1.100
```

### Varredura rápida (top 100 portas)

```bash
# Varredura rápida com número reduzido de portas para avaliação rápida
nmap -F 192.168.1.100
```

---

## $ Service_Detection

Identificar qual software está sendo executado em cada porta aberta.

### Detecção de versão

```bash
# Sondar portas abertas para determinar nome e versão do serviço
nmap -sV 192.168.1.100
```

### Detecção de versão agressiva

```bash
# Aumentar intensidade de detecção (1-9, padrão 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### Fingerprinting de SO

```bash
# Detectar o sistema operacional do alvo usando análise de pilha TCP/IP
sudo nmap -O 192.168.1.100
```

### Detecção combinada de serviço + SO

```bash
# Enumeração completa de serviços com fingerprinting de SO
sudo nmap -sV -O 192.168.1.100
```

### Varredura agressiva (SO + versão + scripts + traceroute)

```bash
# Habilitar todos os recursos de detecção em uma única flag
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — detecção automatizada de vulnerabilidades e enumeração.

### Executar scripts padrão

```bash
# Executar o conjunto padrão de scripts seguros e informativos
nmap -sC 192.168.1.100
```

### Executar um script específico

```bash
# Executar um único script NSE por nome
nmap --script=http-title 192.168.1.100
```

### Executar categorias de scripts

```bash
# Executar todos os scripts de detecção de vulnerabilidades
nmap --script=vuln 192.168.1.100

# Executar todos os scripts de descoberta
nmap --script=discovery 192.168.1.100

# Executar scripts de força bruta contra serviços de autenticação
nmap --script=brute 192.168.1.100
```

### Enumeração HTTP

```bash
# Enumerar diretórios e arquivos do servidor web
nmap --script=http-enum 192.168.1.100

# Detectar firewalls de aplicação web
nmap --script=http-waf-detect 192.168.1.100
```

### Enumeração SMB

```bash
# Enumerar compartilhamentos SMB e usuários (redes Windows)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### Análise SSL/TLS

```bash
# Verificar detalhes de certificado SSL e conjuntos de cifras
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

Contornar firewalls e IDS durante testes de penetração autorizados.

### Fragmentar pacotes

```bash
# Dividir pacotes de sondagem em fragmentos menores para contornar filtros de pacotes simples
sudo nmap -f 192.168.1.100
```

### Varredura decoy

```bash
# Gerar IPs de origem falsificados para mascarar o scanner real
sudo nmap -D RND:10 192.168.1.100
```

### Falsificar porta de origem

```bash
# Usar uma porta de origem confiável para contornar regras de firewall baseadas em porta
sudo nmap --source-port 53 192.168.1.100
```

### Controle de temporização

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Varredura idle (varredura zombie)

```bash
# Usar um host "zombie" de terceiros para varrer sem revelar seu IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

Salvar resultados de varredura para documentação e pós-processamento.

### Saída normal

```bash
# Salvar resultados em formato legível por humanos
nmap -oN scan_results.txt 192.168.1.100
```

### Saída XML (para ferramentas)

```bash
# Salvar resultados em formato XML (analisável pelo Metasploit, etc.)
nmap -oX scan_results.xml 192.168.1.100
```

### Saída grep-able

```bash
# Salvar resultados em formato compatível com grep para scripting
nmap -oG scan_results.gnmap 192.168.1.100
```

### Todos os formatos de uma vez

```bash
# Salvar em formato normal, XML e grep-able simultaneamente
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

Cadeias de comandos copiar-colar para cenários de engajamento comuns.

### Reconhecimento rápido

```bash
# Avaliação inicial rápida de um alvo
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Varredura completa de portas com detecção de serviços

```bash
# Varredura abrangente de todas as portas com detecção de versão
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Avaliação de vulnerabilidades

```bash
# Detecção de serviços mais scripts de vulnerabilidades
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Reconhecimento stealth (pegada mínima)

```bash
# Varredura de baixo perfil para ambientes com monitoramento ativo
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
