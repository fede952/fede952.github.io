---
title: "El Mapa de Internet: Puertos de Red, Protocolos y Codigos de Estado"
description: "Guia visual de TCP/IP, Modelo OSI, Puertos Comunes (SSH, HTTP, DNS) y Codigos de Estado HTTP para DevOps y Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["puertos comunes cheat sheet", "codigos de estado http", "tcp vs udp", "modelo osi explicado", "tipos de registros dns", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "El Mapa de Internet: Puertos de Red, Protocolos y Codigos de Estado",
    "description": "Guia visual de TCP/IP, Modelo OSI, Puertos Comunes (SSH, HTTP, DNS) y Codigos de Estado HTTP para DevOps y Hackers.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Puertos Comunes

Cada servicio en una red escucha en un puerto. Estos son los que necesitas saber de memoria.

### Puertos Bien Conocidos (0–1023)

| Puerto | Protocolo | Servicio | Notas |
|--------|-----------|----------|-------|
| 20 | TCP | FTP Data | Transferencia de datos en modo activo |
| 21 | TCP | FTP Control | Comandos y autenticacion |
| 22 | TCP | SSH / SFTP | Shell seguro y transferencia de archivos |
| 23 | TCP | Telnet | Acceso remoto sin cifrar (evitar) |
| 25 | TCP | SMTP | Envio de correo electronico |
| 53 | TCP/UDP | DNS | Resolucion de nombres de dominio |
| 67/68 | UDP | DHCP | Asignacion dinamica de IP |
| 80 | TCP | HTTP | Trafico web sin cifrar |
| 110 | TCP | POP3 | Recuperacion de correo |
| 143 | TCP | IMAP | Recuperacion de correo (lado servidor) |
| 443 | TCP | HTTPS | Trafico web cifrado (TLS) |
| 445 | TCP | SMB | Compartir archivos en Windows |
| 587 | TCP | SMTP (TLS) | Envio seguro de correo |

### Puertos Registrados (1024–49151)

| Puerto | Protocolo | Servicio | Notas |
|--------|-----------|----------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener de Oracle database |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Protocolo de Escritorio Remoto |
| 5432 | TCP | PostgreSQL | Base de datos PostgreSQL |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | Almacen de datos en memoria |
| 8080 | TCP | HTTP Alt | Puerto comun de desarrollo/proxy |
| 8443 | TCP | HTTPS Alt | Puerto HTTPS alternativo |
| 27017 | TCP | MongoDB | Base de datos MongoDB |

---

## Codigos de Estado HTTP

La forma que tiene el servidor de decirte que paso. Agrupados por categoria.

### 1xx — Informativos

| Codigo | Nombre | Significado |
|--------|--------|-------------|
| 100 | Continue | Sigue enviando el cuerpo de la peticion |
| 101 | Switching Protocols | Actualizando a WebSocket |

### 2xx — Exito

| Codigo | Nombre | Significado |
|--------|--------|-------------|
| 200 | OK | La peticion fue exitosa |
| 201 | Created | Recurso creado (POST exitoso) |
| 204 | No Content | Exito, pero no hay nada que devolver |

### 3xx — Redireccion

| Codigo | Nombre | Significado |
|--------|--------|-------------|
| 301 | Moved Permanently | La URL cambio para siempre (actualizar marcadores) |
| 302 | Found | Redireccion temporal |
| 304 | Not Modified | Usar la version en cache |
| 307 | Temporary Redirect | Como 302, pero mantiene el metodo HTTP |
| 308 | Permanent Redirect | Como 301, pero mantiene el metodo HTTP |

### 4xx — Errores del Cliente

| Codigo | Nombre | Significado |
|--------|--------|-------------|
| 400 | Bad Request | Sintaxis malformada o datos invalidos |
| 401 | Unauthorized | Se requiere autenticacion |
| 403 | Forbidden | Autenticado pero no autorizado |
| 404 | Not Found | El recurso no existe |
| 405 | Method Not Allowed | Verbo HTTP incorrecto (GET vs POST) |
| 408 | Request Timeout | El servidor se canso de esperar |
| 409 | Conflict | Conflicto de estado (ej: duplicado) |
| 413 | Payload Too Large | El cuerpo de la peticion excede el limite |
| 418 | I'm a Teapot | RFC 2324. Si, es real. |
| 429 | Too Many Requests | Limite de tasa alcanzado |

### 5xx — Errores del Servidor

| Codigo | Nombre | Significado |
|--------|--------|-------------|
| 500 | Internal Server Error | Fallo generico del servidor |
| 502 | Bad Gateway | El servidor upstream envio una respuesta invalida |
| 503 | Service Unavailable | Servidor sobrecargado o en mantenimiento |
| 504 | Gateway Timeout | El servidor upstream no respondio a tiempo |

---

## TCP vs UDP

Los dos protocolos de la capa de transporte. Herramientas diferentes para trabajos diferentes.

| Caracteristica | TCP | UDP |
|----------------|-----|-----|
| Conexion | Orientado a conexion (handshake) | Sin conexion (disparar y olvidar) |
| Fiabilidad | Entrega garantizada, ordenada | Sin garantia, sin orden |
| Velocidad | Mas lento (overhead) | Mas rapido (overhead minimo) |
| Tamano de cabecera | 20–60 bytes | 8 bytes |
| Control de flujo | Si (ventanas) | No |
| Casos de uso | Web, email, transferencia de archivos, SSH | DNS, streaming, gaming, VoIP |

### Handshake de Tres Vias TCP

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### Cierre de Conexion TCP

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

Como HTTPS establece una conexion cifrada.

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

Conceptos clave:
- **Cifrado asimetrico** (RSA/ECDSA) se usa solo para el handshake
- **Cifrado simetrico** (AES) se usa para la transferencia real de datos (mas rapido)
- **TLS 1.3** redujo el handshake a 1 ida y vuelta (vs 2 en TLS 1.2)

---

## El Modelo OSI

Siete capas, desde cables fisicos hasta tu navegador. Cada capa se comunica con su par en el otro extremo.

| Capa | Nombre | Ejemplos de Protocolo | Unidad de Datos | Dispositivos |
|------|--------|----------------------|-----------------|--------------|
| 7 | Aplicacion | HTTP, FTP, DNS, SMTP | Datos | — |
| 6 | Presentacion | SSL/TLS, JPEG, ASCII | Datos | — |
| 5 | Sesion | NetBIOS, RPC | Datos | — |
| 4 | Transporte | TCP, UDP | Segmento/Datagrama | — |
| 3 | Red | IP, ICMP, ARP | Paquete | Router |
| 2 | Enlace de Datos | Ethernet, Wi-Fi, PPP | Trama | Switch |
| 1 | Fisica | Cables, Radio, Fibra | Bits | Hub |

> **Mnemonico (de arriba a abajo):** **A**plicacion **P**resentacion **S**esion **T**ransporte **R**ed e**N**lace **F**isica

### Modelo TCP/IP (Simplificado)

| Capa TCP/IP | Equivalente OSI | Ejemplos |
|-------------|-----------------|----------|
| Aplicacion | 7, 6, 5 | HTTP, DNS, SSH |
| Transporte | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Acceso a Red | 2, 1 | Ethernet, Wi-Fi |

---

## Tipos de Registros DNS

Como los nombres de dominio se mapean a servicios.

| Tipo | Proposito | Ejemplo |
|------|-----------|---------|
| A | Dominio → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Dominio → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias a otro dominio | `www.example.com → example.com` |
| MX | Servidor de correo | `example.com → mail.example.com` |
| TXT | Verificacion, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Delegacion de nameserver | `example.com → ns1.provider.com` |
| SOA | Info de autoridad de zona | Serial, refresh, retry, expire |
| SRV | Ubicacion de servicio | `_sip._tcp.example.com` |
| PTR | Busqueda inversa (IP → dominio) | `34.216.184.93 → example.com` |

---

## Reenvio de Puertos SSH

Tunelizar trafico a traves de SSH. Esencial para acceder a servicios detras de firewalls.

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

## Tabla de Referencia Rapida

| Que | Comando / Valor |
|-----|-----------------|
| Verificar puertos abiertos | `ss -tlnp` o `netstat -tlnp` |
| Escanear puertos | `nmap -sV target` |
| Consulta DNS | `dig example.com A` o `nslookup example.com` |
| Trazar ruta | `traceroute example.com` |
| Probar conectividad | `ping -c 4 example.com` |
| Peticion HTTP | `curl -I https://example.com` |
| Verificar certificado TLS | `openssl s_client -connect example.com:443` |
| Capturar paquetes | `tcpdump -i eth0 port 80` |
