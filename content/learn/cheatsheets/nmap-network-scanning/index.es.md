---
title: "Manual de Campo Nmap: Comandos de Reconocimiento de Redes"
description: "Comandos esenciales de Nmap para escaneo de redes, descubrimiento de hosts, enumeración de puertos, detección de servicios y evaluación de vulnerabilidades. Una referencia táctica rápida para pentesters."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "comandos nmap", "guía escaneo de red", "nmap escaneo de puertos", "nmap detección de servicios", "nmap scripts NSE", "nmap escaneo de vulnerabilidades", "comandos penetration testing"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Manual de Campo Nmap: Comandos de Reconocimiento de Redes",
    "description": "Comandos esenciales de Nmap para escaneo de redes, descubrimiento de hosts, enumeración de puertos y evaluación de vulnerabilidades.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## $ System_Init

Nmap es la primera herramienta cargada en cualquier actividad de reconocimiento. Mapea la superficie de ataque, identifica hosts activos, enumera puertos abiertos, identifica servicios y detecta vulnerabilidades — todo desde un único binario. Este manual de campo proporciona los comandos exactos para cada fase del reconocimiento de red.

Todos los comandos asumen pruebas autorizadas. Desplegar responsablemente.

---

## $ Host_Discovery

Identificar objetivos activos en la red antes del escaneo de puertos.

### Barrido de ping (ICMP echo)

```bash
# Descubrir hosts activos en una subred usando ping ICMP
nmap -sn 192.168.1.0/24
```

### Descubrimiento ARP (solo red local)

```bash
# Usar solicitudes ARP para descubrimiento de hosts en la LAN local (método más rápido)
nmap -sn -PR 192.168.1.0/24
```

### Descubrimiento TCP SYN en puertos específicos

```bash
# Descubrir hosts enviando paquetes SYN a puertos comunes
nmap -sn -PS22,80,443 10.0.0.0/24
```

### Deshabilitar resolución DNS (acelerar escaneos)

```bash
# Omitir búsquedas DNS inversas para resultados más rápidos
nmap -sn -n 192.168.1.0/24
```

### Escaneo de lista (sin enviar paquetes)

```bash
# Listar objetivos que serían escaneados sin enviar ningún paquete
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

Enumerar puertos abiertos para mapear la superficie de ataque del objetivo.

### Escaneo SYN (escaneo sigiloso — predeterminado)

```bash
# Escaneo semi-abierto: envía SYN, recibe SYN/ACK, envía RST (nunca completa el handshake)
sudo nmap -sS 192.168.1.100
```

### Escaneo TCP connect (no requiere root)

```bash
# Escaneo completo con handshake TCP (más lento pero funciona sin privilegios elevados)
nmap -sT 192.168.1.100
```

### Escaneo UDP

```bash
# Escanear puertos UDP abiertos (más lento debido al comportamiento del protocolo)
sudo nmap -sU 192.168.1.100
```

### Escanear puertos específicos

```bash
# Escanear solo puertos específicos
nmap -p 22,80,443,8080 192.168.1.100

# Escanear un rango de puertos
nmap -p 1-1024 192.168.1.100

# Escanear todos los 65535 puertos
nmap -p- 192.168.1.100
```

### Escaneo de puertos principales

```bash
# Escanear los 100 puertos más comúnmente abiertos
nmap --top-ports 100 192.168.1.100
```

### Escaneo rápido (top 100 puertos)

```bash
# Escaneo rápido con número reducido de puertos para evaluación rápida
nmap -F 192.168.1.100
```

---

## $ Service_Detection

Identificar qué software se ejecuta en cada puerto abierto.

### Detección de versión

```bash
# Sondear puertos abiertos para determinar nombre y versión del servicio
nmap -sV 192.168.1.100
```

### Detección de versión agresiva

```bash
# Aumentar intensidad de detección (1-9, predeterminado 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### Huella digital de SO

```bash
# Detectar el sistema operativo del objetivo usando análisis de pila TCP/IP
sudo nmap -O 192.168.1.100
```

### Detección combinada de servicio + SO

```bash
# Enumeración completa de servicios con huella digital de SO
sudo nmap -sV -O 192.168.1.100
```

### Escaneo agresivo (SO + versión + scripts + traceroute)

```bash
# Habilitar todas las características de detección en un solo flag
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — detección automática de vulnerabilidades y enumeración.

### Ejecutar scripts predeterminados

```bash
# Ejecutar el conjunto predeterminado de scripts seguros e informativos
nmap -sC 192.168.1.100
```

### Ejecutar un script específico

```bash
# Ejecutar un único script NSE por nombre
nmap --script=http-title 192.168.1.100
```

### Ejecutar categorías de scripts

```bash
# Ejecutar todos los scripts de detección de vulnerabilidades
nmap --script=vuln 192.168.1.100

# Ejecutar todos los scripts de descubrimiento
nmap --script=discovery 192.168.1.100

# Ejecutar scripts de fuerza bruta contra servicios de autenticación
nmap --script=brute 192.168.1.100
```

### Enumeración HTTP

```bash
# Enumerar directorios y archivos del servidor web
nmap --script=http-enum 192.168.1.100

# Detectar firewalls de aplicaciones web
nmap --script=http-waf-detect 192.168.1.100
```

### Enumeración SMB

```bash
# Enumerar recursos compartidos SMB y usuarios (redes Windows)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### Análisis SSL/TLS

```bash
# Verificar detalles del certificado SSL y conjuntos de cifrado
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

Evadir firewalls e IDS durante pruebas de penetración autorizadas.

### Fragmentar paquetes

```bash
# Dividir paquetes de sondeo en fragmentos más pequeños para evadir filtros de paquetes simples
sudo nmap -f 192.168.1.100
```

### Escaneo señuelo

```bash
# Generar IPs de origen falsificadas para enmascarar el escáner real
sudo nmap -D RND:10 192.168.1.100
```

### Falsificar puerto de origen

```bash
# Usar un puerto de origen confiable para evadir reglas de firewall basadas en puertos
sudo nmap --source-port 53 192.168.1.100
```

### Control de temporización

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Escaneo inactivo (escaneo zombie)

```bash
# Usar un host "zombie" de terceros para escanear sin revelar tu IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

Guardar resultados de escaneo para documentación y post-procesamiento.

### Salida normal

```bash
# Guardar resultados en formato legible por humanos
nmap -oN scan_results.txt 192.168.1.100
```

### Salida XML (para herramientas)

```bash
# Guardar resultados en formato XML (procesable por Metasploit, etc.)
nmap -oX scan_results.xml 192.168.1.100
```

### Salida grep-able

```bash
# Guardar resultados en formato compatible con grep para scripting
nmap -oG scan_results.gnmap 192.168.1.100
```

### Todos los formatos a la vez

```bash
# Guardar en formato normal, XML y grep-able simultáneamente
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

Cadenas de comandos copiar-pegar para escenarios de engagement comunes.

### Reconocimiento rápido

```bash
# Evaluación inicial rápida de un objetivo
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Escaneo completo de puertos con detección de servicios

```bash
# Escaneo completo de todos los puertos con detección de versión
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Evaluación de vulnerabilidades

```bash
# Detección de servicios más scripts de vulnerabilidades
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Reconocimiento sigiloso (huella mínima)

```bash
# Escaneo de bajo perfil para entornos con monitoreo activo
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
