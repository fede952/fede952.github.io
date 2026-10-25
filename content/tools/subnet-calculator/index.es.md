---
title: "Calculadora de subredes IPv4/IPv6 y VLSM"
description: "Calcula red, broadcast, rango de hosts, máscara y wildcard de cualquier CIDR IPv4 o IPv6 y divide un bloque en subredes iguales o VLSM. En tu navegador."
intro: "Una **calculadora de subredes** para IPv4 e IPv6: escribe una dirección con su prefijo o máscara y obtén al instante la red, el broadcast, el rango de hosts utilizables, la máscara, la wildcard y el número de hosts, con vista binaria. Una tercera pestaña divide un bloque en subredes iguales o en subredes VLSM según el número de hosts."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["calculadora de subredes", "calculadora cidr", "calcular subred", "calculadora máscara de subred", "calculadora subredes ipv6", "calculadora vlsm", "máscara wildcard", "calcular dirección de red"]
tags: ["redes", "herramientas-desarrollo", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Calculadora de subredes para IPv4, IPv6 y VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "En la pestaña **IPv4**, escribe una dirección con prefijo (`10.0.0.5/8`), con máscara decimal (`172.16.5.4 255.255.240.0`) o con wildcard al estilo Cisco (`192.168.1.1 0.0.0.255`). Una dirección sin prefijo se toma como `/32`."
  - "Lee los resultados mientras escribes: red, broadcast, primer y último host utilizable, máscara, wildcard, hosts utilizables y direcciones totales, y el tipo de dirección (privada, pública, CGNAT, link-local…)."
  - "Mira la tabla **Binario**: los bits de red aparecen resaltados y los de host atenuados, así ves exactamente dónde corta el prefijo la dirección."
  - "En la pestaña **IPv6**, pega una dirección completa o comprimida con prefijo para obtener la forma comprimida según la RFC 5952, la forma expandida, la primera y la última dirección del prefijo y cuántas redes /64 contiene."
  - "En **Dividir (VLSM)**, indica el bloque a dividir y elige **En subredes iguales** (cuántas) o **Por hosts por subred (VLSM)** (una lista como `100, 50, 20, 2`). Copia cualquier valor con su botón **Copiar** o el plan completo con **Copiar tabla**."
faq:
  - q: "¿Por qué una /24 tiene 254 hosts utilizables y no 256?"
    a: "Una /24 tiene 256 direcciones, pero la primera es la dirección de red y la última la de broadcast. Ninguna de las dos se puede asignar a un host, así que quedan 254. La misma regla (total menos dos) se aplica a todos los prefijos hasta /30."
  - q: "¿Cómo trata la calculadora las /31 y /32?"
    a: "Una /31 se trata como enlace punto a punto según la RFC 3021: las dos direcciones son utilizables y no hay broadcast. Una /32 es un único host, usada para loopbacks, rutas de host y reglas de firewall. Los equipos antiguos que no admiten la RFC 3021 necesitan una /30 para un enlace."
  - q: "¿Qué es una máscara wildcard?"
    a: "El inverso bit a bit de la máscara de red: 255.255.255.0 se convierte en 0.0.0.255. Las ACL de Cisco y las sentencias network de OSPF usan wildcards, donde un bit 0 significa \"debe coincidir\" y un bit 1 \"cualquier valor\". Puedes escribir una wildcard directamente en el campo IPv4 y la calculadora la convierte en prefijo."
  - q: "¿Qué significa VLSM y por qué se asignan primero las subredes más grandes?"
    a: "Variable Length Subnet Masking permite que cada subred tenga su propio prefijo: una LAN de 100 hosts recibe una /25 y un enlace punto a punto una /31. Asignar de la petición más grande a la más pequeña mantiene cada subred alineada con su límite sin huecos desperdiciados; después los resultados se muestran en el orden en que los escribiste."
  - q: "¿Por qué al dividir en 3 subredes obtengo 4?"
    a: "La división en partes iguales toma bits de host prestados y cada bit duplica el número de subredes: 1 bit da 2 y 2 bits dan 4. Tres subredes necesitan por tanto 2 bits, que producen 4. Usa el modo VLSM si quieres exactamente las subredes que pides, cada una del tamaño de sus hosts."
  - q: "¿Qué prefijo IPv6 debe usar una LAN?"
    a: "Una /64. La autoconfiguración sin estado (SLAAC) y muchas funciones de IPv6 suponen un identificador de interfaz de 64 bits. Normalmente una sede recibe una /48 o una /56 y la divide en /64; la calculadora muestra cuántas redes /64 caben en el prefijo que introduces."
  - q: "¿Se envía a algún servidor lo que escribo?"
    a: "No. Todos los cálculos los hace un pequeño módulo JavaScript en tu navegador; la página no hace ninguna petición con tus datos, así que puedes usarla con planes de direccionamiento internos."
---

## Cómo funciona

### Aritmética IPv4

Una dirección IPv4 es un número de 32 bits. La calculadora lee los cuatro octetos (rechaza valores mayores que 255 y ceros a la izquierda ambiguos como `010`), construye la máscara a partir del prefijo poniendo a uno los *n* bits superiores y trabaja con operaciones bit a bit:

- **Dirección de red** = dirección AND máscara.
- **Wildcard** = NOT máscara.
- **Dirección de broadcast** = red OR wildcard.
- **Hosts utilizables** = 2^(32 − prefijo) − 2, con las dos excepciones de las preguntas frecuentes: una /31 tiene dos direcciones utilizables (RFC 3021) y una /32 tiene una.

Si escribes una máscara decimal, debe ser *contigua*: unos seguidos de ceros. `255.255.240.0` se acepta como /20; `255.0.255.0` se rechaza. Si el valor no es una máscara válida pero sí una wildcard válida (ceros seguidos de unos), se interpreta como wildcard, así que `0.0.15.255` también significa /20.

El tipo de dirección sale de los registros de uso especial de la IANA: rangos privados RFC 1918 (10/8, 172.16/12, 192.168/16), espacio compartido para NAT de operador (100.64/10, RFC 6598), loopback (127/8), link-local (169.254/16), los tres rangos de documentación, multicast (224/4) y espacio reservado.

### IPv6

Las direcciones IPv6 son números de 128 bits que se manejan como `BigInt` de JavaScript para no perder precisión. El analizador acepta la forma completa, la compresión `::` (una sola vez por dirección) y una cola IPv4 como `::ffff:192.0.2.1`. La salida sigue la **RFC 5952**, la forma de texto canónica: hexadecimal en minúsculas, sin ceros a la izquierda en cada grupo y la secuencia más larga de dos o más grupos a cero sustituida por `::` (la de más a la izquierda si dos tienen la misma longitud). Un solo grupo a cero nunca se comprime.

Para un prefijo, la primera dirección es la dirección AND la máscara, la última pone a uno todos los bits de host y el tamaño es 2^(128 − prefijo). IPv6 no tiene broadcast, así que no hay "menos dos".

### Dividir un bloque

*En subredes iguales* añade ⌈log₂ n⌉ bits al prefijo y lista todas las subredes resultantes (hasta 1.024 filas). *VLSM* calcula para cada número de hosts el prefijo más pequeño que lo contiene, ordena las peticiones de mayor a menor y asigna cada una en la siguiente dirección alineada con su tamaño. Si una petición no cabe en lo que queda, recibes un error que la nombra en lugar de un plan con solapamientos.

## Casos de uso

- **Diseñar un plan de direccionamiento.** Divide una /22 para una oficina nueva en VLAN de usuarios, voz, impresoras y gestión según la plantilla y pega la tabla en tu documentación.
- **Escribir reglas de firewall y ACL.** Obtén la red/prefijo o la wildcard exacta para un grupo de objetos y comprueba que una /20 cubre de verdad el rango que crees.
- **Resolución de problemas.** Dos hosts no se comunican: introduce las dos direcciones con su máscara y comprueba si están realmente en la misma subred.
- **Redes en la nube.** Planifica los CIDR de VPC y subredes sin solapamientos, recordando que los proveedores reservan algunas direcciones por subred además de red y broadcast.
- **Estudio y exámenes.** Comprueba ejercicios de subnetting para CCNA, Network+ o entrevistas; la vista binaria muestra por qué el resultado es el que es.
