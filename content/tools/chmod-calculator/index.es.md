---
title: "Calculadora Chmod: Permisos Linux"
description: "Activa lectura, escritura y ejecución para propietario, grupo y otros y obtén el número chmod (755, 644…), la cadena rwx y el comando listo para copiar."
intro: "Pulsa los interruptores de permisos y obtén el número **chmod**, la cadena `rwxr-xr-x` que ves en `ls -l` y un comando listo para ejecutar. Los ajustes rápidos cubren los casos habituales: 755, 644, 600, 444 y el que conviene evitar, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["calculadora chmod", "chmod 755", "permisos de archivos linux", "chmod 644", "permisos octales", "permisos rwx", "permisos unix", "generador de comando chmod"]
tags: ["linux", "sysadmin", "permisos", "herramienta"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "Para cada clase (**Propietario**, **Grupo**, **Otros**) activa o desactiva **Lectura**, **Escritura** y **Ejecución**. El valor por defecto es 755."
  - "Lee el número octal tras `chmod` y la cadena simbólica de debajo, la misma notación que muestra `ls -l`."
  - "Escribe el nombre del archivo: los nombres con espacios o caracteres especiales de la shell se entrecomillan automáticamente en el comando copiado."
  - "O empieza con un **ajuste rápido**: 755 para scripts y directorios, 644 para archivos normales, 600 para claves privadas, 444 para archivos de solo lectura."
  - "Pulsa **Copiar comando** y pégalo en tu terminal."
faq:
  - q: "¿Qué significa chmod 755?"
    a: "7 para el propietario (lectura 4 + escritura 2 + ejecución 1), 5 para el grupo (lectura 4 + ejecución 1) y 5 para los demás. El propietario puede hacerlo todo; el resto puede leer y ejecutar, pero no modificar. Es el estándar para scripts, binarios y directorios."
  - q: "¿Qué diferencia hay entre 644 y 755?"
    a: "644 (`rw-r--r--`) no tiene bit de ejecución: adecuado para documentos, configuraciones y archivos web. 755 (`rwxr-xr-x`) añade ejecución para todos: necesario para scripts y programas, y para directorios, donde \"ejecutar\" significa poder entrar en ellos."
  - q: "¿Por qué es peligroso chmod 777?"
    a: "Permite a cualquier usuario del sistema modificar el archivo o el directorio. En un servidor compartido o en la raíz de una web, cualquier proceso comprometido puede sustituir tu código o dejar archivos. Si algo solo funciona con 777, la solución real suele ser el propietario o el grupo del archivo (`chown`), no ampliar permisos."
  - q: "¿Qué permisos debe tener una clave privada SSH?"
    a: "600 (`rw-------`): lectura y escritura solo para ti. OpenSSH se niega a usar una clave privada que otros puedan leer y muestra \"UNPROTECTED PRIVATE KEY FILE\". El directorio `~/.ssh` debería ser 700."
  - q: "¿Qué significa ejecución en un directorio?"
    a: "Es el permiso para atravesarlo: entrar con `cd` y acceder por nombre a los archivos de dentro. La lectura en un directorio permite listar los nombres; sin ejecución ves los nombres pero no puedes abrir los archivos. Por eso los directorios suelen ser 755 o 700."
  - q: "¿Admite setuid, setgid o el sticky bit?"
    a: "No. La calculadora cubre los nueve bits básicos, el modo de tres cifras que se usa en casi todos los comandos `chmod`. Los bits especiales son una cuarta cifra inicial (4 setuid, 2 setgid, 1 sticky, como en `chmod 1777 /tmp`); añádela a mano si la necesitas."
---

## Cómo funciona

Los permisos Unix son nueve bits en tres grupos de tres. Cada grupo responde a las mismas tres preguntas, lectura, escritura, ejecución, para una clase de usuarios: el **propietario** del archivo (`u`), su **grupo** (`g`) y todos los demás (`o`).

Cada permiso tiene un valor fijo, y una cifra es simplemente su suma:

| Permiso | Valor | Símbolo |
|---|---|---|
| Lectura | 4 | `r` |
| Escritura | 2 | `w` |
| Ejecución | 1 | `x` |

Así, 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` y 4 = `r--`. La calculadora suma los interruptores activos de cada clase, escribe las tres cifras juntas y vuelve a convertir cada cifra en `r`, `w`, `x` o `-` con una prueba de bits (`cifra & 4`, `& 2`, `& 1`). El `-` inicial de la cadena simbólica es el carácter de tipo de archivo que `ls -l` muestra para un archivo normal (`d` para un directorio).

Los ajustes rápidos hacen lo contrario: cada cifra de `644` se descompone en sus bits para fijar los nueve interruptores.

El comando copiado es `chmod <octal> <archivo>`. Si el nombre contiene algo distinto de letras, cifras y `._/@%+=:,-`, se envuelve en comillas simples (`'mi archivo.sh'`), escapando al estilo POSIX las comillas internas, para que el comando se pueda pegar sin riesgos en bash o zsh.

### Modos habituales

| Modo | Simbólico | Uso típico |
|---|---|---|
| 755 | `rwxr-xr-x` | Scripts, binarios, directorios |
| 644 | `rw-r--r--` | Archivos normales, configuraciones, recursos web |
| 700 | `rwx------` | Directorios privados como `~/.ssh` |
| 600 | `rw-------` | Claves privadas, archivos `.env`, credenciales |
| 444 | `r--r--r--` | Archivos que nadie debe modificar |
| 777 | `rwxrwxrwx` | Casi nunca: cualquiera puede cambiarlo |

## Casos de uso

- **"Permission denied" al ejecutar un script.** Añade el bit de ejecución: `chmod 755 deploy.sh`, o `chmod u+x` si solo lo ejecutas tú.
- **Proteger secretos.** Pon a 600 los archivos `.env`, los de claves de API y las claves SSH para que otros usuarios de la máquina no puedan leerlos.
- **Servidores web.** Las configuraciones típicas usan 644 para archivos y 755 para directorios, propiedad del usuario de despliegue y legibles por el servidor web.
- **Docker y CI.** Los archivos copiados en imágenes o descargados por la CI a veces pierden el bit de ejecución; la calculadora te da la línea `RUN chmod` exacta.
- **Aprender la notación.** Traduce entre la salida de `ls -l` y los números octales hasta que leer `drwxr-x---` sea automático.
