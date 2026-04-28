---
title: "Entrevista Linux SysAdmin: Procesos, Permisos y Redes"
description: "20 preguntas esenciales de entrevista de administración de sistemas Linux para roles Senior SysAdmin y DevOps. Cubre permisos de archivos, gestión de procesos, systemd, redes y resolución de problemas."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Entrevista Linux SysAdmin: Procesos, Permisos y Redes",
    "description": "20 preguntas esenciales de entrevista de administración de sistemas Linux sobre permisos, procesos, systemd y redes.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

La administración de sistemas Linux es la base de la infraestructura moderna. Ya sea que estés entrevistando para un rol de SysAdmin, DevOps, SRE o Cloud Engineer, serás evaluado en tu capacidad para gestionar usuarios, solucionar problemas de procesos, configurar redes y asegurar servidores — todo desde la línea de comandos. Esta guía cubre 20 preguntas que separan a los candidatos senior de los junior, con respuestas que demuestran experiencia operativa real.

**¿Necesitas una referencia rápida de comandos?** Mantén abierto nuestro [Cheatsheet Linux SysAdmin](/cheatsheets/linux-sysadmin-permissions/) durante tu preparación.

---

## Permisos y Propiedad de Archivos

<details>
<summary><strong>1. Explica el modelo de permisos de Linux (rwx, notación octal, bits especiales).</strong></summary>
<br>

Cada archivo tiene tres niveles de permisos: **Propietario**, **Grupo**, **Otros**. Cada nivel puede tener **Lectura (r=4)**, **Escritura (w=2)**, **Ejecución (x=1)**.

La notación octal combina estos: `chmod 755` = rwxr-xr-x (propietario: todos los permisos, grupo/otros: lectura+ejecución).

**Bits especiales**:
- **SUID (4000)**: El archivo se ejecuta como el propietario del archivo, no como el usuario que lo ejecuta. Ejemplo: `/usr/bin/passwd` se ejecuta como root para que los usuarios puedan cambiar su propia contraseña.
- **SGID (2000)**: En archivos, se ejecuta como el grupo propietario. En directorios, los nuevos archivos heredan el grupo del directorio.
- **Sticky bit (1000)**: En directorios, solo el propietario del archivo puede eliminar sus archivos. Ejemplo clásico: `/tmp`.
</details>

<details>
<summary><strong>2. ¿Cuál es la diferencia entre enlaces duros y enlaces simbólicos?</strong></summary>
<br>

- **Enlace duro**: Una referencia directa al inodo (los datos reales en disco). Múltiples enlaces duros al mismo archivo comparten el mismo número de inodo. Eliminar un enlace duro no afecta a los demás — los datos persisten hasta que se eliminan todos los enlaces duros. No puede cruzar límites de sistema de archivos. No puede enlazar a directorios.
- **Enlace simbólico (symlink)**: Un puntero a una ruta de archivo (como un acceso directo). Tiene su propio inodo. Si el archivo de destino se elimina, el symlink se convierte en un enlace colgante. Puede cruzar sistemas de archivos. Puede enlazar a directorios.

Usa `ls -li` para ver los números de inodo y confirmar las relaciones entre enlaces duros.
</details>

<details>
<summary><strong>3. Un desarrollador no puede escribir en un directorio compartido. ¿Cómo diagnosticas y solucionas el problema?</strong></summary>
<br>

Pasos de diagnóstico:
1. `ls -la /shared/` — verifica propiedad y permisos.
2. `id developer` — verifica a qué grupos pertenece el usuario.
3. `getfacl /shared/` — verifica las ACLs que podrían anular los permisos estándar.

Soluciones comunes:
- Añade el usuario al grupo del directorio: `sudo usermod -aG devteam developer`.
- Establece SGID en el directorio para que los nuevos archivos hereden el grupo: `chmod g+s /shared/`.
- Si se necesitan ACLs: `setfacl -m u:developer:rwx /shared/`.
- Asegúrate de que el umask no esté bloqueando la escritura del grupo (verifica con el comando `umask`).
</details>

<details>
<summary><strong>4. ¿Qué es umask y cómo afecta la creación de archivos?</strong></summary>
<br>

`umask` define los permisos predeterminados **eliminados** de los nuevos archivos y directorios. Es una máscara de bits que se resta de los permisos máximos.

- Máximo predeterminado para archivos: 666 (sin ejecución por defecto).
- Máximo predeterminado para directorios: 777.
- Con `umask 022`: los archivos obtienen 644 (rw-r--r--), los directorios obtienen 755 (rwxr-xr-x).
- Con `umask 077`: los archivos obtienen 600 (rw-------), los directorios obtienen 700 (rwx------).

Se establece a nivel de sistema en `/etc/profile` o por usuario en `~/.bashrc`. Crítico para la seguridad — un umask permisivo puede exponer archivos sensibles a usuarios no autorizados.
</details>

## Gestión de Procesos

<details>
<summary><strong>5. Explica la diferencia entre un proceso, un hilo y un demonio.</strong></summary>
<br>

- **Proceso**: Una instancia de un programa en ejecución con su propio espacio de memoria, PID, descriptores de archivo y entorno. Creado por `fork()` o `exec()`.
- **Hilo**: Una unidad de ejecución ligera dentro de un proceso. Los hilos comparten el mismo espacio de memoria y descriptores de archivo pero tienen su propia pila y registros. Más rápidos de crear que los procesos.
- **Demonio**: Un proceso en segundo plano que se ejecuta sin un terminal de control. Típicamente iniciado en el arranque, se ejecuta continuamente y proporciona un servicio (sshd, nginx, cron). Convencionalmente nombrado con el sufijo `d`.
</details>

<details>
<summary><strong>6. ¿Qué son los procesos zombie y cómo los manejas?</strong></summary>
<br>

Un **zombie** es un proceso que ha terminado de ejecutarse pero todavía tiene una entrada en la tabla de procesos porque su padre no ha llamado a `wait()` para leer su estado de salida. No consume recursos excepto un espacio PID.

Identifica zombies: `ps aux | grep Z` — muestran estado `Z` (defunct).

**No puedes** matar un zombie — ya está muerto. Para eliminarlo:
1. Envía `SIGCHLD` al proceso padre: `kill -s SIGCHLD <parent_pid>`.
2. Si el padre lo ignora, matar el proceso padre dejará huérfano al zombie, que será adoptado por `init` (PID 1). Init automáticamente llama a `wait()` y lo limpia.

Un gran número de zombies generalmente indica un proceso padre defectuoso que no está recolectando sus hijos.
</details>

<details>
<summary><strong>7. Explica las señales de Linux. ¿Qué son SIGTERM, SIGKILL y SIGHUP?</strong></summary>
<br>

Las señales son interrupciones de software enviadas a los procesos:

- **SIGTERM (15)**: Solicitud de terminación cortés. El proceso puede capturarla, limpiar recursos y salir de forma ordenada. Esto es lo que `kill <pid>` envía por defecto.
- **SIGKILL (9)**: Terminación forzada. No puede ser capturada, bloqueada ni ignorada. El kernel termina el proceso inmediatamente. Usar solo como último recurso — no es posible ninguna limpieza.
- **SIGHUP (1)**: Históricamente "colgado". Muchos demonios (nginx, Apache) recargan su configuración cuando reciben SIGHUP, en lugar de reiniciarse.
- **SIGINT (2)**: Interrupción, enviada por Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)**: Pausar y reanudar un proceso.
</details>

<details>
<summary><strong>8. ¿Cómo encuentras y matas un proceso que consume demasiada CPU?</strong></summary>
<br>

1. Identifica el proceso: `top -o %CPU` o `ps aux --sort=-%cpu | head -10`.
2. Obtén detalles: `ls -l /proc/<pid>/exe` para ver el binario real.
3. Verifica qué está haciendo: `strace -p <pid>` para llamadas al sistema, `lsof -p <pid>` para archivos abiertos.
4. Parada ordenada: `kill <pid>` (SIGTERM) — permite la limpieza.
5. Parada forzada: `kill -9 <pid>` (SIGKILL) — solo si SIGTERM falla.
6. Prevenir recurrencia: Si es gestionado por systemd, establece `CPUQuota=50%` en el archivo unit del servicio.
</details>

## Systemd y Servicios

<details>
<summary><strong>9. ¿Qué es systemd y cómo se diferencia de SysVinit?</strong></summary>
<br>

**SysVinit**: Proceso de arranque secuencial usando scripts shell en `/etc/init.d/`. Los servicios se inician uno tras otro en un nivel de ejecución definido. Tiempos de arranque lentos. Simple pero con manejo limitado de dependencias.

**systemd**: Proceso de arranque paralelo usando archivos unit. Soporta dependencias, activación por socket, inicio de servicios bajo demanda, cgroups para control de recursos y journald para logging. Arranque mucho más rápido. Gestiona servicios, timers, montajes, sockets y targets.

systemd es el sistema init predeterminado en RHEL, Ubuntu, Debian, Fedora, SUSE y Arch.
</details>

<details>
<summary><strong>10. ¿Cómo creas un servicio systemd personalizado?</strong></summary>
<br>

Crea un archivo unit en `/etc/systemd/system/myapp.service`:

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

Luego: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Valores clave de `Type`: `simple` (predeterminado, el proceso principal se ejecuta en primer plano), `forking` (el proceso hace fork en segundo plano, necesita `PIDFile`), `oneshot` (se ejecuta una vez y termina), `notify` (el proceso señala preparación vía sd_notify).
</details>

<details>
<summary><strong>11. ¿Cómo analizas el rendimiento de arranque con systemd?</strong></summary>
<br>

- `systemd-analyze` — tiempo total de arranque.
- `systemd-analyze blame` — lista de servicios ordenados por tiempo de inicio.
- `systemd-analyze critical-chain` — árbol de la ruta crítica de arranque.
- `systemd-analyze plot > boot.svg` — genera una línea de tiempo visual de la secuencia de arranque.
- `journalctl -b -p err` — errores del arranque actual.

Para acelerar el arranque: deshabilita servicios innecesarios (`systemctl disable`), cambia servicios a activación por socket (inicio bajo demanda) e identifica servicios lentos desde la salida de blame.
</details>

## Redes

<details>
<summary><strong>12. Explica el three-way handshake de TCP.</strong></summary>
<br>

1. **SYN**: El cliente envía un paquete SYN al servidor con un número de secuencia inicial.
2. **SYN-ACK**: El servidor responde con SYN-ACK, reconociendo el SYN del cliente y enviando su propio número de secuencia.
3. **ACK**: El cliente envía un ACK confirmando el número de secuencia del servidor. La conexión está establecida.

La desconexión usa un handshake de cuatro vías: FIN → ACK → FIN → ACK (cada lado cierra independientemente su mitad de la conexión).

Depuración con: `ss -tuln` (puertos en escucha), `ss -tulnp` (con nombres de procesos), `tcpdump -i eth0 port 80` (captura de paquetes).
</details>

<details>
<summary><strong>13. ¿Cuál es la diferencia entre TCP y UDP?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol): Orientado a conexión, confiable, entrega ordenada. Usa handshake, acknowledgments, retransmisiones. Mayor overhead. Usado para HTTP, SSH, FTP, bases de datos.
- **UDP** (User Datagram Protocol): Sin conexión, no confiable, sin orden garantizado. Sin handshake, sin acknowledgments. Menor overhead, menor latencia. Usado para DNS, DHCP, VoIP, streaming, gaming.

Concepto clave: "No confiable" no significa malo — significa que la aplicación maneja la confiabilidad si es necesario. DNS usa UDP porque las consultas son pequeñas y rápidas; si una respuesta se pierde, el cliente simplemente la reenvía.
</details>

<details>
<summary><strong>14. Un servidor no puede alcanzar una IP externa. ¿Cómo haces la resolución de problemas?</strong></summary>
<br>

Enfoque capa por capa:
1. **L1 - Físico**: `ip link show` — ¿la interfaz está activa?
2. **L2 - Enlace de Datos**: `ip neighbor show` — ¿la tabla ARP está poblada?
3. **L3 - Red**: `ip route show` — ¿hay una puerta de enlace predeterminada? `ping <gateway>` — ¿puedes alcanzarla?
4. **L3 - Externo**: `ping 8.8.8.8` — ¿puedes alcanzar internet por IP?
5. **L7 - DNS**: `nslookup google.com` — ¿la resolución DNS funciona? Verifica `/etc/resolv.conf`.
6. **Firewall**: `iptables -L -n` o `nft list ruleset` — ¿las conexiones salientes están bloqueadas?
7. **Traza de ruta**: `traceroute 8.8.8.8` — ¿dónde se rompe la ruta?
</details>

## Almacenamiento y Sistemas de Archivos

<details>
<summary><strong>15. ¿Qué es un inodo?</strong></summary>
<br>

Un inodo es una estructura de datos que almacena metadatos sobre un archivo: permisos, propiedad, tamaño, marcas de tiempo y punteros a los bloques de datos en disco. Cada archivo y directorio tiene un inodo.

Crucialmente, el **nombre del archivo NO se almacena en el inodo** — se almacena en la entrada del directorio, que mapea un nombre a un número de inodo. Por esto funcionan los enlaces duros: múltiples entradas de directorio pueden apuntar al mismo inodo.

Quedarse sin inodos (incluso con espacio libre en disco) impide crear nuevos archivos. Verifica con `df -i`. Causa común: millones de archivos pequeños (colas de correo, directorios de caché).
</details>

<details>
<summary><strong>16. ¿Cómo extiendes un volumen lógico LVM sin tiempo de inactividad?</strong></summary>
<br>

1. Verifica el espacio disponible: `vgdisplay` — busca PE (physical extents) libres.
2. Si no hay espacio libre, añade un nuevo disco físico: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Extiende el volumen lógico: `lvextend -L +10G /dev/myvg/mylv`.
4. Redimensiona el sistema de archivos (en línea para ext4/XFS):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

Sin necesidad de desmontar. Sin tiempo de inactividad. Esta es una de las principales ventajas de LVM sobre las particiones sin formato.
</details>

## Seguridad y Hardening

<details>
<summary><strong>17. ¿Cuál es la diferencia entre su, sudo y sudoers?</strong></summary>
<br>

- **su** (switch user): Cambia completamente a otro usuario. `su -` carga el entorno del usuario de destino. Requiere la contraseña del usuario de destino.
- **sudo** (superuser do): Ejecuta un solo comando como otro usuario (generalmente root). Requiere la contraseña del **llamante**. Proporciona registro de auditoría de quién ejecutó qué.
- **sudoers** (`/etc/sudoers`): Archivo de configuración que define quién puede usar sudo y qué comandos pueden ejecutar. Se edita de forma segura con `visudo` (validación de sintaxis).

Mejor práctica: Deshabilita el inicio de sesión directo como root (`PermitRootLogin no` en sshd_config). Da acceso sudo a los administradores en su lugar — proporciona responsabilidad (registra quién hizo qué) y control granular.
</details>

<details>
<summary><strong>18. ¿Cómo haces el hardening de un servidor SSH?</strong></summary>
<br>

Cambios esenciales en `/etc/ssh/sshd_config`:
- `PermitRootLogin no` — prevenir inicio de sesión directo como root.
- `PasswordAuthentication no` — forzar autenticación basada en clave.
- `PubkeyAuthentication yes` — habilitar claves SSH.
- `Port 2222` — cambiar del puerto predeterminado (reduce escaneos automatizados).
- `MaxAuthTries 3` — limitar intentos de autenticación.
- `AllowUsers deploy admin` — lista blanca de usuarios específicos.
- `ClientAliveInterval 300` — desconectar sesiones inactivas.
- Instalar `fail2ban` — banear automáticamente IPs después de intentos fallidos de inicio de sesión.
</details>

## Scripting y Automatización

<details>
<summary><strong>19. ¿Cuál es la diferencia entre $?, $$, $! y $@ en Bash?</strong></summary>
<br>

- **$?** — Estado de salida del último comando (0 = éxito, distinto de cero = fallo).
- **$$** — PID de la shell actual.
- **$!** — PID del último proceso en segundo plano.
- **$@** — Todos los argumentos pasados al script (cada uno como una palabra separada).
- **$#** — Número de argumentos.
- **$0** — Nombre del script mismo.
- **$1, $2, ...** — Argumentos posicionales individuales.

Patrón común: `command && echo "success" || echo "fail"` usa `$?` implícitamente.
</details>

<details>
<summary><strong>20. Escribe un one-liner para encontrar todos los archivos mayores de 100MB modificados en los últimos 7 días.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Desglose:
- `find /` — busca desde la raíz.
- `-type f` — solo archivos (no directorios).
- `-size +100M` — mayores de 100 megabytes.
- `-mtime -7` — modificados en los últimos 7 días.
- `-exec ls -lh {} \;` — muestra el tamaño en formato legible para cada resultado.
- `2>/dev/null` — suprime errores de permiso denegado.

Alternativa con ordenamiento: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
