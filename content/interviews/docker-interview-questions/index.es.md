---
title: "Las 20 Preguntas Más Frecuentes en Entrevistas sobre Docker y Respuestas (Edición 2026)"
description: "Domina tu entrevista de Senior DevOps con estas 20 preguntas avanzadas sobre Docker que cubren contenedores, imágenes, redes, volúmenes, Docker Compose y mejores prácticas de producción."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["preguntas entrevista docker", "entrevista senior devops", "preguntas contenedorización", "respuestas entrevista docker", "entrevista docker compose", "mejores prácticas dockerfile", "entrevista orquestación contenedores", "preguntas redes docker", "entrevista ingeniero devops", "preguntas docker producción"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Las 20 Preguntas Más Frecuentes en Entrevistas sobre Docker y Respuestas (Edición 2026)",
    "description": "Preguntas avanzadas de entrevistas sobre Docker para roles Senior DevOps que cubren contenedores, imágenes, redes y mejores prácticas de producción.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "es"
  }
---

## Inicialización del Sistema

Docker se ha convertido en una habilidad innegociable para cualquier rol de DevOps, SRE o ingeniería backend. Los entrevistadores a nivel senior esperan que vayas más allá de `docker run` — quieren ver que comprendes la estratificación de imágenes, los aspectos internos de las redes, el endurecimiento de seguridad y los patrones de orquestación para producción. Esta guía contiene las 20 preguntas más frecuentes en entrevistas de nivel Senior y Lead, con respuestas detalladas que demuestran profundidad.

**¿Necesitas un repaso rápido de comandos antes de tu entrevista?** Guarda en favoritos nuestro [Cheatsheet Docker Captain's Log](/cheatsheets/docker-container-commands/).

---

## Conceptos Fundamentales

<details>
<summary><strong>1. ¿Cuál es la diferencia entre un contenedor y una máquina virtual?</strong></summary>
<br>

Una **máquina virtual** ejecuta un sistema operativo invitado completo sobre un hipervisor, incluyendo su propio kernel, controladores y bibliotecas del sistema. Cada VM está completamente aislada pero consume recursos significativos (GBs de RAM, minutos para arrancar).

Un **contenedor** comparte el kernel del sistema operativo del host y aísla los procesos usando namespaces de Linux y cgroups. Empaqueta solo la aplicación y sus dependencias — sin kernel separado. Esto hace que los contenedores sean ligeros (MBs), rápidos de iniciar (milisegundos) y altamente portables.

Diferencia clave: Las VMs virtualizan el **hardware**, los contenedores virtualizan el **sistema operativo**.
</details>

<details>
<summary><strong>2. ¿Qué son las capas de imágenes Docker y cómo funcionan?</strong></summary>
<br>

Una imagen Docker se construye a partir de una serie de **capas de solo lectura**. Cada instrucción en un Dockerfile (`FROM`, `RUN`, `COPY`, etc.) crea una nueva capa. Las capas se apilan una sobre otra usando un sistema de archivos de unión (como OverlayFS).

Cuando un contenedor se ejecuta, Docker agrega una delgada **capa escribible** en la parte superior (la capa del contenedor). Los cambios realizados en tiempo de ejecución solo afectan esta capa escribible — las capas subyacentes de la imagen permanecen sin cambios.

Esta arquitectura permite:
- **Caché**: Si una capa no ha cambiado, Docker la reutiliza de la caché durante las construcciones.
- **Compartición**: Múltiples contenedores de la misma imagen comparten las capas de solo lectura, ahorrando espacio en disco.
- **Eficiencia**: Solo las capas modificadas necesitan ser descargadas o enviadas a los registros.
</details>

<details>
<summary><strong>3. ¿Cuál es la diferencia entre CMD y ENTRYPOINT en un Dockerfile?</strong></summary>
<br>

Ambos definen qué se ejecuta cuando un contenedor se inicia, pero se comportan de manera diferente:

- **CMD** proporciona argumentos predeterminados que pueden ser completamente sobrescritos en tiempo de ejecución. Si ejecutas `docker run myimage /bin/bash`, el CMD se reemplaza.
- **ENTRYPOINT** define el ejecutable principal que siempre se ejecuta. Los argumentos en tiempo de ejecución se agregan a él, no lo reemplazan.

Mejor práctica: Usa `ENTRYPOINT` para el proceso principal y `CMD` para los argumentos predeterminados:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

Ejecutar `docker run myimage --port 3000` ejecutará `python app.py --port 3000`.
</details>

<details>
<summary><strong>4. ¿Qué es una construcción multi-stage y por qué es importante?</strong></summary>
<br>

Una construcción multi-stage usa múltiples instrucciones `FROM` en un solo Dockerfile. Cada `FROM` inicia una nueva etapa de construcción, y puedes copiar selectivamente artefactos de una etapa a otra.

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

Esto produce una imagen final que contiene solo el binario compilado — sin herramientas de construcción, sin código fuente, sin archivos intermedios. El resultado es una imagen dramáticamente más pequeña (a menudo 10-100 veces más pequeña) con una superficie de ataque reducida.
</details>

<details>
<summary><strong>5. ¿Cuál es la diferencia entre COPY y ADD en un Dockerfile?</strong></summary>
<br>

Ambos copian archivos del contexto de construcción a la imagen, pero `ADD` tiene funcionalidades extra:
- `ADD` puede extraer automáticamente archivos `.tar` locales.
- `ADD` puede descargar archivos desde URLs.

Sin embargo, las mejores prácticas de Docker recomiendan usar `COPY` en casi todos los casos porque es explícito y predecible. Usa `ADD` solo cuando necesites específicamente la extracción de tar. Nunca uses `ADD` para descargar archivos — usa `RUN curl` o `RUN wget` en su lugar, para que la capa de descarga pueda ser cacheada correctamente.
</details>

## Redes

<details>
<summary><strong>6. Explica los modos de red de Docker (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (predeterminado): Crea una red interna privada en el host. Los contenedores en el mismo bridge pueden comunicarse por IP o nombre del contenedor. El tráfico hacia el exterior requiere mapeo de puertos (`-p`).
- **Host**: Elimina el aislamiento de red. El contenedor comparte directamente la pila de red del host. No se necesita mapeo de puertos, pero tampoco hay aislamiento. Útil para aplicaciones con requisitos críticos de rendimiento.
- **None**: Sin red en absoluto. El contenedor solo tiene una interfaz loopback. Usado para trabajos por lotes o cargas de trabajo sensibles a la seguridad.
- **Overlay**: Abarca múltiples hosts Docker (usado en Swarm/Kubernetes). Los contenedores en diferentes máquinas pueden comunicarse como si estuvieran en la misma red, usando tunneling VXLAN.
</details>

<details>
<summary><strong>7. ¿Cómo funciona la comunicación entre contenedores?</strong></summary>
<br>

En una red bridge definida por el usuario, los contenedores pueden alcanzarse **por nombre del contenedor** mediante el resolver DNS integrado de Docker. El servidor DNS se ejecuta en `127.0.0.11` dentro de cada contenedor.

En la red bridge predeterminada, la resolución DNS **no** está disponible — los contenedores solo pueden comunicarse por dirección IP, lo cual no es confiable ya que las IPs se asignan dinámicamente.

Mejor práctica: Siempre crea una red bridge personalizada (`docker network create mynet`) y conecta los contenedores a ella. Nunca dependas del bridge predeterminado para la comunicación entre contenedores.
</details>

<details>
<summary><strong>8. ¿Cuál es la diferencia entre EXPOSE y publicar un puerto?</strong></summary>
<br>

`EXPOSE` en un Dockerfile es puramente **documentación** — le dice a cualquiera que lea el Dockerfile que la aplicación escucha en un puerto específico. NO abre ni mapea realmente el puerto.

Publicar un puerto (`-p 8080:80`) realmente crea una regla de red que mapea un puerto del host a un puerto del contenedor, haciendo el servicio accesible desde fuera del contenedor.

Puedes publicar puertos que no están en la directiva `EXPOSE`, y `EXPOSE` solo no hace nada sin `-p`.
</details>

## Volúmenes y Almacenamiento

<details>
<summary><strong>9. ¿Cuáles son los tres tipos de montajes en Docker?</strong></summary>
<br>

1. **Volúmenes** (`docker volume create`): Gestionados por Docker, almacenados en `/var/lib/docker/volumes/`. Ideales para datos persistentes (bases de datos). Sobreviven a la eliminación del contenedor. Portables entre hosts.
2. **Bind mounts** (`-v /host/path:/container/path`): Mapean un directorio específico del host en el contenedor. La ruta del host debe existir. Ideales para desarrollo (recarga de código en vivo). No portables.
3. **Montajes tmpfs** (`--tmpfs /tmp`): Almacenados solo en la memoria del host. Nunca se escriben en disco. Ideales para datos sensibles que no deben persistir (secretos, tokens de sesión).
</details>

<details>
<summary><strong>10. ¿Cómo se persisten los datos de un contenedor de base de datos?</strong></summary>
<br>

Usa un **volumen con nombre** montado en el directorio de datos de la base de datos:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

Los datos sobreviven a reinicios y eliminaciones del contenedor. Al actualizar la versión de la base de datos, detén el contenedor antiguo, inicia uno nuevo con el mismo volumen y deja que la nueva versión maneje la migración de datos.

Nunca uses bind mounts para bases de datos en producción — los volúmenes tienen mejor rendimiento de E/S y son gestionados por el driver de almacenamiento de Docker.
</details>

## Seguridad

<details>
<summary><strong>11. ¿Cómo se asegura un contenedor Docker en producción?</strong></summary>
<br>

Prácticas clave de endurecimiento:
- **Ejecutar como no-root**: Usa la directiva `USER` en el Dockerfile. Nunca ejecutes procesos de aplicación como root.
- **Usar imágenes base mínimas**: `alpine`, `distroless` o `scratch` en lugar de `ubuntu`.
- **Eliminar capabilities**: Usa `--cap-drop ALL --cap-add <solo-necesarias>`.
- **Sistema de archivos de solo lectura**: Usa `--read-only` y monta solo rutas específicas escribibles.
- **Sin nuevos privilegios**: Usa `--security-opt=no-new-privileges`.
- **Escanear imágenes**: Usa `docker scout`, Trivy o Snyk para detectar vulnerabilidades en imágenes base y dependencias.
- **Firmar imágenes**: Usa Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) para verificar la autenticidad de las imágenes.
- **Limitar recursos**: Usa `--memory`, `--cpus` para prevenir el agotamiento de recursos.
</details>

<details>
<summary><strong>12. ¿Qué es el modo rootless de Docker?</strong></summary>
<br>

El modo rootless de Docker ejecuta el daemon Docker y los contenedores completamente dentro de un namespace de usuario, sin requerir privilegios root en el host. Esto elimina la principal preocupación de seguridad con Docker: que el daemon se ejecuta como root, y una fuga del contenedor significa acceso root al host.

En modo rootless, incluso si un atacante escapa del contenedor, solo obtiene los privilegios del usuario sin privilegios que ejecuta Docker. La contrapartida es que algunas funcionalidades (como vincular a puertos por debajo del 1024) requieren configuración adicional.
</details>

## Docker Compose y Orquestación

<details>
<summary><strong>13. ¿Cuál es la diferencia entre docker-compose up y docker-compose run?</strong></summary>
<br>

- `docker compose up`: Inicia **todos** los servicios definidos en `docker-compose.yml`, crea redes/volúmenes y respeta el orden de `depends_on`. Típicamente usado para levantar todo el stack.
- `docker compose run <servicio> <comando>`: Inicia un **único** servicio con un comando puntual. No inicia servicios dependientes por defecto (usa `--service-ports` para mapear puertos, `--rm` para limpiar). Usado para ejecutar migraciones, pruebas o tareas administrativas.
</details>

<details>
<summary><strong>14. ¿Cómo funciona depends_on y cuáles son sus limitaciones?</strong></summary>
<br>

`depends_on` controla el **orden de inicio** — asegura que el servicio A arranque antes que el servicio B. Sin embargo, solo espera a que el contenedor se **inicie**, no a que la aplicación dentro esté **lista**.

Por ejemplo, un contenedor de base de datos podría iniciarse en segundos, pero PostgreSQL necesita tiempo adicional para inicializarse. Tu contenedor de la aplicación se iniciará e inmediatamente fallará al intentar conectarse.

Solución: Usa `depends_on` con una `condition` y health check:

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. ¿Cuándo elegirías Docker Swarm en lugar de Kubernetes?</strong></summary>
<br>

**Docker Swarm**: Integrado en Docker, sin configuración adicional. Ideal para despliegues pequeños a medianos donde la simplicidad importa. Usa los mismos archivos Docker Compose. Ecosistema y comunidad limitados comparados con Kubernetes. Adecuado para equipos que no tienen ingenieros de plataforma dedicados.

**Kubernetes**: Estándar de la industria para la orquestación de contenedores a escala. Soporta auto-escalado, actualizaciones rolling, service mesh, custom resource definitions y un ecosistema masivo (Helm, Istio, ArgoCD). Mayor complejidad y curva de aprendizaje. Necesario para despliegues a gran escala, multi-equipo y multi-cloud.

Regla general: Si tienes menos de 20 servicios y un equipo pequeño, Swarm es suficiente. Más allá de eso, Kubernetes vale la inversión.
</details>

## Producción y Resolución de Problemas

<details>
<summary><strong>16. ¿Cómo se reduce el tamaño de una imagen Docker?</strong></summary>
<br>

1. **Usa construcciones multi-stage** — mantén las herramientas de construcción fuera de la imagen final.
2. **Usa imágenes base mínimas** — `alpine` (~5MB) en lugar de `ubuntu` (~75MB).
3. **Combina comandos RUN** — cada `RUN` crea una capa. Encadena comandos con `&&` y limpia en la misma capa.
4. **Usa .dockerignore** — excluye `node_modules`, `.git`, archivos de prueba, documentación del contexto de construcción.
5. **Ordena las capas por frecuencia de cambio** — pon las capas que cambian raramente (dependencias) antes de las capas que cambian frecuentemente (código fuente) para maximizar los aciertos de caché.
</details>

<details>
<summary><strong>17. Un contenedor sigue reiniciándose. ¿Cómo lo depuras?</strong></summary>
<br>

Enfoque paso a paso:
1. `docker ps -a` — verifica el código de salida. Código 137 = terminado por OOM. Código 1 = error de la aplicación.
2. `docker logs <container>` — lee los registros de la aplicación en busca de trazas de pila o mensajes de error.
3. `docker inspect <container>` — verifica `State.OOMKilled`, límites de recursos y variables de entorno.
4. `docker run -it --entrypoint /bin/sh <image>` — inicia una shell interactiva para depurar el entorno manualmente.
5. `docker stats` — verifica si el contenedor está alcanzando los límites de memoria o CPU.
6. Verifica `docker events` — busca señales de kill o eventos OOM del daemon.
</details>

<details>
<summary><strong>18. ¿Cuál es la diferencia entre docker stop y docker kill?</strong></summary>
<br>

- `docker stop` envía **SIGTERM** al proceso principal (PID 1) y espera un período de gracia (predeterminado 10 segundos). Si el proceso no termina, Docker envía SIGKILL. Esto permite que la aplicación realice un apagado gradual (cerrar conexiones, vaciar buffers, guardar estado).
- `docker kill` envía **SIGKILL** inmediatamente. El proceso se termina sin ninguna oportunidad de limpieza. Usar solo cuando un contenedor no responde.

Mejor práctica: Siempre usa `docker stop` en producción. Asegúrate de que tu aplicación maneje SIGTERM correctamente.
</details>

<details>
<summary><strong>19. ¿Cómo se manejan los secretos en Docker?</strong></summary>
<br>

**Nunca** incorpores secretos en las imágenes (ENV en Dockerfile, COPY de archivos .env). Persisten en las capas de la imagen y son visibles con `docker history`.

Enfoques por nivel de madurez:
- **Básico**: Pasa secretos vía `--env-file` en tiempo de ejecución (archivo no incluido en la imagen).
- **Mejor**: Usa secretos de Docker Swarm o Kubernetes secrets (montados como archivos, no como variables de entorno).
- **Óptimo**: Usa un gestor de secretos externo (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) e inyecta secretos en tiempo de ejecución vía sidecar o init container.
</details>

<details>
<summary><strong>20. ¿Qué es un health check de Docker y por qué es crítico?</strong></summary>
<br>

Un health check es un comando que Docker ejecuta periódicamente dentro del contenedor para verificar que la aplicación realmente está funcionando — no solo que el proceso está en ejecución.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Sin un health check, Docker solo sabe si el proceso está vivo (el PID existe). Con un health check, Docker sabe si la aplicación está **saludable** (respondiendo a peticiones). Esto es crítico para:
- **Balanceadores de carga**: Enrutar tráfico solo a contenedores saludables.
- **Orquestadores**: Reiniciar contenedores no saludables automáticamente.
- **depends_on**: Esperar la disponibilidad real, no solo el inicio del proceso.
</details>
