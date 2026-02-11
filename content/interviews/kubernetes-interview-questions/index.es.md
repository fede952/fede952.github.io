---
title: "Kubernetes (K8s) Preparación para Entrevistas: Preguntas y Respuestas Nivel Senior"
description: "20 preguntas avanzadas de Kubernetes para entrevistas de DevOps y SRE Senior. Cubre arquitectura, ciclo de vida de pods, networking, almacenamiento, RBAC y troubleshooting en producción."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Preparación para Entrevistas: Preguntas y Respuestas Nivel Senior",
    "description": "20 preguntas avanzadas de Kubernetes sobre arquitectura, networking, almacenamiento, seguridad y troubleshooting en producción.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

Kubernetes es el sistema operativo de la nube — y la habilidad más demandada para roles de DevOps, SRE e Ingeniería de Plataforma. Las entrevistas de nivel senior van en profundidad: te preguntarán sobre los internos del control plane, modelos de networking, RBAC, gestión de recursos y cómo depurar incidentes en producción bajo presión. Esta guía contiene 20 preguntas que aparecen repetidamente en entrevistas de las principales empresas tecnológicas, con respuestas que demuestran la profundidad esperada a nivel Staff/Senior.

**¿Necesitas un repaso rápido de comandos?** Mantén abierto nuestro [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) durante tu preparación.

---

## Arquitectura

<details>
<summary><strong>1. Describe los componentes del control plane de Kubernetes y sus responsabilidades.</strong></summary>
<br>

El control plane gestiona el estado del clúster:

- **kube-apiserver**: La puerta de entrada al clúster. Cada comando `kubectl`, acción de controlador y decisión del scheduler pasa por el API server. Valida y persiste el estado en etcd.
- **etcd**: Un almacén clave-valor distribuido que contiene todo el estado del clúster (estado deseado, estado actual, configuraciones, secrets). Es la única fuente de verdad.
- **kube-scheduler**: Observa los pods recién creados sin nodo asignado y selecciona un nodo basándose en requisitos de recursos, reglas de afinidad, taints y restricciones.
- **kube-controller-manager**: Ejecuta bucles de controladores (controladores de Deployment, ReplicaSet, Node, Job) que reconcilian continuamente el estado deseado con el estado actual.
- **cloud-controller-manager**: Se integra con las APIs del proveedor cloud para LoadBalancers, aprovisionamiento de almacenamiento y ciclo de vida de nodos.
</details>

<details>
<summary><strong>2. ¿Qué sucede cuando ejecutas `kubectl apply -f deployment.yaml`?</strong></summary>
<br>

1. `kubectl` envía un HTTP POST/PATCH al **API server** con el manifiesto del Deployment.
2. El API server **valida** la solicitud (autenticación, autorización vía RBAC, admission controllers).
3. El API server escribe el objeto Deployment en **etcd**.
4. El **controlador de Deployment** detecta el nuevo Deployment y crea un **ReplicaSet**.
5. El **controlador de ReplicaSet** lo detecta y crea el número especificado de objetos **Pod**.
6. El **scheduler** detecta los pods no programados y asigna cada uno a un nodo basándose en la disponibilidad de recursos y restricciones.
7. El **kubelet** en cada nodo asignado detecta la asignación del pod, descarga la imagen del contenedor e inicia el contenedor a través del runtime de contenedores (containerd/CRI-O).
8. El **kube-proxy** en cada nodo actualiza las reglas iptables/IPVS si hay un Service asociado.
</details>

<details>
<summary><strong>3. ¿Cuál es la diferencia entre un Deployment, StatefulSet y DaemonSet?</strong></summary>
<br>

- **Deployment**: Gestiona aplicaciones sin estado. Los pods son intercambiables, pueden escalarse libremente y se crean/destruyen en cualquier orden. Ideal para servidores web, APIs, workers.
- **StatefulSet**: Gestiona aplicaciones con estado. Cada pod obtiene un **hostname estable** (`pod-0`, `pod-1`), **almacenamiento persistente** (PVC por pod) y los pods se crean/destruyen en **orden**. Ideal para bases de datos, Kafka, ZooKeeper.
- **DaemonSet**: Asegura **un pod por nodo**. Cuando un nuevo nodo se une al clúster, un pod se programa automáticamente en él. Ideal para recolectores de logs, agentes de monitoreo, plugins de red.
</details>

<details>
<summary><strong>4. Explica el ciclo de vida del pod y sus fases.</strong></summary>
<br>

Un pod pasa por estas fases:

1. **Pending**: El pod es aceptado pero aún no está programado o las imágenes se están descargando.
2. **Running**: Al menos un contenedor está en ejecución o iniciándose/reiniciándose.
3. **Succeeded**: Todos los contenedores salieron con código 0 (para Jobs/cargas de trabajo batch).
4. **Failed**: Todos los contenedores terminaron, al menos uno salió con un código distinto de cero.
5. **Unknown**: El nodo es inalcanzable, el estado del pod no se puede determinar.

Dentro de un pod en ejecución, los contenedores pueden estar en estados: **Waiting** (descargando imagen, init containers), **Running**, o **Terminated** (salió o se cayó).
</details>

## Networking

<details>
<summary><strong>5. Explica el modelo de networking de Kubernetes.</strong></summary>
<br>

El networking de Kubernetes sigue tres reglas fundamentales:

1. **Cada pod obtiene su propia dirección IP** — sin NAT entre pods.
2. **Todos los pods pueden comunicarse con todos los demás pods** entre nodos sin NAT.
3. **La IP que un pod ve de sí mismo** es la misma IP que otros usan para alcanzarlo.

Esto se implementa mediante plugins CNI (Container Network Interface) como Calico, Flannel, Cilium o Weave. Crean una red overlay o underlay que satisface estas reglas. Cada nodo obtiene una subred CIDR para pods y el plugin CNI maneja el enrutamiento entre nodos.
</details>

<details>
<summary><strong>6. ¿Cuál es la diferencia entre los servicios ClusterIP, NodePort y LoadBalancer?</strong></summary>
<br>

- **ClusterIP** (predeterminado): IP virtual solo interno. Accesible solo desde dentro del clúster. Usado para comunicación entre servicios.
- **NodePort**: Expone el servicio en un puerto estático (30000-32767) en la IP de cada nodo. El tráfico externo puede alcanzar `<NodeIP>:<NodePort>`. Se construye sobre ClusterIP.
- **LoadBalancer**: Aprovisiona un balanceador de carga externo a través del proveedor cloud. Obtiene una IP/DNS pública. Se construye sobre NodePort. Usado para servicios públicos en producción.

También existe **ExternalName**, que mapea un servicio a un CNAME DNS (sin proxying, solo resolución DNS).
</details>

<details>
<summary><strong>7. ¿Qué es un Ingress y cómo difiere de un Service?</strong></summary>
<br>

Un **Service** opera en la Capa 4 (TCP/UDP) — enruta tráfico a pods basándose en IP y puerto.

Un **Ingress** opera en la Capa 7 (HTTP/HTTPS) — enruta tráfico basándose en hostname y ruta URL. Un solo Ingress puede enrutar `api.example.com` al servicio API y `app.example.com` al servicio frontend, todo a través de un solo balanceador de carga.

Un Ingress requiere un **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB) para implementar realmente las reglas de enrutamiento. El recurso Ingress es solo una configuración — el controlador hace el trabajo.
</details>

<details>
<summary><strong>8. ¿Cómo funciona el DNS dentro de un clúster de Kubernetes?</strong></summary>
<br>

Kubernetes ejecuta **CoreDNS** (o kube-dns) como un complemento del clúster. Cada servicio obtiene un registro DNS:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Cuando un pod hace una consulta DNS para `my-service`, el resolver en `/etc/resolv.conf` (configurado por kubelet) añade los dominios de búsqueda y consulta a CoreDNS. CoreDNS observa el API server para cambios en Service/Endpoint y actualiza sus registros automáticamente.
</details>

## Almacenamiento

<details>
<summary><strong>9. Explica PersistentVolume (PV), PersistentVolumeClaim (PVC) y StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: Una pieza de almacenamiento aprovisionada por un administrador o dinámicamente por una StorageClass. Existe independientemente de cualquier pod. Tiene un ciclo de vida separado de los pods.
- **PersistentVolumeClaim (PVC)**: Una solicitud de almacenamiento por parte de un pod. Especifica tamaño, modo de acceso y opcionalmente una StorageClass. Kubernetes vincula el PVC a un PV coincidente.
- **StorageClass**: Define una clase de almacenamiento (SSD, HDD, NFS) y el aprovisionador que crea PVs dinámicamente. Permite el aprovisionamiento de almacenamiento bajo demanda — sin intervención del administrador necesaria.

Flujo: Pod referencia PVC → PVC solicita almacenamiento de StorageClass → StorageClass activa el aprovisionador → Aprovisionador crea PV → PVC se vincula a PV → Pod monta PV.
</details>

<details>
<summary><strong>10. ¿Qué son los modos de acceso y las políticas de recuperación?</strong></summary>
<br>

**Modos de Acceso**:
- **ReadWriteOnce (RWO)**: Montado en lectura/escritura por un solo nodo. Más común (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: Montado en solo lectura por muchos nodos. Usado para configuraciones compartidas.
- **ReadWriteMany (RWX)**: Montado en lectura/escritura por muchos nodos. Requiere almacenamiento en red (NFS, EFS, CephFS).

**Políticas de Recuperación** (qué sucede cuando se elimina el PVC):
- **Retain**: El PV se mantiene con sus datos. El administrador debe recuperarlo manualmente.
- **Delete**: El PV y el almacenamiento subyacente se eliminan. Predeterminado para aprovisionamiento dinámico.
- **Recycle** (obsoleto): `rm -rf` básico en el volumen. Usa Retain o Delete en su lugar.
</details>

## Seguridad y RBAC

<details>
<summary><strong>11. ¿Cómo funciona RBAC en Kubernetes?</strong></summary>
<br>

RBAC (Control de Acceso Basado en Roles) tiene cuatro objetos:

- **Role**: Define permisos (verbos: get, list, create, delete) sobre recursos (pods, servicios, secrets) dentro de un **solo namespace**.
- **ClusterRole**: Igual que Role pero a **nivel de clúster** (todos los namespaces, o recursos con alcance de clúster como nodos).
- **RoleBinding**: Vincula un Role a un usuario, grupo o cuenta de servicio dentro de un namespace.
- **ClusterRoleBinding**: Vincula un ClusterRole a un sujeto en todo el clúster.

Principio: Comienza con los permisos mínimos necesarios. Nunca vincules `cluster-admin` a cuentas de servicio de aplicaciones. Audita RBAC regularmente con `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. ¿Qué son los Pod Security Standards (PSS)?</strong></summary>
<br>

Los Pod Security Standards reemplazaron las PodSecurityPolicies (eliminadas en K8s 1.25). Definen tres niveles de seguridad:

- **Privileged**: Sin restricciones. Permite todo. Usado para pods a nivel de sistema (plugins CNI, drivers de almacenamiento).
- **Baseline**: Previene escalaciones de privilegios conocidas. Bloquea hostNetwork, hostPID, contenedores privilegiados, pero permite la mayoría de cargas de trabajo.
- **Restricted**: Seguridad máxima. Requiere non-root, eliminar todas las capabilities, sistema de archivos root en solo lectura, sin escalación de privilegios.

Aplicado mediante el controlador **Pod Security Admission** a nivel de namespace usando etiquetas:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. ¿Cómo se gestionan los secrets en Kubernetes de forma segura?</strong></summary>
<br>

Los secrets predeterminados de Kubernetes están **codificados en base64, no cifrados**. Cualquiera con acceso a la API puede decodificarlos.

Pasos de endurecimiento:
1. **Habilitar cifrado en reposo** en etcd (`EncryptionConfiguration` con AES-CBC o proveedor KMS).
2. **Usar gestores de secrets externos** (Vault, AWS Secrets Manager) con el External Secrets Operator o CSI Secrets Store Driver.
3. **RBAC**: Restringir `get`/`list` en secrets solo a las cuentas de servicio que los necesitan.
4. **Montar como archivos**, no como variables de entorno — las variables de entorno pueden filtrarse a través de logs, volcados de crash y `/proc`.
5. **Rotar secrets** regularmente y usar credenciales de corta duración donde sea posible.
</details>

## Scheduling y Recursos

<details>
<summary><strong>14. Explica las solicitudes y los límites de recursos.</strong></summary>
<br>

- **Solicitudes (Requests)**: La cantidad de CPU/memoria **garantizada** al contenedor. El scheduler usa las solicitudes para decidir qué nodo tiene suficiente capacidad.
- **Límites (Limits)**: La cantidad **máxima** que un contenedor puede usar. Si un contenedor excede su límite de memoria, es eliminado por OOM. Si excede el límite de CPU, es ralentizado.

Clases QoS basadas en solicitudes/límites:
- **Guaranteed**: Solicitudes == Límites para todos los contenedores. Mayor prioridad, último en ser desalojado.
- **Burstable**: Solicitudes < Límites. Prioridad media.
- **BestEffort**: Sin solicitudes ni límites establecidos. Primero en ser desalojado bajo presión.

Mejor práctica: Siempre establece solicitudes (para precisión del scheduling) y límites (para estabilidad del clúster).
</details>

<details>
<summary><strong>15. ¿Qué son los taints, tolerations y node affinity?</strong></summary>
<br>

- **Taints** se aplican a los nodos: "No programes pods aquí a menos que toleren este taint." Ejemplo: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Tolerations** se aplican a los pods: "Puedo tolerar este taint." Los pods con tolerations coincidentes pueden ser programados en nodos con taints.
- **Node Affinity** es una especificación del pod que dice "Prefiere o requiere la programación en nodos con etiquetas específicas." Ejemplo: requerir nodos con `disktype=ssd`.

Usar juntos: Aplicar taint a nodos GPU → solo pods con tolerations y afinidad GPU llegan allí. Previene que cargas de trabajo sin GPU desperdicien hardware costoso.
</details>

## Troubleshooting

<details>
<summary><strong>16. Un pod está atascado en CrashLoopBackOff. ¿Cómo lo depuras?</strong></summary>
<br>

`CrashLoopBackOff` significa que el contenedor sigue cayéndose y Kubernetes está esperando antes de reiniciarlo (retraso exponencial hasta 5 minutos).

Pasos de depuración:
1. `kubectl describe pod <name>` — verifica Events, Last State, Exit Code.
2. `kubectl logs <pod> --previous` — lee los logs de la instancia que se cayó.
3. Análisis del código de salida: 1 = error de aplicación, 137 = eliminado por OOM, 139 = segfault, 143 = SIGTERM.
4. Si el contenedor se cae demasiado rápido para los logs: `kubectl run debug --image=<image> --command -- sleep 3600` y ejecuta exec para inspeccionar el entorno.
5. Verifica si las sondas de readiness/liveness están mal configuradas (sonda apuntando a puerto/ruta incorrectos).
6. Verifica los límites de recursos — el contenedor puede ser eliminado por OOM antes de poder registrar algo.
</details>

<details>
<summary><strong>17. Un Service no está enrutando tráfico a los pods. ¿Qué verificas?</strong></summary>
<br>

1. **Las etiquetas coinciden**: El `spec.selector` del Service debe coincidir exactamente con las `metadata.labels` del pod.
2. **Existen Endpoints**: `kubectl get endpoints <service>` — si está vacío, el selector no coincide con ningún pod en ejecución.
3. **Los pods están Ready**: Solo los pods que pasan las sondas de readiness aparecen en los Endpoints. Verifica `kubectl get pods` para el estado Ready.
4. **Desajuste de puertos**: El `targetPort` del Service debe coincidir con el puerto en el que el contenedor está realmente escuchando.
5. **Network Policy**: Una NetworkPolicy podría estar bloqueando el ingreso a los pods.
6. **DNS**: Desde un pod de depuración, `nslookup <service-name>` para verificar que la resolución DNS funciona.
</details>

<details>
<summary><strong>18. ¿Cómo se realiza un despliegue sin tiempo de inactividad?</strong></summary>
<br>

1. **Estrategia de rolling update** (predeterminada): Establece `maxUnavailable: 0` y `maxSurge: 1` para asegurar que los pods antiguos solo se eliminen después de que los nuevos pods estén Ready.
2. **Sondas de readiness**: Sin una sonda de readiness, Kubernetes considera un pod Ready inmediatamente después del inicio — el tráfico lo alcanza antes de que la app esté inicializada.
3. **PreStop hook**: Añade un hook de ciclo de vida `preStop` con un sleep corto (5-10s) para permitir que las solicitudes en curso se completen antes de que el pod sea removido de los endpoints del Service.
4. **PodDisruptionBudget (PDB)**: Asegura que un número mínimo de pods esté siempre disponible durante interrupciones voluntarias (drenado de nodos, actualizaciones).
5. **Apagado graceful**: La aplicación debe manejar SIGTERM y finalizar las solicitudes activas antes de salir.
</details>

<details>
<summary><strong>19. ¿Qué es un Horizontal Pod Autoscaler y cómo funciona?</strong></summary>
<br>

El HPA escala automáticamente el número de réplicas de pods basándose en métricas observadas (CPU, memoria o métricas personalizadas).

Cómo funciona:
1. El HPA consulta el **Metrics Server** (o la API de métricas personalizadas) cada 15 segundos.
2. Calcula: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. Si las réplicas deseadas difieren de las actuales, actualiza el conteo de réplicas del Deployment.
4. Los períodos de enfriamiento previenen oscilaciones: estabilización de escalado hacia arriba (0s predeterminado), estabilización de escalado hacia abajo (300s predeterminado).

Requisitos: Metrics Server instalado, solicitudes de recursos definidas en contenedores (para métricas de CPU/memoria), límites mín/máx de réplicas configurados.
</details>

<details>
<summary><strong>20. ¿Cuál es la diferencia entre una sonda de liveness y una sonda de readiness?</strong></summary>
<br>

- **Sonda de liveness**: "¿Está vivo el contenedor?" Si falla, kubelet **mata y reinicia** el contenedor. Usada para detectar deadlocks o procesos congelados.
- **Sonda de readiness**: "¿Está el contenedor listo para servir tráfico?" Si falla, el pod es **removido de los endpoints del Service** (no se enruta tráfico hacia él), pero el contenedor NO se reinicia. Usada para períodos de calentamiento, verificaciones de dependencias, sobrecarga temporal.

También existe una **Sonda de startup**: Deshabilita las sondas de liveness/readiness hasta que la app haya iniciado. Útil para aplicaciones de inicio lento para prevenir eliminaciones prematuras.

Error común: Usar una sonda de liveness que verifica una dependencia downstream (base de datos). Si la base de datos se cae, todos los pods se reinician — empeorando la interrupción. La liveness solo debe verificar la aplicación en sí.
</details>
