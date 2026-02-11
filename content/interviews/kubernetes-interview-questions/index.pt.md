---
title: "Kubernetes (K8s) Preparação para Entrevistas: Perguntas e Respostas Nível Sênior"
description: "20 perguntas avançadas de Kubernetes para entrevistas de DevOps e SRE Sênior. Cobre arquitetura, ciclo de vida de pods, rede, armazenamento, RBAC e troubleshooting em produção."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Preparação para Entrevistas: Perguntas e Respostas Nível Sênior",
    "description": "20 perguntas avançadas de Kubernetes sobre arquitetura, rede, armazenamento, segurança e troubleshooting em produção.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

Kubernetes é o sistema operacional da nuvem — e a habilidade mais demandada para funções de DevOps, SRE e Engenharia de Plataforma. Entrevistas de nível sênior são profundas: você será questionado sobre os internos do control plane, modelos de rede, RBAC, gerenciamento de recursos e como depurar incidentes em produção sob pressão. Este guia contém 20 perguntas que aparecem repetidamente em entrevistas nas principais empresas de tecnologia, com respostas que demonstram a profundidade esperada no nível Staff/Sênior.

**Precisa de uma revisão rápida de comandos?** Mantenha nosso [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) aberto durante sua preparação.

---

## Arquitetura

<details>
<summary><strong>1. Descreva os componentes do control plane do Kubernetes e suas responsabilidades.</strong></summary>
<br>

O control plane gerencia o estado do cluster:

- **kube-apiserver**: A porta de entrada para o cluster. Cada comando `kubectl`, ação de controller e decisão do scheduler passa pelo API server. Ele valida e persiste o estado no etcd.
- **etcd**: Um armazenamento chave-valor distribuído que contém todo o estado do cluster (estado desejado, estado atual, configurações, secrets). É a única fonte da verdade.
- **kube-scheduler**: Observa pods recém-criados sem nó atribuído e seleciona um nó com base em requisitos de recursos, regras de afinidade, taints e restrições.
- **kube-controller-manager**: Executa loops de controllers (controllers de Deployment, ReplicaSet, Node, Job) que reconciliam continuamente o estado desejado com o estado atual.
- **cloud-controller-manager**: Integra-se com APIs do provedor cloud para LoadBalancers, provisionamento de armazenamento e ciclo de vida de nós.
</details>

<details>
<summary><strong>2. O que acontece quando você executa `kubectl apply -f deployment.yaml`?</strong></summary>
<br>

1. `kubectl` envia um HTTP POST/PATCH para o **API server** com o manifesto do Deployment.
2. O API server **valida** a requisição (autenticação, autorização via RBAC, admission controllers).
3. O API server escreve o objeto Deployment no **etcd**.
4. O **controller de Deployment** detecta o novo Deployment e cria um **ReplicaSet**.
5. O **controller de ReplicaSet** detecta e cria o número especificado de objetos **Pod**.
6. O **scheduler** detecta pods não agendados e atribui cada um a um nó com base na disponibilidade de recursos e restrições.
7. O **kubelet** em cada nó atribuído detecta a atribuição do pod, baixa a imagem do contêiner e inicia o contêiner via o runtime de contêineres (containerd/CRI-O).
8. O **kube-proxy** em cada nó atualiza as regras iptables/IPVS se um Service estiver associado.
</details>

<details>
<summary><strong>3. Qual é a diferença entre Deployment, StatefulSet e DaemonSet?</strong></summary>
<br>

- **Deployment**: Gerencia aplicações sem estado. Os pods são intercambiáveis, podem ser escalados livremente e são criados/destruídos em qualquer ordem. Melhor para servidores web, APIs, workers.
- **StatefulSet**: Gerencia aplicações com estado. Cada pod recebe um **hostname estável** (`pod-0`, `pod-1`), **armazenamento persistente** (PVC por pod) e os pods são criados/destruídos em **ordem**. Melhor para bancos de dados, Kafka, ZooKeeper.
- **DaemonSet**: Garante **um pod por nó**. Quando um novo nó entra no cluster, um pod é automaticamente agendado nele. Melhor para coletores de logs, agentes de monitoramento, plugins de rede.
</details>

<details>
<summary><strong>4. Explique o ciclo de vida do pod e suas fases.</strong></summary>
<br>

Um pod passa por estas fases:

1. **Pending**: O pod é aceito mas ainda não agendado ou as imagens estão sendo baixadas.
2. **Running**: Pelo menos um contêiner está em execução ou iniciando/reiniciando.
3. **Succeeded**: Todos os contêineres saíram com código 0 (para Jobs/cargas de trabalho batch).
4. **Failed**: Todos os contêineres terminaram, pelo menos um saiu com um código diferente de zero.
5. **Unknown**: O nó está inacessível, o estado do pod não pode ser determinado.

Dentro de um pod em execução, os contêineres podem estar nos estados: **Waiting** (baixando imagem, init containers), **Running**, ou **Terminated** (saiu ou crashou).
</details>

## Rede

<details>
<summary><strong>5. Explique o modelo de rede do Kubernetes.</strong></summary>
<br>

A rede do Kubernetes segue três regras fundamentais:

1. **Cada pod recebe seu próprio endereço IP** — sem NAT entre pods.
2. **Todos os pods podem se comunicar com todos os outros pods** entre nós sem NAT.
3. **O IP que um pod vê para si mesmo** é o mesmo IP que outros usam para alcançá-lo.

Isso é implementado por plugins CNI (Container Network Interface) como Calico, Flannel, Cilium ou Weave. Eles criam uma rede overlay ou underlay que satisfaz essas regras. Cada nó recebe uma sub-rede CIDR para pods e o plugin CNI gerencia o roteamento entre nós.
</details>

<details>
<summary><strong>6. Qual é a diferença entre os serviços ClusterIP, NodePort e LoadBalancer?</strong></summary>
<br>

- **ClusterIP** (padrão): IP virtual apenas interno. Acessível somente de dentro do cluster. Usado para comunicação entre serviços.
- **NodePort**: Expõe o serviço em uma porta estática (30000-32767) no IP de cada nó. Tráfego externo pode alcançar `<NodeIP>:<NodePort>`. Construído sobre ClusterIP.
- **LoadBalancer**: Provisiona um balanceador de carga externo via provedor cloud. Recebe um IP/DNS público. Construído sobre NodePort. Usado para serviços públicos em produção.

Também existe **ExternalName**, que mapeia um serviço para um CNAME DNS (sem proxying, apenas resolução DNS).
</details>

<details>
<summary><strong>7. O que é um Ingress e como difere de um Service?</strong></summary>
<br>

Um **Service** opera na Camada 4 (TCP/UDP) — roteia tráfego para pods com base em IP e porta.

Um **Ingress** opera na Camada 7 (HTTP/HTTPS) — roteia tráfego com base em hostname e caminho URL. Um único Ingress pode rotear `api.example.com` para o serviço API e `app.example.com` para o serviço frontend, tudo através de um único balanceador de carga.

Um Ingress requer um **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB) para realmente implementar as regras de roteamento. O recurso Ingress é apenas uma configuração — o controller faz o trabalho.
</details>

<details>
<summary><strong>8. Como o DNS funciona dentro de um cluster Kubernetes?</strong></summary>
<br>

Kubernetes executa **CoreDNS** (ou kube-dns) como um add-on do cluster. Cada serviço recebe um registro DNS:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Quando um pod faz uma consulta DNS para `my-service`, o resolver em `/etc/resolv.conf` (configurado pelo kubelet) adiciona os domínios de busca e consulta o CoreDNS. O CoreDNS observa o API server para mudanças em Service/Endpoint e atualiza seus registros automaticamente.
</details>

## Armazenamento

<details>
<summary><strong>9. Explique PersistentVolume (PV), PersistentVolumeClaim (PVC) e StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: Uma porção de armazenamento provisionada por um administrador ou dinamicamente por uma StorageClass. Existe independentemente de qualquer pod. Tem um ciclo de vida separado dos pods.
- **PersistentVolumeClaim (PVC)**: Uma solicitação de armazenamento por um pod. Especifica tamanho, modo de acesso e opcionalmente uma StorageClass. Kubernetes vincula o PVC a um PV correspondente.
- **StorageClass**: Define uma classe de armazenamento (SSD, HDD, NFS) e o provisionador que cria PVs dinamicamente. Permite provisionamento de armazenamento sob demanda — sem necessidade de intervenção do administrador.

Fluxo: Pod referencia PVC → PVC solicita armazenamento da StorageClass → StorageClass aciona o provisionador → Provisionador cria PV → PVC se vincula ao PV → Pod monta o PV.
</details>

<details>
<summary><strong>10. O que são modos de acesso e políticas de recuperação?</strong></summary>
<br>

**Modos de Acesso**:
- **ReadWriteOnce (RWO)**: Montado em leitura/escrita por um único nó. Mais comum (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: Montado em somente leitura por muitos nós. Usado para configurações compartilhadas.
- **ReadWriteMany (RWX)**: Montado em leitura/escrita por muitos nós. Requer armazenamento em rede (NFS, EFS, CephFS).

**Políticas de Recuperação** (o que acontece quando o PVC é excluído):
- **Retain**: O PV é mantido com seus dados. O administrador deve recuperá-lo manualmente.
- **Delete**: PV e armazenamento subjacente são excluídos. Padrão para provisionamento dinâmico.
- **Recycle** (obsoleto): `rm -rf` básico no volume. Use Retain ou Delete em seu lugar.
</details>

## Segurança e RBAC

<details>
<summary><strong>11. Como o RBAC funciona no Kubernetes?</strong></summary>
<br>

RBAC (Controle de Acesso Baseado em Funções) tem quatro objetos:

- **Role**: Define permissões (verbos: get, list, create, delete) em recursos (pods, serviços, secrets) dentro de um **único namespace**.
- **ClusterRole**: Igual ao Role, mas em **nível de cluster** (todos os namespaces, ou recursos com escopo de cluster como nós).
- **RoleBinding**: Vincula um Role a um usuário, grupo ou conta de serviço dentro de um namespace.
- **ClusterRoleBinding**: Vincula um ClusterRole a um sujeito em todo o cluster.

Princípio: Comece com as permissões mínimas necessárias. Nunca vincule `cluster-admin` a contas de serviço de aplicações. Audite RBAC regularmente com `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. O que são Pod Security Standards (PSS)?</strong></summary>
<br>

Os Pod Security Standards substituíram as PodSecurityPolicies (removidas no K8s 1.25). Eles definem três níveis de segurança:

- **Privileged**: Sem restrições. Permite tudo. Usado para pods de nível de sistema (plugins CNI, drivers de armazenamento).
- **Baseline**: Previne escalações de privilégio conhecidas. Bloqueia hostNetwork, hostPID, contêineres privilegiados, mas permite a maioria das cargas de trabalho.
- **Restricted**: Segurança máxima. Requer non-root, remover todas as capabilities, sistema de arquivos root somente leitura, sem escalação de privilégio.

Aplicado via controller **Pod Security Admission** no nível do namespace usando labels:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Como gerenciar secrets no Kubernetes de forma segura?</strong></summary>
<br>

Os secrets padrão do Kubernetes são **codificados em base64, não criptografados**. Qualquer pessoa com acesso à API pode decodificá-los.

Passos de endurecimento:
1. **Habilitar criptografia em repouso** no etcd (`EncryptionConfiguration` com AES-CBC ou provedor KMS).
2. **Usar gerenciadores de secrets externos** (Vault, AWS Secrets Manager) com o External Secrets Operator ou CSI Secrets Store Driver.
3. **RBAC**: Restringir `get`/`list` em secrets apenas às contas de serviço que precisam deles.
4. **Montar como arquivos**, não como variáveis de ambiente — variáveis de ambiente podem vazar via logs, dumps de crash e `/proc`.
5. **Rotacionar secrets** regularmente e usar credenciais de curta duração onde possível.
</details>

## Scheduling e Recursos

<details>
<summary><strong>14. Explique requests e limits de recursos.</strong></summary>
<br>

- **Requests**: A quantidade de CPU/memória **garantida** ao contêiner. O scheduler usa requests para decidir qual nó tem capacidade suficiente.
- **Limits**: A quantidade **máxima** que um contêiner pode usar. Se um contêiner exceder seu limit de memória, é morto por OOM. Se exceder o limit de CPU, é limitado.

Classes QoS baseadas em requests/limits:
- **Guaranteed**: Requests == Limits para todos os contêineres. Maior prioridade, último a ser despejado.
- **Burstable**: Requests < Limits. Prioridade média.
- **BestEffort**: Sem requests ou limits definidos. Primeiro a ser despejado sob pressão.

Melhor prática: Sempre defina requests (para precisão do scheduling) e limits (para estabilidade do cluster).
</details>

<details>
<summary><strong>15. O que são taints, tolerations e node affinity?</strong></summary>
<br>

- **Taints** são aplicados a nós: "Não agende pods aqui a menos que tolerem este taint." Exemplo: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Tolerations** são aplicadas a pods: "Eu posso tolerar este taint." Pods com tolerations correspondentes podem ser agendados em nós com taints.
- **Node Affinity** é uma especificação do pod que diz "Prefira ou exija agendamento em nós com labels específicas." Exemplo: exigir nós com `disktype=ssd`.

Usar juntos: Aplicar taint em nós GPU → apenas pods com tolerations GPU e afinidade GPU vão para lá. Previne que cargas de trabalho sem GPU desperdicem hardware caro.
</details>

## Troubleshooting

<details>
<summary><strong>16. Um pod está preso em CrashLoopBackOff. Como você depura?</strong></summary>
<br>

`CrashLoopBackOff` significa que o contêiner continua crashando e Kubernetes está esperando antes de reiniciá-lo (atraso exponencial até 5 minutos).

Passos de depuração:
1. `kubectl describe pod <name>` — verifique Events, Last State, Exit Code.
2. `kubectl logs <pod> --previous` — leia os logs da instância que crashou.
3. Análise do código de saída: 1 = erro de aplicação, 137 = morto por OOM, 139 = segfault, 143 = SIGTERM.
4. Se o contêiner crasha rápido demais para logs: `kubectl run debug --image=<image> --command -- sleep 3600` e execute exec para inspecionar o ambiente.
5. Verifique se as probes de readiness/liveness estão mal configuradas (probe apontando para porta/caminho errado).
6. Verifique os limits de recursos — o contêiner pode ser morto por OOM antes de conseguir registrar algo.
</details>

<details>
<summary><strong>17. Um Service não está roteando tráfego para os pods. O que você verifica?</strong></summary>
<br>

1. **Labels correspondem**: O `spec.selector` do Service deve corresponder exatamente às `metadata.labels` do pod.
2. **Endpoints existem**: `kubectl get endpoints <service>` — se vazio, o selector não corresponde a nenhum pod em execução.
3. **Pods estão Ready**: Apenas pods passando probes de readiness aparecem nos Endpoints. Verifique `kubectl get pods` para o status Ready.
4. **Incompatibilidade de portas**: O `targetPort` do Service deve corresponder à porta na qual o contêiner está realmente escutando.
5. **Network Policy**: Uma NetworkPolicy pode estar bloqueando o ingresso aos pods.
6. **DNS**: De um pod de depuração, `nslookup <service-name>` para verificar que a resolução DNS funciona.
</details>

<details>
<summary><strong>18. Como realizar um deployment sem tempo de inatividade?</strong></summary>
<br>

1. **Estratégia de rolling update** (padrão): Defina `maxUnavailable: 0` e `maxSurge: 1` para garantir que os pods antigos só sejam removidos após os novos pods estarem Ready.
2. **Probes de readiness**: Sem uma probe de readiness, Kubernetes considera um pod Ready imediatamente após o início — o tráfego o atinge antes da aplicação estar inicializada.
3. **PreStop hook**: Adicione um hook de ciclo de vida `preStop` com um sleep curto (5-10s) para permitir que requisições em andamento sejam completadas antes do pod ser removido dos endpoints do Service.
4. **PodDisruptionBudget (PDB)**: Garante que um número mínimo de pods esteja sempre disponível durante interrupções voluntárias (drains de nós, upgrades).
5. **Shutdown gracioso**: A aplicação deve tratar SIGTERM e finalizar requisições ativas antes de sair.
</details>

<details>
<summary><strong>19. O que é um Horizontal Pod Autoscaler e como funciona?</strong></summary>
<br>

O HPA escala automaticamente o número de réplicas de pods com base em métricas observadas (CPU, memória ou métricas personalizadas).

Como funciona:
1. O HPA consulta o **Metrics Server** (ou API de métricas personalizadas) a cada 15 segundos.
2. Calcula: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. Se as réplicas desejadas diferem das atuais, atualiza a contagem de réplicas do Deployment.
4. Períodos de cooldown previnem oscilações: estabilização de scale-up (padrão 0s), estabilização de scale-down (padrão 300s).

Requisitos: Metrics Server instalado, requests de recursos definidos nos contêineres (para métricas de CPU/memória), limites mín/máx de réplicas configurados.
</details>

<details>
<summary><strong>20. Qual é a diferença entre uma liveness probe e uma readiness probe?</strong></summary>
<br>

- **Liveness probe**: "O contêiner está vivo?" Se falhar, kubelet **mata e reinicia** o contêiner. Usada para detectar deadlocks ou processos congelados.
- **Readiness probe**: "O contêiner está pronto para servir tráfego?" Se falhar, o pod é **removido dos endpoints do Service** (nenhum tráfego roteado para ele), mas o contêiner NÃO é reiniciado. Usada para períodos de aquecimento, verificações de dependências, sobrecarga temporária.

Também existe uma **Startup probe**: Desabilita as probes de liveness/readiness até que a aplicação tenha iniciado. Útil para aplicações de início lento para prevenir mortes prematuras.

Erro comum: Usar uma liveness probe que verifica uma dependência downstream (banco de dados). Se o banco de dados cair, todos os pods reiniciam — piorando a interrupção. A liveness deve verificar apenas a aplicação em si.
</details>
