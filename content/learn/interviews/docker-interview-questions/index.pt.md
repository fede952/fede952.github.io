---
title: "Top 20 Perguntas e Respostas de Entrevista sobre Docker (Edição 2026)"
description: "Domine sua entrevista de Senior DevOps com estas 20 perguntas avançadas sobre Docker cobrindo containers, imagens, redes, volumes, Docker Compose e boas práticas de produção."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["perguntas entrevista docker", "entrevista senior devops", "perguntas containerização", "respostas entrevista docker", "entrevista docker compose", "boas práticas dockerfile", "entrevista orquestração containers", "perguntas redes docker", "entrevista engenheiro devops", "perguntas docker produção"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Top 20 Perguntas e Respostas de Entrevista sobre Docker (Edição 2026)",
    "description": "Perguntas avançadas de entrevista sobre Docker para cargos Senior DevOps cobrindo containers, imagens, redes e boas práticas de produção.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

Docker tornou-se uma habilidade indispensável para qualquer cargo de DevOps, SRE ou engenharia backend. Entrevistadores de nível sênior esperam que você vá além do `docker run` — eles querem ver que você entende camadas de imagem, detalhes internos de rede, endurecimento de segurança e padrões de orquestração para produção. Este guia contém as 20 perguntas mais frequentes em entrevistas de nível Sênior e Lead, com respostas detalhadas que demonstram profundidade.

**Precisa de uma revisão rápida de comandos antes da entrevista?** Salve nos favoritos nosso [Cheatsheet Docker Captain's Log](/cheatsheets/docker-container-commands/).

---

## Conceitos Fundamentais

<details>
<summary><strong>1. Qual é a diferença entre um container e uma máquina virtual?</strong></summary>
<br>

Uma **máquina virtual** executa um sistema operacional convidado completo sobre um hypervisor, incluindo seu próprio kernel, drivers e bibliotecas do sistema. Cada VM é completamente isolada, mas consome recursos significativos (GBs de RAM, minutos para iniciar).

Um **container** compartilha o kernel do sistema operacional do host e isola processos usando namespaces Linux e cgroups. Ele empacota apenas a aplicação e suas dependências — sem kernel separado. Isso torna os containers leves (MBs), rápidos para iniciar (milissegundos) e altamente portáveis.

Diferença chave: VMs virtualizam o **hardware**, containers virtualizam o **sistema operacional**.
</details>

<details>
<summary><strong>2. O que são as camadas de imagem Docker e como funcionam?</strong></summary>
<br>

Uma imagem Docker é construída a partir de uma série de **camadas somente leitura**. Cada instrução no Dockerfile (`FROM`, `RUN`, `COPY`, etc.) cria uma nova camada. As camadas são empilhadas usando um sistema de arquivos union (como OverlayFS).

Quando um container é executado, Docker adiciona uma fina **camada gravável** no topo (a camada do container). Alterações feitas em tempo de execução afetam apenas esta camada gravável — as camadas subjacentes da imagem permanecem inalteradas.

Esta arquitetura permite:
- **Cache**: Se uma camada não mudou, Docker a reutiliza do cache durante as builds.
- **Compartilhamento**: Múltiplos containers da mesma imagem compartilham as camadas somente leitura, economizando espaço em disco.
- **Eficiência**: Apenas camadas modificadas precisam ser baixadas ou enviadas para registries.
</details>

<details>
<summary><strong>3. Qual é a diferença entre CMD e ENTRYPOINT em um Dockerfile?</strong></summary>
<br>

Ambos definem o que é executado quando um container inicia, mas se comportam de forma diferente:

- **CMD** fornece argumentos padrão que podem ser completamente substituídos em tempo de execução. Se você executar `docker run myimage /bin/bash`, o CMD é substituído.
- **ENTRYPOINT** define o executável principal que sempre é executado. Argumentos em tempo de execução são adicionados a ele, não substituídos.

Boa prática: Use `ENTRYPOINT` para o processo principal e `CMD` para argumentos padrão:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

Executar `docker run myimage --port 3000` executará `python app.py --port 3000`.
</details>

<details>
<summary><strong>4. O que é uma build multi-stage e por que é importante?</strong></summary>
<br>

Uma build multi-stage usa múltiplas instruções `FROM` em um único Dockerfile. Cada `FROM` inicia uma nova etapa de build, e você pode copiar seletivamente artefatos de uma etapa para outra.

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

Isso produz uma imagem final contendo apenas o binário compilado — sem ferramentas de build, sem código-fonte, sem arquivos intermediários. O resultado é uma imagem drasticamente menor (frequentemente 10-100x menor) com uma superfície de ataque reduzida.
</details>

<details>
<summary><strong>5. Qual é a diferença entre COPY e ADD em um Dockerfile?</strong></summary>
<br>

Ambos copiam arquivos do contexto de build para a imagem, mas `ADD` tem funcionalidades extras:
- `ADD` pode extrair automaticamente arquivos `.tar` locais.
- `ADD` pode baixar arquivos de URLs.

No entanto, as boas práticas Docker recomendam usar `COPY` em quase todos os casos porque é explícito e previsível. Use `ADD` apenas quando precisar especificamente de extração tar. Nunca use `ADD` para baixar arquivos — use `RUN curl` ou `RUN wget` em vez disso, para que a camada de download possa ser cacheada corretamente.
</details>

## Redes

<details>
<summary><strong>6. Explique os modos de rede do Docker (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (padrão): Cria uma rede interna privada no host. Containers na mesma bridge podem se comunicar por IP ou nome do container. Tráfego externo requer mapeamento de portas (`-p`).
- **Host**: Remove o isolamento de rede. O container compartilha diretamente a pilha de rede do host. Sem necessidade de mapeamento de portas, mas sem isolamento. Útil para aplicações com requisitos críticos de desempenho.
- **None**: Sem rede alguma. O container tem apenas uma interface loopback. Usado para jobs batch ou cargas de trabalho sensíveis à segurança.
- **Overlay**: Abrange múltiplos hosts Docker (usado em Swarm/Kubernetes). Containers em máquinas diferentes podem se comunicar como se estivessem na mesma rede, usando tunneling VXLAN.
</details>

<details>
<summary><strong>7. Como funciona a comunicação entre containers?</strong></summary>
<br>

Em uma rede bridge definida pelo usuário, containers podem se alcançar **pelo nome do container** através do resolver DNS integrado do Docker. O servidor DNS roda em `127.0.0.11` dentro de cada container.

Na rede bridge padrão, a resolução DNS **não** está disponível — containers só podem se comunicar por endereço IP, o que não é confiável já que IPs são atribuídos dinamicamente.

Boa prática: Sempre crie uma rede bridge personalizada (`docker network create mynet`) e conecte containers a ela. Nunca dependa da bridge padrão para comunicação entre containers.
</details>

<details>
<summary><strong>8. Qual é a diferença entre EXPOSE e publicar uma porta?</strong></summary>
<br>

`EXPOSE` em um Dockerfile é puramente **documentação** — informa a qualquer pessoa lendo o Dockerfile que a aplicação escuta em uma porta específica. NÃO abre ou mapeia realmente a porta.

Publicar uma porta (`-p 8080:80`) realmente cria uma regra de rede que mapeia uma porta do host para uma porta do container, tornando o serviço acessível de fora do container.

Você pode publicar portas que não estão na diretiva `EXPOSE`, e `EXPOSE` sozinho não faz nada sem `-p`.
</details>

## Volumes e Armazenamento

<details>
<summary><strong>9. Quais são os três tipos de montagens Docker?</strong></summary>
<br>

1. **Volumes** (`docker volume create`): Gerenciados pelo Docker, armazenados em `/var/lib/docker/volumes/`. Ideais para dados persistentes (bancos de dados). Sobrevivem à remoção do container. Portáveis entre hosts.
2. **Bind mounts** (`-v /host/path:/container/path`): Mapeiam um diretório específico do host para o container. O caminho do host deve existir. Ideais para desenvolvimento (recarregamento de código em tempo real). Não portáveis.
3. **Montagens tmpfs** (`--tmpfs /tmp`): Armazenadas apenas na memória do host. Nunca escritas em disco. Ideais para dados sensíveis que não devem persistir (segredos, tokens de sessão).
</details>

<details>
<summary><strong>10. Como persistir dados de um container de banco de dados?</strong></summary>
<br>

Use um **volume nomeado** montado no diretório de dados do banco de dados:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

Os dados sobrevivem a reinícios e remoções do container. Ao atualizar a versão do banco de dados, pare o container antigo, inicie um novo com o mesmo volume e deixe a nova versão lidar com a migração dos dados.

Nunca use bind mounts para bancos de dados em produção — volumes têm melhor desempenho de I/O e são gerenciados pelo driver de armazenamento do Docker.
</details>

## Segurança

<details>
<summary><strong>11. Como proteger um container Docker em produção?</strong></summary>
<br>

Práticas-chave de endurecimento:
- **Executar como não-root**: Use a diretiva `USER` no Dockerfile. Nunca execute processos da aplicação como root.
- **Usar imagens base mínimas**: `alpine`, `distroless` ou `scratch` em vez de `ubuntu`.
- **Remover capabilities**: Use `--cap-drop ALL --cap-add <apenas-necessárias>`.
- **Sistema de arquivos somente leitura**: Use `--read-only` e monte apenas caminhos específicos graváveis.
- **Sem novos privilégios**: Use `--security-opt=no-new-privileges`.
- **Escanear imagens**: Use `docker scout`, Trivy ou Snyk para detectar vulnerabilidades em imagens base e dependências.
- **Assinar imagens**: Use Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) para verificar a autenticidade das imagens.
- **Limitar recursos**: Use `--memory`, `--cpus` para prevenir esgotamento de recursos.
</details>

<details>
<summary><strong>12. O que é o modo rootless do Docker?</strong></summary>
<br>

O modo rootless do Docker executa o daemon Docker e containers inteiramente dentro de um namespace de usuário, sem requerer privilégios root no host. Isso elimina a principal preocupação de segurança com Docker: o daemon roda como root, e uma fuga do container significa acesso root ao host.

No modo rootless, mesmo que um atacante escape do container, ele obtém apenas os privilégios do usuário não privilegiado que executa o Docker. A contrapartida é que algumas funcionalidades (como vincular a portas abaixo de 1024) requerem configuração adicional.
</details>

## Docker Compose e Orquestração

<details>
<summary><strong>13. Qual é a diferença entre docker-compose up e docker-compose run?</strong></summary>
<br>

- `docker compose up`: Inicia **todos** os serviços definidos em `docker-compose.yml`, cria redes/volumes e respeita a ordem de `depends_on`. Tipicamente usado para subir toda a stack.
- `docker compose run <serviço> <comando>`: Inicia um **único** serviço com um comando pontual. Não inicia serviços dependentes por padrão (use `--service-ports` para mapear portas, `--rm` para limpeza). Usado para executar migrações, testes ou tarefas administrativas.
</details>

<details>
<summary><strong>14. Como funciona depends_on e quais são suas limitações?</strong></summary>
<br>

`depends_on` controla a **ordem de inicialização** — garante que o serviço A inicie antes do serviço B. No entanto, ele apenas espera o container **iniciar**, não que a aplicação dentro esteja **pronta**.

Por exemplo, um container de banco de dados pode iniciar em segundos, mas o PostgreSQL precisa de tempo adicional para inicializar. Seu container da aplicação iniciará e imediatamente falhará ao conectar.

Solução: Use `depends_on` com uma `condition` e health check:

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
<summary><strong>15. Quando você escolheria Docker Swarm em vez de Kubernetes?</strong></summary>
<br>

**Docker Swarm**: Integrado ao Docker, sem configuração adicional. Ideal para implantações pequenas a médias onde a simplicidade importa. Usa os mesmos arquivos Docker Compose. Ecossistema e comunidade limitados comparados ao Kubernetes. Adequado para equipes que não têm engenheiros de plataforma dedicados.

**Kubernetes**: Padrão da indústria para orquestração de containers em escala. Suporta auto-scaling, atualizações rolling, service mesh, custom resource definitions e um ecossistema massivo (Helm, Istio, ArgoCD). Maior complexidade e curva de aprendizado. Necessário para implantações em grande escala, multi-equipe e multi-cloud.

Regra geral: Se você tem menos de 20 serviços e uma equipe pequena, Swarm é suficiente. Além disso, Kubernetes vale o investimento.
</details>

## Produção e Resolução de Problemas

<details>
<summary><strong>16. Como reduzir o tamanho de uma imagem Docker?</strong></summary>
<br>

1. **Usar builds multi-stage** — manter ferramentas de build fora da imagem final.
2. **Usar imagens base mínimas** — `alpine` (~5MB) em vez de `ubuntu` (~75MB).
3. **Combinar comandos RUN** — cada `RUN` cria uma camada. Encadear comandos com `&&` e limpar na mesma camada.
4. **Usar .dockerignore** — excluir `node_modules`, `.git`, arquivos de teste, documentação do contexto de build.
5. **Ordenar camadas por frequência de mudança** — colocar camadas que mudam raramente (dependências) antes de camadas que mudam frequentemente (código-fonte) para maximizar cache hits.
</details>

<details>
<summary><strong>17. Um container continua reiniciando. Como você faz o debug?</strong></summary>
<br>

Abordagem passo a passo:
1. `docker ps -a` — verificar o código de saída. Código 137 = morto por OOM. Código 1 = erro da aplicação.
2. `docker logs <container>` — ler os logs da aplicação em busca de stack traces ou mensagens de erro.
3. `docker inspect <container>` — verificar `State.OOMKilled`, limites de recursos e variáveis de ambiente.
4. `docker run -it --entrypoint /bin/sh <image>` — iniciar um shell interativo para debugar o ambiente manualmente.
5. `docker stats` — verificar se o container está atingindo limites de memória ou CPU.
6. Verificar `docker events` — procurar sinais de kill ou eventos OOM do daemon.
</details>

<details>
<summary><strong>18. Qual é a diferença entre docker stop e docker kill?</strong></summary>
<br>

- `docker stop` envia **SIGTERM** ao processo principal (PID 1) e espera um período de graça (padrão 10 segundos). Se o processo não terminar, Docker envia SIGKILL. Isso permite que a aplicação realize um desligamento gracioso (fechar conexões, esvaziar buffers, salvar estado).
- `docker kill` envia **SIGKILL** imediatamente. O processo é terminado sem chance de limpeza. Use apenas quando um container não responde.

Boa prática: Sempre use `docker stop` em produção. Garanta que sua aplicação trate SIGTERM corretamente.
</details>

<details>
<summary><strong>19. Como gerenciar segredos no Docker?</strong></summary>
<br>

**Nunca** incorpore segredos nas imagens (ENV no Dockerfile, COPY de arquivos .env). Eles persistem nas camadas da imagem e são visíveis com `docker history`.

Abordagens por nível de maturidade:
- **Básico**: Passe segredos via `--env-file` em tempo de execução (arquivo não incluído na imagem).
- **Melhor**: Use segredos do Docker Swarm ou Kubernetes secrets (montados como arquivos, não como variáveis de ambiente).
- **Ótimo**: Use um gerenciador de segredos externo (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) e injete segredos em tempo de execução via sidecar ou init container.
</details>

<details>
<summary><strong>20. O que é um health check Docker e por que é fundamental?</strong></summary>
<br>

Um health check é um comando que Docker executa periodicamente dentro do container para verificar que a aplicação está realmente funcionando — não apenas que o processo está rodando.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Sem um health check, Docker só sabe se o processo está vivo (PID existe). Com um health check, Docker sabe se a aplicação está **saudável** (respondendo a requisições). Isso é fundamental para:
- **Balanceadores de carga**: Direcionar tráfego apenas para containers saudáveis.
- **Orquestradores**: Reiniciar containers não saudáveis automaticamente.
- **depends_on**: Esperar pela prontidão real, não apenas pelo início do processo.
</details>
