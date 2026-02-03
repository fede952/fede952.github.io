---
title: "Pare de Pagar por IA: Execute DeepSeek e Llama 3 Localmente de Graça"
date: 2025-02-02
description: "Aprenda a executar modelos de IA poderosos como DeepSeek e Llama 3 no seu próprio PC gratuitamente com Ollama. Privacidade total, sem taxas mensais, funciona offline."
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

Você não precisa de uma assinatura de 20$/mês para usar um assistente de IA poderoso. Com uma ferramenta gratuita e de código aberto chamada **Ollama**, você pode executar modelos de linguagem de última geração — incluindo **Llama 3 da Meta** e **DeepSeek-R1** — diretamente no seu computador. Sem nuvem. Sem conta. Nenhum dado jamais sai da sua máquina.

Este guia te acompanha em toda a configuração em menos de 10 minutos.

## Por Que Executar IA Localmente?

### Privacidade Completa

Quando você usa um serviço de IA na nuvem, cada prompt que digita é enviado para um servidor remoto. Isso inclui trechos de código, ideias de negócio, perguntas pessoais — tudo. Com um **LLM local**, suas conversas ficam no seu hardware. Ponto final.

### Zero Custos Mensais

ChatGPT Plus custa 20$/mês. Claude Pro custa 20$/mês. GitHub Copilot custa 10$/mês. Um modelo local não custa **nada** após o download inicial. Os modelos são de código aberto e gratuitos.

### Funciona Offline

Num avião? Numa cabana sem Wi-Fi? Não importa. Um modelo local roda inteiramente na sua CPU e RAM — não é necessária conexão com a internet.

---

## Pré-requisitos

Você não precisa de uma GPU ou estação de trabalho potente. Aqui está o mínimo:

- **Sistema Operacional:** Windows 10/11, macOS 12+ ou Linux
- **RAM:** 8 GB mínimo (16 GB recomendados para modelos maiores)
- **Espaço em Disco:** ~5 GB livres para a aplicação e um modelo
- **Opcional:** Uma GPU dedicada (NVIDIA/AMD) acelera a inferência mas **não é necessária**

---

## Passo 1: Baixar e Instalar o Ollama

**Ollama** é um runtime leve que baixa, gerencia e executa LLMs com um único comando. A instalação é simples em todas as plataformas.

### Windows

1. Visite [ollama.com](https://ollama.com) e clique em **Download for Windows**.
2. Execute o instalador — leva cerca de um minuto.
3. O Ollama roda em segundo plano automaticamente após a instalação.

### macOS

Você tem duas opções:

```bash
# Opção A: Homebrew (recomendado)
brew install ollama

# Opção B: Download direto
# Visite https://ollama.com e baixe o .dmg
```

### Linux

Um único comando resolve tudo:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Após a instalação, verifique se funciona:

```bash
ollama --version
```

Você deve ver um número de versão no seu terminal.

---

## Passo 2: Execute Seu Primeiro Modelo — O Comando Mágico

Este é o momento. Abra um terminal e digite:

```bash
ollama run llama3
```

É isso. O Ollama vai baixar o modelo **Llama 3 8B** (~4,7 GB) na primeira execução, depois te leva a uma sessão de chat interativa diretamente no terminal:

```
>>> Quem é você?
Sou Llama, um grande modelo de linguagem treinado pela Meta.
Como posso ajudá-lo hoje?

>>> Escreva uma função Python que verifica se um número é primo.
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### Experimente o DeepSeek-R1 para Tarefas de Raciocínio

**DeepSeek-R1** se destaca em matemática, lógica e resolução de problemas passo a passo:

```bash
ollama run deepseek-r1
```

### Outros Modelos Populares

| Modelo | Comando | Ideal Para |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | Chat geral, programação |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | Matemática, lógica, raciocínio |
| Mistral 7B | `ollama run mistral` | Rápido, polivalente eficiente |
| Gemma 2 9B | `ollama run gemma2` | Modelo aberto do Google |
| Qwen 2.5 7B | `ollama run qwen2.5` | Tarefas multilíngues |

Execute `ollama list` para ver seus modelos baixados e `ollama rm <modelo>` para deletar um e liberar espaço.

---

## Passo 3: Adicione uma Interface de Chat com Open WebUI (Opcional)

O terminal funciona, mas se você quer uma interface polida **tipo ChatGPT**, instale o **Open WebUI**. O método mais rápido é Docker:

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

Depois abra [http://localhost:3000](http://localhost:3000) no seu navegador. Você terá uma interface de chat familiar com histórico de conversas, troca de modelo, upload de arquivos e mais — tudo conectado à sua instância local do Ollama.

> **Sem Docker?** Existem outros frontends leves como [Chatbox](https://chatboxai.app) (app desktop) ou [Ollama Web UI](https://github.com/ollama-webui/ollama-webui) que não requerem Docker.

---

## IA Local vs. IA na Nuvem: A Comparação Completa

| Característica | IA Local (Ollama) | IA na Nuvem (ChatGPT, Claude) |
|---|---|---|
| **Privacidade** | Seus dados nunca saem do seu PC | Dados enviados para servidores remotos |
| **Custo** | Completamente gratuito | 20$/mês para níveis premium |
| **Internet Necessária** | Não — funciona totalmente offline | Sim — sempre |
| **Velocidade** | Depende do seu hardware | Rápido (GPUs no servidor) |
| **Qualidade do Modelo** | Excelente (Llama 3, DeepSeek) | Excelente (GPT-4o, Claude) |
| **Esforço de Instalação** | Um comando | Criar uma conta |
| **Personalização** | Controle total, fine-tuning | Limitada |
| **Retenção de Dados** | Você controla tudo | Política do provedor se aplica |

**Resumindo:** Modelos na nuvem ainda têm vantagem em capacidade bruta para as maiores tarefas, mas para ajuda diária com código, escrita, brainstorming e perguntas, modelos locais são **mais que suficientes** — e são gratuitos e privados.

---

## Conclusão

Executar uma IA local não é mais um hobby de nicho para pesquisadores com GPUs caras. Graças ao **Ollama** e ao ecossistema de modelos de código aberto, qualquer pessoa com um laptop moderno pode ter um assistente de IA privado, gratuito e com capacidade offline em menos de 10 minutos.

Os comandos para lembrar:

```bash
# Instalar (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Executar um modelo
ollama run llama3

# Listar seus modelos
ollama list
```

Experimente. Uma vez que você vivenciar a velocidade e privacidade de um LLM local, pode acabar recorrendo à nuvem cada vez menos.

> Precisa manter o foco enquanto programa com sua IA local? Experimente nosso [mixer de sons ambientais ZenFocus e timer Pomodoro](/pt/tools/zen-focus/) — outra ferramenta que funciona inteiramente no seu navegador sem nenhum rastreamento.
