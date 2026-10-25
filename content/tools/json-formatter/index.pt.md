---
title: "Formatador e validador JSON, para YAML"
description: "Formate, minifique e valide JSON com erro em linha e coluna exatas, ordene chaves, navegue pela árvore e converta JSON em YAML ou CSV. Privado, no navegador."
intro: "Cole JSON para **formatá-lo** com 2 ou 4 espaços ou tabulações, **minificá-lo**, **validá-lo** com a *linha e a coluna* exatas do primeiro erro, **ordenar as chaves**, navegar por ele como **árvore** recolhível ou converter **JSON para YAML**, **YAML para JSON** e **JSON para CSV**. Arquivos de vários megabytes são processados por um worker em segundo plano; nada é enviado."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["formatador json", "validador json", "formatar json online", "json beautifier", "json para yaml", "yaml para json", "json para csv", "minificar json"]
tags: ["ferramentas-dev", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "Formatador, validador e conversor de JSON"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Cole seu JSON em **Entrada**, abra um arquivo `.json` com **Abrir arquivo** ou clique em **Exemplo** para testar."
  - "Clique em **Formatar** (ou Ctrl/⌘ + Enter) para indentar com o **Recuo** escolhido; **Minificar** remove todos os espaços. Marque **Ordenar chaves** para colocar em ordem alfabética as chaves de cada objeto."
  - "Se o JSON for inválido, a linha de status indica o problema e a posição — por exemplo *Linha 3, coluna 14: vírgula sobrando no final* — e mostra a linha problemática com uma marca sob o caractere exato."
  - "Converta com **Para YAML** ou **Para CSV** (escolha o **Separador CSV**). Para o caminho inverso, mude para **Entrada YAML**, cole o YAML e clique em **Formatar** para obter JSON."
  - "Alterne a saída entre **Texto** e **Árvore** para navegar em estruturas grandes e depois **Copiar** ou **Baixar** o resultado."
faq:
  - q: "Meu JSON é enviado para um servidor?"
    a: "Não. Análise, formatação e conversão acontecem no seu navegador — entradas acima de 2 MB num Web Worker da mesma aba. A página não faz nenhuma requisição com seus dados, então respostas de API, tokens e arquivos de configuração ficam no seu computador."
  - q: "Por que aparece \"vírgula sobrando no final\"?"
    a: "O JSON não permite vírgula depois do último elemento de um objeto ou array, mesmo que o JavaScript permita. `[1, 2,]` e `{\"a\": 1,}` não são JSON válido: remova a última vírgula. Outros erros comuns que o validador identifica: aspas simples, chaves sem aspas, comentários e valores NaN ou Infinity."
  - q: "Como ele encontra a linha e a coluna de um erro?"
    a: "As mensagens do JSON.parse variam entre navegadores e algumas trazem só uma posição em caracteres. Quando a análise falha, a ferramenta relê o texto com seu próprio analisador estrito segundo a RFC 8259, que para no primeiro caractere impossível num JSON válido e informa a linha e a coluna dele."
  - q: "Como o JSON é convertido em CSV?"
    a: "Um array de objetos vira uma linha por objeto. Objetos aninhados viram colunas com ponto (`address.city`), arrays dentro de uma linha são escritos como texto JSON e as colunas são a união de todas as chaves na ordem em que aparecem. Valores com vírgulas, aspas ou quebras de linha ficam entre aspas, como pede a RFC 4180. Um array de arrays é escrito linha por linha."
  - q: "Comentários e âncoras do YAML são mantidos na conversão?"
    a: "De YAML para JSON, âncoras e aliases são resolvidos em valores comuns e os comentários se perdem, porque o JSON não tem nenhum dos dois. De JSON para YAML sai um YAML em blocos sem âncoras, então estruturas repetidas são escritas por inteiro."
  - q: "Ordenar as chaves altera meus dados?"
    a: "Nenhum valor muda. As chaves dos objetos são reordenadas por code point Unicode (maiúsculas antes das minúsculas) em todos os níveis; os arrays mantêm a ordem, porque a ordem faz parte do dado. A saída ordenada é útil para diffs e para arquivos estáveis no controle de versão."
  - q: "Qual o tamanho máximo de arquivo?"
    a: "Dezenas de megabytes num computador. Acima de 2 MB, a formatação e a minificação rodam num worker em segundo plano para a página continuar responsiva. A visão em árvore cria os nós só quando você os abre e mostra no máximo 500 filhos por nó de cada vez."
---

## Como funciona

### Uma validação que se explica

A entrada é analisada com o `JSON.parse` nativo do navegador, o analisador mais rápido e fiel ao padrão disponível. Quando ele falha, um segundo analisador, propositalmente pequeno, percorre o texto seguindo a gramática da RFC 8259 — objetos, arrays, strings com suas regras de escape, números sem zeros à esquerda, `true`, `false`, `null` — e para no primeiro caractere que não pode continuar um documento válido. Essa posição é convertida em linha e coluna e ligada a uma explicação clara: uma vírgula sobrando, dois-pontos faltando, uma string com aspas simples, uma tabulação sem escape dentro de uma string ou texto depois do fim do documento.

### Formatar, minificar e ordenar

A formatação usa `JSON.stringify` com o recuo escolhido (2 espaços, 4 espaços ou uma tabulação). Minificar grava a mesma estrutura sem espaços. **Ordenar chaves** reconstrói cada objeto com as chaves em ordem de code point antes de serializar; a ordem dos arrays nunca muda. Os números são escritos como o JavaScript os lê, então inteiros acima de 2^53 perdem precisão — guarde esses IDs como strings.

### Entradas grandes

Acima de 2 MB em UTF-8, a formatação e a minificação passam para um **Web Worker**, uma thread em segundo plano da mesma aba, para digitar e rolar continuarem fluidos enquanto um dump grande de API é processado. A visão em árvore é montada sob demanda: os filhos de um nó só são criados quando você o expande.

### Conversões

O suporte a YAML vem do **js-yaml** (MIT), servido por este site e carregado só na primeira vez que você usa YAML. O YAML é lido com o esquema seguro padrão, então não pode criar objetos personalizados nem executar código. O CSV é gerado pela própria ferramenta, com as aspas e quebras de linha da RFC 4180.

## Casos de uso

- **Depurar APIs.** Formate uma resposta de uma linha só, ache na árvore o campo que você precisa ou descubra exatamente onde um payload editado à mão quebra.
- **Configuração.** Converta um trecho de Kubernetes ou Docker Compose entre YAML e JSON, ou valide um `package.json` ou `tsconfig.json` depois de editar.
- **Exportação de dados.** Transforme um array de registros em CSV para uma planilha, com os campos aninhados achatados em colunas.
- **Code review e controle de versão.** Ordene as chaves e formate de forma consistente para os diffs mostrarem mudanças reais, não reordenações.
- **Dados sensíveis.** Inspecione payloads de JWT, corpos de webhook ou logs com dados pessoais sem colá-los num site de terceiros.
