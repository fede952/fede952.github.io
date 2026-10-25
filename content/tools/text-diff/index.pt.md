---
title: "Comparar textos online: ache as diferenças"
description: "Compare dois textos ou arquivos lado a lado ou em linha, destaque palavras ou caracteres, ignore espaços ou maiúsculas e copie um diff unificado. Privado."
intro: "Cole duas versões de um texto, de um arquivo de configuração ou de um trecho de código para ver cada linha **adicionada**, **removida** e **alterada**, **lado a lado** ou **em linha**, com as **palavras** ou os **caracteres** alterados em destaque. Ignore espaços ou maiúsculas, recolha as linhas inalteradas e **copie um diff unificado** para aplicar com `git apply` ou `patch`. Nada sai do seu navegador."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["comparar textos", "comparar dois textos", "diff online", "encontrar diferenças texto", "comparar arquivos", "diff unificado", "text compare", "comparador de textos"]
tags: ["ferramentas-dev", "diff", "texto", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Comparador de textos (diff)"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Cole a versão antiga em **Original** e a nova em **Alterado**, ou carregue cada uma com **Abrir arquivo**. Clique em **Exemplo** para testar com duas versões de uma configuração do nginx."
  - "O resultado é atualizado enquanto você digita. Escolha **Lado a lado** para ver as duas versões em colunas ou **Em linha** para uma única coluna com linhas − e + (o padrão no celular)."
  - "Defina **Destacar** como **Palavras** ou **Caracteres** para escolher a precisão com que as mudanças dentro de uma linha alterada são marcadas."
  - "Marque **Ignorar espaços** para tratar recuos e espaços repetidos como iguais, e **Ignorar maiúsculas** para não diferenciar maiúsculas de minúsculas."
  - "Trechos longos sem mudanças são recolhidos para três linhas de contexto; clique numa barra *⋯ linhas inalteradas* para expandir. Use **Copiar diff unificado** ou **Baixar .diff** para compartilhar a mudança como patch."
faq:
  - q: "Meus textos são enviados para algum lugar?"
    a: "Não. A comparação acontece inteiramente no seu navegador com a biblioteca de código aberto jsdiff, servida por este site. Nada do que você cola ou abre é enviado a um servidor, então você pode comparar contratos, arquivos de configuração com segredos ou código privado."
  - q: "Qual a diferença entre destacar palavras e caracteres?"
    a: "Nos dois casos os textos são primeiro emparelhados linha a linha. Dentro de cada linha alterada, o modo palavras marca palavras inteiras e sinais de pontuação diferentes — a opção mais clara para textos e para a maior parte do código. O modo caracteres marca caracteres individuais e mostra um erro de digitação de uma letra ou um dígito trocado num identificador ou número longo."
  - q: "O que exatamente \"Ignorar espaços\" ignora?"
    a: "Os espaços no início e no fim da linha e a quantidade de espaços entre as palavras: `a  =  1` e `a = 1` contam como a mesma linha, e blocos reindentados não aparecem como alterados. Um espaço entre duas palavras que antes estavam juntas continua sendo uma diferença. Linhas em branco continuam sendo comparadas como linhas."
  - q: "O que é um diff unificado e como aplicá-lo?"
    a: "É o formato de texto padrão de uma mudança, usado pelo git, por ferramentas de code review e pelo patch: cabeçalhos `---` e `+++` e depois blocos que começam com `@@`, com as linhas removidas marcadas com − e as adicionadas com +, mais três linhas de contexto. Salve como arquivo `.diff` e execute `git apply mudanca.diff` ou `patch -p0 < mudanca.diff`."
  - q: "Como a ferramenta decide que uma linha foi alterada e não removida e adicionada?"
    a: "Ela usa o algoritmo de diff de Myers sobre linhas inteiras para encontrar o menor conjunto de remoções e adições. Quando um bloco de linhas removidas é seguido diretamente por linhas adicionadas, elas são emparelhadas uma a uma como linhas alteradas. Se um par tem menos de cerca de 30% de conteúdo em comum, ele aparece como substituído, sem destaques internos."
  - q: "Ela compara arquivos grandes?"
    a: "Sim, de vários megabytes. Textos com mais de cerca de 400.000 caracteres são comparados quando você clica em Comparar, e não a cada tecla. A visualização mostra até 4.000 linhas; o diff unificado sempre traz o resultado completo. Textos tão diferentes que demorariam demais são avisados em vez de travar a página."
  - q: "Ela lida com quebras de linha do Windows?"
    a: "Sim. As quebras de linha CRLF e CR são normalizadas antes da comparação, então o mesmo arquivo salvo no Windows e no Linux aparece como idêntico. A falta de quebra de linha no final é ignorada na visualização e indicada no diff unificado."
---

## Como funciona

### Primeiro as linhas, depois palavras ou caracteres

Os dois textos são divididos em linhas e comparados com o **algoritmo de diff de Myers** (o mesmo do `git diff`), que encontra a menor sequência de remoções e adições para transformar o original no texto alterado. Linhas removidas seguidas diretamente por linhas adicionadas são emparelhadas como *alteradas*, e cada par é comparado de novo, token por token: palavras, espaços e sinais de pontuação isolados, ou caracteres individuais. Só os tokens diferentes ficam em destaque.

### Opções que não reescrevem o seu texto

**Ignorar espaços** e **Ignorar maiúsculas** mudam a forma como linhas e tokens são *comparados*, não o que é exibido: cada coluna mostra exatamente o que você colou. Assim a visualização continua fiel quando, por exemplo, um bloco de código foi reindentado: as linhas coincidem e na coluna da direita você ainda vê o novo recuo.

### Diff unificado

Os botões **Copiar diff unificado** e **Baixar .diff** geram um patch padrão com três linhas de contexto, com os nomes dos arquivos no cabeçalho se você os abriu (senão `original.txt` e `changed.txt`). Aplicado ao original, ele reproduz exatamente o texto alterado; os testes desta ferramenta verificam isso com `git apply`.

## Casos de uso

- **Código e configuração.** Veja o que mudou entre duas versões de um arquivo do nginx, Docker Compose ou YAML antes do deploy, sem fazer commit.
- **Documentos e contratos.** Encontre cada palavra editada entre duas versões de um contrato, de uma política ou de um artigo.
- **Logs e exportações.** Compare duas saídas de comandos, exportações CSV ou listas para achar as linhas que apareceram ou sumiram.
- **Compartilhar uma mudança.** Transforme sua edição num arquivo `.diff` que um colega pode aplicar com git ou colar num chamado.
- **Conferir um copiar e colar.** Verifique se um script, uma chave ou um trecho copiado entre sistemas chegou sem mudanças invisíveis — use o modo caracteres para o máximo de detalhe.
