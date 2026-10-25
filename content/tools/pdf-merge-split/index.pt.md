---
title: "Juntar e dividir PDF online grátis"
description: "Junte arquivos PDF, divida-os por páginas ou intervalos, reordene, gire e exclua páginas no navegador. Seus PDFs nunca são enviados. Grátis e sem cadastro."
intro: "**Junte PDFs** num único arquivo, **divida um PDF** em páginas avulsas ou intervalos e, de quebra, reordene, gire ou exclua páginas, com miniaturas que você pode arrastar. Tudo acontece nesta aba do navegador: contratos, holerites e digitalizações nunca saem do seu dispositivo."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["juntar pdf", "dividir pdf", "unir arquivos pdf", "reordenar páginas pdf", "dividir pdf online", "juntar pdf sem enviar", "extrair páginas de pdf", "girar páginas pdf"]
tags: ["pdf", "privacidade", "documentos", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "Juntar, dividir e organizar PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Solte um ou mais arquivos PDF na caixa ou clique para escolhê-los. Cada página aparece como uma miniatura numerada, na ordem dos arquivos."
  - "Organize as páginas: arraste uma miniatura para outra posição ou use os botões **←** e **→** (práticos no celular). **⟳** gira uma página em 90°, **✕** a deixa fora do resultado."
  - "Para juntar tudo, defina o **Nome do arquivo** e clique em **Juntar e baixar**: você recebe um único PDF com as páginas exatamente como as organizou."
  - "Para dividir, escolha **Cada página num PDF separado**, ou **Por intervalos de páginas** e digite grupos como `1-3, 4, 5-` (os números das miniaturas; `5-` significa da página 5 até o fim)."
  - "Clique em **Dividir e baixar (.zip)**. Cada grupo vira um PDF com o nome do primeiro arquivo (`relatorio-part-1.pdf`…); com um só grupo você recebe o PDF diretamente."
faq:
  - q: "Meus PDFs são enviados para algum lugar?"
    a: "Não. O navegador lê os arquivos, mostra a prévia com o pdf.js e os reconstrói com a pdf-lib, ambos rodando nesta aba. A página baixa essas bibliotecas uma vez e não envia nada; você pode observar o painel Rede enquanto junta os arquivos para confirmar."
  - q: "Juntar PDFs reduz a qualidade?"
    a: "Não. As páginas são copiadas como estão: texto continua texto, imagens mantêm a compressão original e as fontes são preservadas. Nada é rasterizado nem comprimido de novo, então o resultado é tão nítido quanto os originais."
  - q: "Posso juntar PDFs protegidos por senha?"
    a: "Não diretamente: um PDF criptografado não pode ser lido sem a senha, e a ferramenta avisa em vez de gerar um arquivo quebrado. Abra-o num leitor de PDF, salve uma cópia sem senha e adicione essa cópia."
  - q: "Links, marcadores e campos de formulário são mantidos?"
    a: "O conteúdo das páginas, as anotações e os links das páginas são copiados. O sumário (marcadores) e a lógica dos formulários interativos pertencem ao arquivo original inteiro e não são recriados no PDF unido, então confira os formulários depois de juntar."
  - q: "Qual o tamanho máximo dos arquivos?"
    a: "Não existe limite fixo; depende da memória do dispositivo. Documentos de algumas centenas de páginas funcionam bem num computador. É gerada uma miniatura por página, então arquivos muito grandes demoram mais para aparecer."
  - q: "O que a rotação faz com o arquivo?"
    a: "Define a rotação da página no PDF (em passos de 90°), que todos os leitores respeitam. O conteúdo não é redesenhado: girar não tem perdas e é desfeito girando de novo."
  - q: "Como extraio só algumas páginas?"
    a: "Use **Por intervalos de páginas** com um único grupo, por exemplo `3-5`: você baixa um PDF que contém só as páginas 3, 4 e 5. Outra opção é remover com ✕ as páginas que não quer e juntar."
---

## Como funciona

### Duas bibliotecas, ambas locais

Ler um PDF e escrever um são tarefas diferentes, então a ferramenta usa duas bibliotecas de código aberto, servidas por este site e carregadas só quando você adiciona um arquivo:

- **pdf.js** (Mozilla, Apache-2.0), o motor do visualizador de PDF do Firefox, gera uma pequena miniatura de cada página num worker em segundo plano, para a página continuar responsiva.
- **pdf-lib** (MIT) monta o resultado. Para cada página, na sua ordem, copia o objeto da página do documento de origem — fluxos de conteúdo, fontes, imagens e anotações — para um documento novo com `copyPages`, aplica a rotação escolhida e salva.

Antes de tudo, a ferramenta confere se cada arquivo começa com `%PDF-`, assim um documento do Word renomeado ou um download corrompido é informado pelo nome.

### Ordem das páginas e intervalos

As miniaturas formam uma única lista para todos os arquivos: juntar grava as páginas nessa ordem, e os números que você digita para dividir também se referem a ela. Intervalos são grupos separados por vírgulas; cada grupo pode ser uma página avulsa (`4`), um intervalo (`1-3`), um fim aberto (`5-` até a última página) ou um início aberto (`-3`). Cada grupo vira um PDF; vários PDFs são empacotados num ZIP com JSZip.

### O que não é incluído

O documento novo recebe metadados novos da pdf-lib no lugar dos títulos e autores de origem, e recursos do documento inteiro, como o sumário de marcadores e os scripts de formulário, não são recriados. Para juntar e dividir no dia a dia — notas fiscais, digitalizações, capítulos, slides — é exatamente o que você precisa.

## Casos de uso

- **Juntar digitalizações** de um contrato ou formulário de várias páginas num único arquivo antes de enviar por e-mail.
- **Dividir um PDF grande** — um livro didático, um manual, um ano de extratos bancários — em capítulos ou meses.
- **Remover páginas** com dados pessoais antes de compartilhar um documento.
- **Corrigir a ordem e a orientação** de um documento digitalizado de cabeça para baixo ou fora de ordem.
- **Montar uma candidatura**: currículo, carta de apresentação e certificados na ordem pedida, sem entregá-los a um serviço online sobre o qual você não sabe nada.
