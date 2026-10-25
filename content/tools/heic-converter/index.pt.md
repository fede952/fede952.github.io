---
title: "Converter HEIC em JPG grátis e sem upload"
description: "Converta fotos HEIC do iPhone em JPG ou PNG no navegador: em lote, com qualidade ajustável, remoção opcional de EXIF/GPS e download em ZIP. Sem upload."
intro: "Transforme **fotos HEIC do iPhone em JPG ou PNG** sem enviá-las para lugar nenhum: solte um ou cem arquivos, escolha formato e qualidade, decida se quer remover os metadados EXIF e a localização GPS e baixe cada arquivo ou um único ZIP. O decodificador roda dentro desta aba do navegador."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["converter heic em jpg", "heic para jpg", "conversor heic", "heic para png", "foto iphone para jpg", "abrir arquivo heic", "converter heic online", "heic jpg grátis"]
tags: ["imagens", "privacidade", "conversor", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "Conversor de HEIC para JPG e PNG"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Solte suas fotos `.heic` ou `.heif` na caixa ou clique para escolhê-las. Dá para adicionar várias de uma vez, e mais depois."
  - "Na primeira vez, a página carrega o decodificador HEIC (cerca de 1,5 MB, uma vez por visita). Depois cada foto é decodificada e convertida em sequência; ao lado do nome aparecem uma miniatura e o novo tamanho."
  - "Escolha **JPG** (arquivos menores, **Qualidade JPG** ajustável) ou **PNG** (sem perdas, maior). Mudar uma opção reconverte as fotos que já estão na lista."
  - "Deixe marcado **Remover metadados (EXIF, localização GPS)** para gerar arquivos limpos, ou desmarque para manter no JPG os dados da câmera e a localização."
  - "Clique em **Baixar** numa foto, ou em **Baixar tudo (.zip)** para salvar todos os arquivos convertidos num único pacote."
faq:
  - q: "Minhas fotos são enviadas para um servidor?"
    a: "Não. Os arquivos são lidos pela File API do navegador e decodificados por uma versão WebAssembly da libheif que roda nesta aba. As únicas requisições de rede servem para baixar o decodificador; suas fotos nunca saem do dispositivo. Você pode conferir no painel Rede do navegador durante a conversão."
  - q: "Por que o iPhone salva as fotos em HEIC?"
    a: "O HEIC guarda uma imagem comprimida em HEVC (H.265) dentro de um contêiner HEIF. Com qualidade parecida, os arquivos têm mais ou menos metade do tamanho de um JPEG, por isso o iOS o usa por padrão. Muitos programas do Windows, sites e aparelhos antigos ainda não o abrem, daí a necessidade de converter."
  - q: "Vou perder qualidade?"
    a: "Converter para JPEG comprime a imagem de novo. Na qualidade padrão de 85 a diferença é muito difícil de notar e o arquivo continua leve; use 95–100 se for editar a foto. O PNG não tem perdas, mas costuma ser de três a cinco vezes maior que o HEIC original."
  - q: "O que \"Remover metadados\" remove?"
    a: "Tudo menos os pixels: os dados EXIF da câmera, a data e a hora e, principalmente, a posição GPS, que pode revelar onde você mora ou trabalha. Com a opção desmarcada, o conversor copia para o JPEG o bloco EXIF original e zera a tag de orientação, porque o decodificador já girou a imagem."
  - q: "Meu HEIC tem várias imagens (Live Photo, sequência). Qual é convertida?"
    a: "A imagem principal, a que o app Fotos mostra. A parte em movimento de uma Live Photo é um arquivo de vídeo separado e não é incluída."
  - q: "Existe limite de tamanho ou de quantidade?"
    a: "Só a memória do seu dispositivo. Cada foto é decodificada em pixels brutos (uma foto de 12 megapixels ocupa cerca de 48 MB durante a conversão), então lotes muito grandes são mais rápidos num computador do que num celular antigo."
  - q: "Posso converter HEIC em PNG com transparência?"
    a: "Fotos de câmeras de celular não têm transparência. Se uma imagem HEIF tiver canal alfa, o PNG o mantém; o JPEG não suporta transparência e a preenche de preto."
---

## Como funciona

### Decodificar sem servidor

Navegadores que não sejam o Safari não abrem HEIC sozinhos, porque o formato embala imagens comprimidas em **HEVC** num contêiner **HEIF** (ISO/IEC 23008-12). Esta página inclui a **libheif** — a biblioteca de referência de código aberto para HEIF, compilada para WebAssembly pelo projeto libheif-js — e só a carrega quando você solta o primeiro arquivo, para a página continuar leve.

Para cada arquivo, o conversor:

1. Lê os bytes com a File API e confere na caixa `ftyp` se a marca é HEIF (`heic`, `heix`, `mif1`…); um JPEG renomeado é informado em vez de travar o decodificador.
2. Decodifica a imagem principal com a libheif num bitmap RGBA. A rotação e o espelhamento salvos no arquivo (`irot`, `imir`) são aplicados nesta etapa.
3. Desenha o bitmap num `<canvas>` e o codifica com `canvas.toBlob()` em JPEG na qualidade escolhida, ou em PNG.

### Metadados

Um canvas nunca carrega metadados, então o arquivo convertido sai limpo por padrão. Se você escolher mantê-los, o conversor analisa o próprio contêiner HEIF — a caixa `meta`, a lista de itens (`iinf`) e suas posições (`iloc`) — para achar o item do tipo `Exif` e o insere no JPEG como um segmento **APP1** padrão. Na cópia, a tag `Orientation` é definida como 1 (normal); caso contrário, os visualizadores girariam uma foto que já está em pé. A saída em PNG é sempre gravada sem metadados.

### Download em ZIP

Com mais de um arquivo, **Baixar tudo** carrega uma pequena biblioteca de ZIP (JSZip), adiciona cada arquivo convertido e salva um único pacote. Nomes repetidos recebem um sufixo numérico (`IMG_0001-2.jpg`).

## Casos de uso

- **Enviar fotos do iPhone para quem usa Windows ou para formulários** que só aceitam JPG ou PNG: candidaturas, sinistros de seguro, portais do governo.
- **Publicar na web sem revelar a sua localização.** Converta e remova o EXIF num só passo antes de enviar para um marketplace ou fórum.
- **Arquivar.** Converta para JPG uma pasta de fotos de férias para o notebook antigo de um parente ou um porta-retratos digital.
- **Designers e desenvolvedores** que recebem prints ou protótipos em HEIC e precisam de PNG para a documentação.
- **Imagens sensíveis** — documentos, RG, fotos médicas — que não deveriam passar por um conversor online que você não consegue verificar.
