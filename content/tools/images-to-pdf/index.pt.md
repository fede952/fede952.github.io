---
title: "JPG para PDF: converter imagens grátis"
description: "Junte imagens JPG, PNG e WebP num único PDF no navegador: reordene, gire, escolha A4, Carta ou o tamanho da imagem e margens. Sem upload, sem EXIF."
intro: "Transforme fotos, digitalizações e prints num único **PDF**: solte imagens **JPG, PNG, WebP ou GIF**, coloque-as em ordem, gire as que estiverem tortas, escolha **A4, Carta ou o tamanho da própria imagem** e uma margem, e baixe. As imagens são processadas nesta aba e os dados EXIF e GPS delas nunca vão parar no PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["jpg para pdf", "converter jpg em pdf", "imagem para pdf", "png para pdf", "fotos para pdf", "juntar imagens em pdf", "jpg para pdf sem upload", "webp para pdf"]
tags: ["pdf", "imagens", "privacidade", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Conversor de imagens para PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Solte suas imagens na caixa ou clique para escolhê-las. Cada imagem vira uma página; dá para adicionar mais a qualquer momento."
  - "Coloque as páginas em ordem arrastando as miniaturas ou com **←** e **→**. **⟳** gira uma imagem em 90°, **✕** a remove."
  - "Escolha o **Tamanho da página**: **A4**, **Carta (US Letter)** ou **Igual à imagem** para páginas que correspondam exatamente a cada foto."
  - "Com A4 ou Carta, a orientação **Automática (por imagem)** põe imagens largas em páginas paisagem e altas em páginas retrato; você pode forçar **Retrato** ou **Paisagem**. Escolha uma **Margem** (nenhuma, 1 cm ou 2 cm)."
  - "Defina o **Nome do arquivo** e clique em **Criar PDF e baixar**."
faq:
  - q: "Minhas imagens são enviadas?"
    a: "Não. O navegador decodifica as imagens, desenha-as num canvas e a pdf-lib as coloca num PDF, tudo dentro desta aba. Nada é enviado a um servidor, o que importa para documentos de identidade, recibos e exames médicos."
  - q: "O PDF guarda a localização ou os dados da câmera das minhas fotos?"
    a: "Não. Cada imagem é redesenhada num canvas antes de ser inserida, e um canvas não carrega metadados; campos EXIF como posição GPS, data e modelo da câmera não ficam no PDF. O PDF recebe apenas metadados técnicos básicos da biblioteca."
  - q: "Por que as fotos do celular ficam na posição certa?"
    a: "Celulares costumam salvar as fotos deitadas e registrar a rotação correta numa tag EXIF. A ferramenta lê a imagem com essa orientação já aplicada antes de desenhá-la, então a página fica igual à foto da sua galeria. Use ⟳ se uma digitalização continuar girada."
  - q: "As imagens perdem qualidade?"
    a: "As fotos são recodificadas em JPEG de alta qualidade (92%), visualmente idêntico para impressão e documentos. Imagens PNG, WebP e GIF são gravadas sem perdas em PNG, mantendo textos nítidos e áreas transparentes."
  - q: "Qual será o tamanho do PDF?"
    a: "Mais ou menos o das imagens que você adicionar. Fotos muito grandes geram PDFs grandes; se o arquivo precisa ser pequeno para um formulário, comprima as fotos antes, por exemplo com um compressor de imagens, e depois converta."
  - q: "Posso converter fotos HEIC do iPhone?"
    a: "A maioria dos navegadores não lê HEIC diretamente. Converta as fotos para JPG antes com o conversor de HEIC deste site — também offline no navegador — e depois adicione os JPGs aqui."
  - q: "O que significa \"Igual à imagem\"?"
    a: "A página fica do tamanho da foto a 96 pixels por polegada, mais a margem. É a melhor escolha para prints e desenhos que não devem ser ajustados a um formato de papel."
---

## Como funciona

### Da imagem à página

Para cada imagem, a ferramenta:

1. Decodifica com `createImageBitmap(file, { imageOrientation: 'from-image' })`, para respeitar a orientação EXIF das fotos de celular.
2. Desenha num `<canvas>` aplicando a sua rotação e codifica de novo: em **JPEG com 92% de qualidade** para fotos JPG, ou em **PNG** para origens PNG, WebP e GIF, preservando transparência e bordas nítidas. Dos GIFs é usado o primeiro quadro.
3. Insere o resultado no PDF com a **pdf-lib** (`embedJpg` / `embedPng`).

### Layout da página

O A4 mede 595 × 842 pontos e o Carta 612 × 792 pontos (1 ponto = 1/72 de polegada). A imagem é redimensionada para caber na página menos a margem de cada lado, mantendo a proporção, e centralizada. Com a orientação automática, a página fica em paisagem sempre que a imagem é mais larga do que alta. Com **Igual à imagem**, a página tem o tamanho da imagem a 96 DPI — um print de 1920 × 1080 dá uma página de 1440 × 810 pontos — mais a margem.

### Bibliotecas

A pdf-lib (MIT) é carregada deste site só quando você cria o PDF; a grade de miniaturas usa a decodificação de imagens do próprio navegador. Nada é pedido a servidores de terceiros.

## Casos de uso

- **Enviar digitalizações de documentos em papel** — recibos, contratos, tarefas escolares — como um único PDF que qualquer escritório consegue abrir.
- **Enviar documentos de identidade ou holerites** para um formulário que só aceita PDF, sem passar antes por um conversor online.
- **Montar um portfólio ou um álbum** de JPGs na ordem que você quiser.
- **Arquivar prints** de uma configuração, de um erro ou de uma conversa num único arquivo datado.
- **Preparar páginas prontas para impressão** em A4 ou Carta com margens uniformes.
