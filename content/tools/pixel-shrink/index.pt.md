---
title: "Comprimir Imagem Online: JPG, PNG, WebP"
description: "Reduza o tamanho de imagens JPG, PNG e WebP no navegador: qualidade, tamanho alvo e largura máxima, conversão para WebP. Sem upload e sem cadastro."
intro: "O **PixelShrink** comprime e converte imagens no seu próprio dispositivo. Arraste uma foto, escolha a qualidade, um tamanho alvo ou uma largura máxima e baixe um JPG, PNG ou WebP mais leve. A imagem nunca é enviada."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["comprimir imagem", "reduzir tamanho de imagem", "compressor de imagens online", "comprimir jpg", "comprimir png", "converter para webp", "redimensionar imagem", "comprimir foto sem upload"]
tags: ["imagens", "compressão", "privacidade", "ferramenta"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink, compressor de imagens"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arraste uma imagem para a área de upload ou clique para escolher um arquivo. São aceitos PNG, JPEG, WebP e AVIF; a pré-visualização mostra o tamanho do arquivo e as dimensões."
  - "Escolha o **formato de saída**: manter o original ou converter para JPEG, PNG ou WebP. Para fotos, o WebP costuma ser o menor."
  - "Ajuste a **qualidade** (1–100, padrão 75), um **tamanho máximo** em MB e uma **largura máxima** em pixels: o lado maior é reduzido a esse valor mantendo a proporção."
  - "Clique em **Comprimir Imagem**. O painel antes/depois mostra os dois tamanhos, as duas dimensões e a porcentagem economizada."
  - "Clique em **Baixar Imagem Comprimida** para salvar o resultado. Se ele não ficar menor que o original, a ferramenta avisa: mantenha o original ou tente outro formato."
faq:
  - q: "Minhas imagens são enviadas para um servidor?"
    a: "Não. A imagem é decodificada, redimensionada e recodificada dentro do seu navegador, em um Web Worker em segundo plano. Nada é enviado: depois que a página carrega, você pode ficar offline e ela continua funcionando. Por isso é seguro também para capturas de documentos, RG ou qualquer coisa particular."
  - q: "Que qualidade devo usar?"
    a: "Para fotos, 70–80 é o ponto ideal: o arquivo diminui bastante e no tamanho normal mal dá para ver diferença. Desça para 50–60 em miniaturas e pré-visualizações. Acima de 90, o arquivo cresce rápido sem ganho visível."
  - q: "Vale a pena converter para WebP?"
    a: "Para a web, geralmente sim. Arquivos WebP costumam ser 25–35% menores que um JPEG de qualidade parecida, e todos os navegadores atuais exibem o formato. Fique no JPEG quando a imagem for para um sistema que só aceita JPG, como alguns formulários ou serviços de impressão."
  - q: "Por que meu PNG ficou maior?"
    a: "PNG é sem perdas, então uma fotografia salva em PNG muitas vezes fica maior que o JPEG original. O PixelShrink reduz PNGs limitando a paleta de cores, o que funciona muito bem para capturas de tela, logotipos e gráficos chapados e mal para fotos. Para fotos, escolha WebP ou JPEG."
  - q: "Consigo comprimir uma imagem abaixo de um tamanho exato, como 200 KB?"
    a: "Defina o **Tamanho máximo** como 0,2 MB. Se a primeira codificação ficar maior, a biblioteca repete o processo até 10 vezes, baixando um pouco a qualidade e as dimensões a cada passada, e para assim que o arquivo couber. Com imagens muito grandes ou detalhadas, reduza também a largura máxima."
  - q: "A compressão remove os dados EXIF e a localização GPS?"
    a: "Sim. A imagem é redesenhada em um canvas e codificada de novo sem copiar os metadados, então somem campos EXIF como modelo da câmera, data e coordenadas GPS. Se você quer só tirar os metadados sem recomprimir, use o EXIF Cleaner."
  - q: "Por que não existe saída em AVIF?"
    a: "A saída é gerada pelo codificador de imagens do próprio navegador, e a maioria dos navegadores consegue exibir AVIF mas não criá-lo a partir de um canvas. O PixelShrink testa isso ao carregar e só mostra a opção AVIF se o seu navegador realmente souber codificar, em vez de gerar escondido um PNG com extensão .avif."
---

## Como funciona

O PixelShrink é uma interface leve sobre a [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, hospedada neste site). Quando você clica em Comprimir, o trabalho vai para um **Web Worker**, e a página continua respondendo mesmo com uma foto de 20 megapixels.

1. **Decodificar.** O arquivo é decodificado em bitmap com `createImageBitmap` (ou com um elemento `<img>` como alternativa), e a orientação EXIF é aplicada para que fotos em retrato não saiam giradas.
2. **Redimensionar.** Se o lado maior passar da *largura máxima*, a imagem é desenhada em um canvas menor com a mesma proporção. Uma foto de 6000 × 4000 com limite de 2048 px vira 2048 × 1365.
3. **Codificar.** JPEG e WebP são codificados pelo navegador (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) com a sua configuração de qualidade. O PNG passa pelo **UPNG.js**, que quantiza a imagem para uma paleta de no máximo 4096 × qualidade cores (3.072 cores no padrão 75) antes de gravar um PNG sem perdas: é o truque que reduz pela metade ou mais capturas de tela e gráficos de interface.
4. **Caber no tamanho alvo.** Se o resultado ainda passar do *tamanho máximo*, a codificação é repetida até **10 vezes**. A cada passada a qualidade é multiplicada por 0,95 (0,85 para PNG) e as dimensões podem ser reduzidas por 0,95, até o arquivo caber ou as passadas acabarem.

O painel antes/depois compara o arquivo original com o resultado, e o download é uma URL local `blob:` chamada `seuarquivo-compressed.<formato>`. Como a imagem é recodificada a partir dos pixels, **metadados como EXIF e GPS não são mantidos**.

### Qual formato escolher

| Conteúdo | Melhor formato | Por quê |
|---|---|---|
| Fotos para site ou blog | WebP, qualidade 70–80 | Arquivos menores, suportados por todos os navegadores |
| Fotos para e-mail, formulários, impressão | JPEG, qualidade 75–85 | Aceito em todo lugar |
| Capturas de tela, diagramas, logotipos | PNG ou WebP | Bordas nítidas e cores chapadas comprimem bem |
| Imagens com transparência | PNG ou WebP | JPEG não tem canal alfa |

O **AVIF** só aparece quando o navegador consegue realmente *codificá-lo* a partir de um canvas. Hoje a maioria não consegue, e o PixelShrink testa isso ao carregar em vez de adivinhar.

## Casos de uso

- **Páginas web mais rápidas.** Imagens de destaque grandes demais são a causa mais comum de um Largest Contentful Paint ruim. Converter um JPEG de 3 MB em um WebP de 2000 px com qualidade 75 muitas vezes fica abaixo de 300 KB.
- **Limites de upload.** Portais do governo, sites de vagas e chamados de suporte costumam limitar anexos a 1 ou 2 MB. Defina o tamanho máximo e deixe a ferramenta achar a qualidade que cabe.
- **E-mail e chat.** Mande cinco fotos das férias em vez de uma quando cada uma tem um décimo do tamanho original.
- **Documentos particulares.** Reduza o scan de um documento de identidade ou de um contrato sem entregá-lo a um serviço online que você não conhece.
- **Recursos de apps e jogos.** Converta sprites PNG ou capturas em arquivos menores antes de colocá-los em um repositório.
