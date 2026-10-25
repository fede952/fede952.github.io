---
title: "Remover Dados EXIF e GPS de Fotos"
description: "Veja os metadados EXIF escondidos em uma foto (localização GPS, câmera, data) e baixe uma cópia limpa sem eles. Funciona offline no navegador, sem upload."
intro: "O **EXIF Cleaner** mostra os metadados escondidos em uma foto (coordenadas GPS, modelo da câmera, data da captura, software) e entrega uma cópia limpa sem nenhum deles. A imagem nunca sai do seu dispositivo."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["remover dados exif", "remover metadados de foto", "tirar gps da foto", "remover localização da foto", "visualizador exif", "apagar exif online", "metadados de foto", "limpar metadados"]
tags: ["privacidade", "osint", "imagens", "ferramenta"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner: ver e remover metadados"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arraste uma foto para a área de upload ou clique para escolher. JPEG funciona melhor; PNG e WebP também são aceitos."
  - "Leia a tabela **Metadados Encontrados**: marca e modelo da câmera, data da captura, software, exposição, ISO, distância focal, orientação, dimensões, copyright, autor e coordenadas GPS."
  - "Se aparecer um aviso vermelho, a foto contém uma **localização GPS**. As coordenadas decimais mostram o lugar onde ela foi tirada, com precisão de poucos metros."
  - "Clique em **Remover Metadados e Baixar**. A imagem é redesenhada sem nenhum metadado e salva no mesmo formato."
  - "Clique em **Baixar Imagem Limpa** para salvar `seuarquivo-clean.jpg` (ou .png/.webp) e compartilhe essa cópia em vez do original."
faq:
  - q: "O que são dados EXIF?"
    a: "EXIF (Exchangeable Image File Format) é um bloco de metadados que câmeras e celulares gravam em cada foto: marca e modelo do aparelho, lente, configurações de exposição, data e hora, o software usado na edição e muitas vezes as coordenadas GPS do lugar da foto. Não aparece quando você vê a imagem, mas é lido em segundos com ferramentas como esta."
  - q: "As redes sociais removem o EXIF automaticamente?"
    a: "As grandes plataformas, como Facebook, Instagram, X e WhatsApp, removem a maior parte dos metadados das imagens publicadas. Anexos de e-mail, links de armazenamento em nuvem, fóruns, sites de classificados, apps de namoro e muitos mensageiros ao enviar \"como arquivo\" ou \"qualidade original\" não fazem isso. Na dúvida, limpe a foto antes."
  - q: "Minha foto é enviada para remover os metadados?"
    a: "Não. A leitura dos metadados e a criação da cópia limpa acontecem em JavaScript dentro desta página. Você pode desconectar da internet depois que ela carregar e a ferramenta continua funcionando, então serve também para fotos sensíveis."
  - q: "A limpeza diminui a qualidade da imagem?"
    a: "A saída PNG é sem perdas. JPEG e WebP são recodificados com qualidade 95, praticamente igual ao original em quase todas as fotos; o tamanho do arquivo pode mudar um pouco. A resolução continua exatamente a mesma."
  - q: "Por que meu PNG ou WebP não mostra metadados?"
    a: "O visualizador usa a exif-js, que lê o bloco EXIF dos arquivos JPEG. PNG e WebP guardam metadados de outro jeito e raramente têm GPS, então a tabela pode ficar vazia. Mesmo assim a cópia limpa é recodificada a partir dos pixels, portanto qualquer metadado que eles tenham também é descartado."
  - q: "A foto limpa continua na posição certa?"
    a: "Sim. Celulares costumam salvar fotos de lado e dependem da tag EXIF Orientation para girá-las. O navegador aplica esse giro ao desenhar a imagem, então a cópia limpa já tem a orientação correta nos próprios pixels e não precisa mais da tag."
  - q: "Dá para recuperar os metadados removidos a partir da cópia limpa?"
    a: "Não. O arquivo limpo é uma imagem nova criada só a partir dos pixels; o bloco de metadados original nunca é copiado. Guarde o original se você quiser a data e o local no seu acervo de fotos."
---

## Como funciona

### Leitura dos metadados

Quando você solta um arquivo, a página o lê localmente com `FileReader` e o entrega à **exif-js** (v2.3.0, hospedada aqui). A biblioteca percorre o segmento APP1 do JPEG e decodifica os diretórios EXIF com estrutura TIFF: o diretório principal da imagem (marca, modelo, software, orientação, copyright, autor), o subdiretório Exif (tempo de exposição, abertura, ISO, distância focal, flash, dimensões em pixels, espaço de cor) e o diretório GPS.

As coordenadas GPS são guardadas em graus, minutos e segundos, com uma referência de hemisfério (N/S, E/W). A ferramenta converte para graus decimais, `graus + minutos/60 + segundos/3600`, negativos para sul e oeste, e mostra com seis casas decimais, cerca de 10 cm de precisão. Se houver uma posição GPS, aparece o aviso vermelho.

### Criação da cópia limpa

Os metadados não são apagados byte a byte: a ferramenta joga fora o contêiner inteiro.

1. O navegador decodifica a imagem em pixels brutos.
2. Esses pixels são desenhados em resolução total em um `<canvas>` HTML. Ao desenhar, o navegador aplica a orientação EXIF, então o resultado fica na posição certa.
3. O canvas é codificado em um arquivo totalmente novo com `canvas.toBlob()`: **JPEG com qualidade 0,95** para entradas JPEG, **WebP com 0,95** para WebP e **PNG** para todo o resto.

Um canvas só contém pixels, então o arquivo novo **não tem EXIF, nem GPS, nem tags XMP ou IPTC, nem miniatura embutida** (miniaturas antigas às vezes ainda mostram o original *sem corte*) e nenhum perfil de cor. As imagens saem em sRGB, então fotos de gama ampla podem parecer levemente menos saturadas.

Para conferir, arraste de novo para a ferramenta o arquivo `-clean` baixado: a tabela fica vazia e o aviso de GPS não aparece.

### O que ela não muda

A cópia limpa remove *metadados*, não o que aparece na foto. Uma placa de rua, um reflexo em uma vitrine, a placa de um carro ou um ponto turístico reconhecível ainda podem revelar onde a foto foi tirada. Corte ou desfoque esses detalhes antes de compartilhar.

## Casos de uso

- **Vender coisas na internet.** Fotos de objetos tiradas em casa podem conter as coordenadas GPS da sua casa. Limpe antes de enviar para um site de classificados.
- **Mandar fotos para pessoas que você mal conhece**, como um locador, um match de aplicativo de namoro ou um comprador, sem entregar seu endereço e o modelo do seu celular.
- **Jornalismo e ativismo.** Remova localização e detalhes do aparelho de imagens que poderiam identificar uma fonte.
- **Conferir o que você vai compartilhar.** Abra uma foto e veja exatamente o que ela revela; ver a própria rua num mapa pela primeira vez costuma assustar.
- **Praticar OSINT.** Investigadores usam o EXIF como pista. Use o visualizador com imagens de exemplo para aprender o que dá para extrair e por que limpar é importante.
