---
title: "Esconder Texto numa Imagem (LSB)"
description: "Esconda uma mensagem secreta dentro de uma imagem com esteganografia LSB e revele-a depois. Exporta PNG sem perdas; tudo no navegador, sem nenhum upload."
intro: "O **Steganography Lab** esconde uma mensagem de texto nos pixels de uma imagem e a lê de volta depois. A foto parece idêntica, porque cada valor de cor muda no máximo 1 em 255. Tudo acontece no seu navegador: a imagem e a mensagem nunca saem do seu dispositivo."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["esteganografia online", "esconder texto em imagem", "esteganografia lsb", "mensagem escondida em foto", "decodificar mensagem oculta", "esteganografia png", "mensagem secreta em imagem", "ferramenta de esteganografia"]
tags: ["privacidade", "segurança", "imagens", "ferramenta"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Na aba **Esconder Mensagem**, solte uma imagem ou clique para escolher (JPG, PNG, WebP ou GIF). A ferramenta mostra o tamanho e quantos bytes ela comporta."
  - "Digite ou cole sua mensagem. A barra de capacidade enche conforme você digita e fica laranja, depois vermelha, perto do limite."
  - "Clique em **Codificar e Baixar PNG**. Um arquivo `stego_<timestamp>.png` é salvo, visualmente idêntico ao original."
  - "Envie esse PNG **como arquivo** (anexo de e-mail, link na nuvem, \"enviar como documento\"), não como foto que um app de mensagens vai recomprimir."
  - "Para ler, abra a aba **Revelar Mensagem**, carregue o PNG e clique em **Decodificar Mensagem Oculta**. Use **Copiar Texto** para pegar o resultado."
faq:
  - q: "A mensagem escondida é criptografada?"
    a: "Não. A esteganografia esconde que a mensagem existe, mas não protege o conteúdo. Quem carregar o PNG nesta ferramenta, ou conhecer o esquema, consegue ler. Para algo sensível, criptografe o texto antes (por exemplo com age ou GPG) e esconda o texto cifrado."
  - q: "Por que a saída precisa ser PNG?"
    a: "O PNG não tem perdas: cada valor de pixel é salvo exatamente como foi escrito. JPEG e WebP com perdas requantizam as cores ao salvar e embaralham justamente os bits baixos onde a mensagem fica. Por isso a aba de revelar só aceita PNG."
  - q: "A mensagem sumiu depois que enviei a imagem. Por quê?"
    a: "A maioria dos apps de mensagens e redes sociais redimensiona e recomprime fotos, e uma captura de tela redesenha os pixels. Qualquer uma dessas coisas destrói os bits escondidos. Envie o PNG como arquivo ou documento para que chegue intacto byte a byte."
  - q: "Quanto texto cabe numa imagem?"
    a: "Três bits por pixel totalmente opaco, menos 19 bytes de cabeçalho e terminador. Uma foto 1920×1080 comporta cerca de 777.000 bytes. O contador é em bytes UTF-8: letras acentuadas usam dois e muitos emoji, quatro."
  - q: "Ferramentas de esteganálise conseguem detectar?"
    a: "Sim. A inserção LSB sequencial é o caso clássico que testes estatísticos como qui-quadrado e análise RS detectam, principalmente quando boa parte da capacidade é usada. Use como ferramenta de aprendizado e privacidade leve, não para comunicação secreta contra um adversário capaz."
  - q: "Funciona com PNG transparente?"
    a: "Sim. Só os pixels totalmente opacos carregam dados, porque o navegador guarda pixels semitransparentes de forma pré-multiplicada e os bits baixos deles não sobreviveriam. As áreas transparentes ficam intactas e apenas reduzem a capacidade."
  - q: "Minha imagem é enviada para algum lugar?"
    a: "Não. O arquivo é lido com a API FileReader e processado num canvas dentro da aba do navegador. Não existe servidor: você pode carregar a página, ficar offline e ela continua funcionando."
---

## Como funciona

A técnica é a **substituição do bit menos significativo (LSB)**, a forma clássica de esteganografia em imagens (há uma explicação mais longa no [guia Esteganografia 101](/pt/learn/guides/steganography-101-hidden-messages/)).

**1. Montar a carga.** Seu texto é codificado em UTF-8 e envolvido assim:

```
STEGO_V1::<sua mensagem>\0\0\0END\0\0\0
```

O prefixo `STEGO_V1::` permite ao decodificador saber na hora se uma imagem carrega uma mensagem; o marcador `END` cercado de bytes nulos indica onde ela termina.

**2. Ler os pixels.** A imagem é desenhada num canvas HTML no tamanho natural, com suavização desligada, e `getImageData()` devolve cada pixel como bytes de vermelho, verde, azul e alfa.

**3. Um bit por canal de cor.** Os bits da carga, do mais significativo para o menos, são escritos um a um no bit mais baixo dos bytes R, G e B de cada pixel totalmente opaco, em ordem de leitura a partir do canto superior esquerdo. Cada byte vira `(valor & 0xFE) | bit`: um canal muda 0 ou 1 e a diferença é invisível. O alfa nunca é alterado, e pixels que não são totalmente opacos são pulados, porque o canvas pré-multiplica as cores deles e os bits baixos se perderiam.

**4. Exportar sem perdas.** O canvas modificado é salvo com `toBlob('image/png')`. Efeito colateral: a saída **não tem metadados EXIF** (câmera, GPS, data), já que o canvas só conhece pixels.

**5. Decodificar.** A aba Revelar faz o inverso: junta os bits baixos dos mesmos canais, reconstrói os bytes e compara os dez primeiros com `STEGO_V1::`. Se não baterem, para na hora, então uma foto grande e limpa é descartada quase instantaneamente; se baterem, lê até o marcador final e converte os bytes de volta em texto.

| Imagem | Pixels opacos | Capacidade |
|---|---|---|
| 800×600 | 480.000 | ≈ 179.981 bytes |
| 1920×1080 | 2.073.600 | ≈ 777.581 bytes |
| 4000×3000 | 12.000.000 | ≈ 4,5 MB |

Quanto mais capacidade você usa, mais fácil fica sinalizar a imagem com esteganálise estatística. Uma mensagem curta numa foto grande e com ruído é bem mais difícil de detectar que uma longa num gráfico de cores chapadas.

## Casos de uso

- **Aprender e ensinar.** Veja exatamente o que a inserção LSB faz e depois tente quebrá-la: recomprima o PNG como JPEG e veja a mensagem sumir.
- **Treino para CTF.** Desafios de esteganografia costumam esconder flags nos LSB; codificar suas próprias amostras deixa o padrão fácil de reconhecer em ferramentas como `zsteg` ou StegSolve.
- **Marcar suas próprias imagens.** Insira uma nota (autor, data) num PNG que você compartilha como arquivo. Ela não sobrevive a edições, mas prova que uma cópia está intacta.
- **Um segredo por diversão.** Esconda uma mensagem numa foto de viagem para um amigo que saiba onde procurar.
- **Transportar texto já criptografado.** Cole um texto cifrado (por exemplo saída do GPG em ASCII armor) e tenha sigilo e discrição ao mesmo tempo.

Para o trabalho oposto, remover dados escondidos nos metadados de uma foto em vez dos pixels, use o [EXIF Cleaner](/pt/tools/exif-cleaner/).
