---
title: "Laboratorio de Esteganografia"
description: "Esconda texto secreto dentro de imagens usando codificacao LSB (Bit Menos Significativo). Codifique e decodifique mensagens ocultas, exporte como PNG. 100% lado cliente, sem uploads."
image: "/images/tools/stego-tool.png"
date: 2026-02-05
hidemeta: true
showToc: false
keywords: ["esteganografia", "esconder texto em imagem", "codificacao LSB", "mensagem secreta", "esteganografia de imagem", "codificar decodificar", "dados ocultos", "esteganografia png", "ferramenta privacidade", "comunicacao secreta"]
draft: false
---

A esteganografia e a arte de esconder informacoes a vista de todos — incorporar dados secretos dentro de midias de aparencia inocente para que sua propria existencia permaneca indetectada. Ao contrario da criptografia, que transforma dados em texto cifrado obvio, a esteganografia oculta o *fato* de que um segredo existe. Esta tecnica tem sido usada por seculos, desde tinta invisivel em papel ate micropontos durante a Segunda Guerra Mundial, e agora vive no reino digital.

**Laboratorio de Esteganografia** usa codificacao LSB (Bit Menos Significativo) para esconder texto dentro de imagens. Ao modificar o bit menos significativo de cada canal de cor (RGB), a ferramenta pode incorporar milhares de caracteres em uma imagem com mudancas imperceptiveis ao olho humano. Carregue qualquer imagem, digite sua mensagem secreta e baixe um PNG com os dados ocultos dentro. Para recuperar a mensagem, simplesmente carregue o PNG codificado na aba "Revelar". Tudo roda localmente no seu navegador — sem servidor, sem uploads, privacidade completa.

<iframe src="/tools/steganography/index.html" width="100%" height="900px" style="border:none; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);" sandbox="allow-scripts allow-same-origin allow-downloads allow-popups"></iframe>
