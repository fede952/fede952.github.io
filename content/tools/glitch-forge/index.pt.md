---
title: "Efeito Glitch para Fotos Online"
description: "Aplique efeitos glitch em fotos: RGB shift, pixel sorting, scanlines e ruído digital, com presets VHS e cyberpunk. PNG em resolução total, sem upload."
intro: "O **GlitchForge** transforma uma foto em glitch art: separação cromática RGB, pixel sorting, scanlines de CRT e ruído digital, dosados com quatro controles ou presets de um clique. A imagem é processada em um canvas no seu navegador e exportada como PNG em resolução total."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["efeito glitch", "glitch art online", "efeito rgb split", "pixel sorting online", "efeito vhs foto", "efeito cyberpunk foto", "efeito aberração cromática", "foto glitch"]
tags: ["imagens", "design", "criatividade", "ferramenta"]
app_category: "MultimediaApplication"
tool_file: "/tools/glitch-forge/"
tool_title: "GlitchForge, gerador de glitch art"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arraste um JPEG, PNG ou WebP para a área do canvas ou clique para escolher um arquivo."
  - "Teste primeiro um preset: **VHS**, **Cyberpunk**, **Corrupt** ou **Subtle**."
  - "Ajuste com os controles: **Amount** (contraste, ruído e rasgos), **RGB Shift**, **Scanlines** e **Pixel Sort**. A pré-visualização se atualiza enquanto você arrasta."
  - "Clique em **Download Cyberpunk Image** para salvar `glitchforge-export.png` na resolução original."
  - "Clique em **Reset Image** para zerar todos os controles e recomeçar."
faq:
  - q: "Minha foto é enviada para algum lugar?"
    a: "Não. A imagem é desenhada em um canvas HTML e cada efeito é calculado sobre os pixels em JavaScript, no seu navegador. Nada vai para servidor nenhum, então dá para usar com fotos pessoais sem problema."
  - q: "Qual a resolução do download?"
    a: "A original. A pré-visualização é reduzida para caber na tela, mas a exportação redesenha a imagem com largura e altura totais, aplica as mesmas configurações e salva um PNG sem perdas."
  - q: "Por que o download fica um pouco diferente da pré-visualização?"
    a: "O ruído e os rasgos horizontais são aleatórios e são gerados de novo na exportação, em outro tamanho. O estilo do efeito é o mesmo, mas os pixels de ruído e a posição das faixas mudam, como acontece toda vez que você mexe num controle."
  - q: "O que é pixel sorting?"
    a: "Um efeito popularizado por artistas glitch como Kim Asendorf: os pixels de uma região são reordenados por brilho, e as áreas claras se esticam em faixas. O GlitchForge ordena na vertical os trechos de pixels claros, então as luzes escorrem para baixo enquanto as áreas escuras ficam intactas."
  - q: "O que é o efeito RGB shift?"
    a: "Ele imita aberração cromática ou um sinal analógico desalinhado: o canal vermelho é deslocado para a direita e o azul para a esquerda, deixando franjas coloridas em todas as bordas. Na intensidade máxima, o deslocamento é de 4% da largura da imagem."
  - q: "Posso usar as imagens comercialmente?"
    a: "O resultado é a sua própria foto transformada por um algoritmo, então os direitos são os da imagem original. A ferramenta não adiciona marca d'água nem reivindica nada sobre o resultado."
---

## Como funciona

Ao carregar um arquivo, a imagem é desenhada em um canvas redimensionado para a pré-visualização e uma cópia limpa dos pixels (`getImageData`) é guardada. A cada movimento de controle, os efeitos são aplicados a uma cópia nova desses pixels, nesta ordem:

1. **Amount: contraste e ruído.** Cada canal de cor é afastado do cinza médio por um fator de contraste de até 1,6×, depois um ruído aleatório de até ±20 níveis é somado e o valor é limitado a 0–255.
2. **RGB shift.** O buffer de pixels é copiado; para cada pixel, o vermelho é lido de um pixel *shift* colunas à esquerda e o azul de *shift* colunas à direita, com *shift* = RGB × 4% da largura. O verde fica no lugar, e daí surgem as franjas vermelhas e azuis.
3. **Pixel sort.** Uma coluna a cada duas é percorrida de cima para baixo. Onde a luminância (0,299 R + 0,587 G + 0,114 B, os pesos Rec. 601) passa de um limite de 1 − Sort, o trecho de pixels claros, limitado a metade da altura × Sort, é recolhido e reordenado do mais escuro para o mais claro.
4. **Scanlines.** Linhas pretas horizontais de um pixel, a cada 2–4 pixels, são desenhadas por cima com opacidade de até 50%, como numa tela CRT.
5. **Rasgos.** Quando Amount passa de 25%, até oito faixas horizontais finas e aleatórias são copiadas e deslocadas para o lado: o clássico "tracking" de fita VHS.

Os presets são só posições dos controles:

| Preset | Amount | RGB | Scanlines | Sort |
|---|---|---|---|---|
| VHS | 45 | 60 | 70 | 10 |
| Cyberpunk | 65 | 80 | 40 | 35 |
| Corrupt | 85 | 50 | 20 | 90 |
| Subtle | 20 | 25 | 15 | 5 |

A renderização é agendada com `requestAnimationFrame`, então arrastar um controle redesenha no máximo uma vez por quadro. Para o download, um segundo canvas no tamanho original roda a mesma sequência de efeitos e é salvo com `toDataURL('image/png')`.

## Casos de uso

- **Capas de álbum, pôsteres e miniaturas** com visual synthwave, VHS ou cyberpunk, sem abrir um editor pesado.
- **Posts em redes sociais.** Uma foto de perfil com glitch ou um fundo de story chama atenção no feed.
- **Recursos para jogos e apps.** Crie fundos de tela corrompida, telas de erro ou texturas de interface "hackeada".
- **Exploração de design.** Pixel sorting e deslocamento de canais geram rapidinho texturas abstratas a partir de fotos comuns.
- **Ensinar processamento de imagem.** Cada controle é uma operação clássica sobre pixels; ligá-los um a um mostra que uma imagem é só uma matriz de números.
