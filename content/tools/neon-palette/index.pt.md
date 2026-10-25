---
title: "Conversor HEX, RGB e HSL + Paletas Neon"
description: "Converta cores entre HEX, RGB e HSL com seletor e cópia em um clique, e gere paletas neon cyberpunk aleatórias para interfaces, pôsteres e temas. Grátis."
intro: "O **NeonPalette** converte qualquer cor entre **HEX, RGB e HSL** enquanto você escolhe ou digita, e gera **paletas neon** aleatórias de três cores: ciano, magenta, azul elétrico, rosa choque e companhia, pensadas para interfaces cyberpunk escuras."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["converter hex para rgb", "rgb para hsl", "conversor hex hsl", "conversor de cores", "paleta de cores neon", "paleta cyberpunk", "seletor de cores online", "cores neon hex"]
tags: ["design", "css", "cores", "ferramenta"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette, conversor de cores e gerador de paletas"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Escolha uma cor no seletor ou digite um código HEX de seis dígitos como `#00E5FF` no campo HEX."
  - "Os campos RGB e HSL e a barra de pré-visualização atualizam na hora."
  - "Clique no botão de copiar ao lado de HEX, RGB ou HSL para copiar essa notação, pronta para CSS."
  - "Clique em **Gerar Paleta Neon** para receber três cores neon aleatórias de famílias de tom diferentes."
  - "Clique em qualquer cartão da paleta para carregar a cor no conversor e copiá-la no formato de que precisa."
faq:
  - q: "Como converter HEX para RGB?"
    a: "Uma cor HEX são três bytes escritos em hexadecimal: `#RRGGBB`. Converta cada par para decimal: `#00E5FF` é vermelho 0x00 = 0, verde 0xE5 = 229, azul 0xFF = 255, ou seja, `rgb(0, 229, 255)`. A forma curta de três dígitos como `#0EF` duplica cada dígito antes (`#00EEFF`)."
  - q: "O que é HSL e por que usar?"
    a: "HSL descreve uma cor por matiz (0–360° no círculo cromático), saturação (de 0% cinza a 100% viva) e luminosidade (de 0% preto a 100% branco). É mais intuitivo que RGB: para uma versão mais clara ou mais apagada de uma cor você muda um número em vez de três."
  - q: "O que faz uma cor parecer neon?"
    a: "Saturação bem alta e luminosidade média sobre fundo escuro. O gerador mantém a saturação entre 85% e 100% e a luminosidade entre 45% e 60%, a faixa em que as cores parecem mais luminosas; mais claras puxam para o pastel e mais escuras perdem o brilho."
  - q: "Cores neon são acessíveis?"
    a: "Em fundo escuro, ciano, verde e amarelo neon costumam passar no contraste WCAG para texto grande, enquanto azuis, violetas e magentas saturados muitas vezes não. Use o neon em destaques, bordas e títulos, deixe o texto corrido quase branco e confira o contraste de cada par texto/fundo."
  - q: "Posso digitar valores RGB ou HSL?"
    a: "O conversor recebe a entrada do seletor e do campo HEX; os campos RGB e HSL mostram o resultado para copiar. Para começar de RGB, converta para HEX ou ajuste no seletor de cores, que aceita valores RGB na maioria dos navegadores."
  - q: "Algo é salvo ou enviado?"
    a: "Não. Todas as conversões são aritmética em JavaScript dentro desta página, e as paletas são geradas localmente com `Math.random()`."
---

## Como funciona

### Conversões

**HEX → RGB.** Os seis dígitos hexadecimais são lidos como um único inteiro de 24 bits e os três canais são extraídos com deslocamento de bits: vermelho = `(n >> 16) & 255`, verde = `(n >> 8) & 255`, azul = `n & 255`.

**RGB → HSL.** Cada canal é escalado para 0–1. Com *max* e *min* sendo o maior e o menor dos três:

- **Luminosidade** L = (max + min) / 2.
- **Saturação** S = 0 para cinzas; senão (max − min) / (max + min) quando L ≤ 0,5, ou (max − min) / (2 − max − min) quando L > 0,5.
- **Matiz**: depende de qual canal é o maior: para o vermelho é (G − B) / (max − min), para o verde 2 + (B − R) / (max − min), para o azul 4 + (R − G) / (max − min), multiplicado por 60° e trazido para 0–360°.

O matiz é arredondado para graus inteiros e S e L para porcentagens inteiras, a precisão com que normalmente se escreve `hsl()` em CSS.

| Cor | HEX | RGB | HSL |
|---|---|---|---|
| Ciano neon | `#00E5FF` | 0, 229, 255 | 186°, 100%, 50% |
| Magenta vibrante | `#FF2DCE` | 255, 45, 206 | 314°, 100%, 59% |
| Verde ácido | `#39FF14` | 57, 255, 20 | 111°, 100%, 54% |

### O gerador neon

O gerador conhece oito famílias de matiz: ciano (170–195°), magenta (290–330°), azul elétrico (210–250°), verde neon (100–150°), rosa choque (330–355°), violeta (260–290°), laranja neon (15–40°) e amarelo neon (50–70°). A cada clique ele embaralha as famílias, pega três e, para cada uma, sorteia um matiz dentro da faixa, uma saturação de 85–100% e uma luminosidade de 45–60%. Os valores HSL são convertidos para HEX pela fórmula por partes padrão, então as três cores são sempre de famílias diferentes, mas têm o mesmo caráter vivo e brilhante.

## Casos de uso

- **CSS e design tokens.** Converta um HEX da marca em `rgb()` para brincar com opacidade ou em `hsl()` para montar variações mais claras e mais escuras.
- **Interfaces escuras e cyberpunk.** Gere cores de destaque para botões, bordas, brilhos e gráficos em fundos escuros.
- **Pôsteres, miniaturas e overlays de live** com visual synthwave ou de letreiro neon.
- **Temas de jogos e apps.** Escolha três destaques neon complementares para um HUD, uma fase ou um tema de terminal.
- **Aprender modelos de cor.** Veja como HEX, RGB e HSL descrevem a mesma cor e como mudar só o matiz faz você girar o círculo.
