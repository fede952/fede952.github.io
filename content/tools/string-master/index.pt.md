---
title: "Contador de Palavras e Maiúsculas"
description: "Conte palavras, caracteres, linhas e tempo de leitura ao vivo; mude maiúsculas, remova linhas duplicadas, limpe espaços ou passe o texto para leetspeak."
intro: "O **StringMaster** é uma pequena bancada de texto. Cole qualquer coisa e ele conta palavras, caracteres, linhas e tempo de leitura enquanto você digita; com um clique muda maiúsculas e minúsculas, remove linhas duplicadas, limpa espaços ou transforma o texto em leetspeak. O texto fica na aba do seu navegador."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["contador de palavras", "contador de caracteres", "ferramentas de texto online", "converter maiúsculas minúsculas", "remover linhas duplicadas", "remover espaços online", "conversor leetspeak", "tempo de leitura"]
tags: ["texto", "ferramentas-dev", "escrita", "ferramenta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster, ferramentas de texto"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Cole ou digite seu texto na caixa **Entrada**. **Palavras**, **Caracteres**, **Linhas** e **Tempo Leitura** se atualizam a cada tecla."
  - "Clique em **Maiúsculas** ou **Minúsculas** para converter o texto inteiro."
  - "Clique em **Remover Duplicados** para manter só a primeira ocorrência de cada linha, ou em **Recortar Espaços** para tirar espaços nas pontas das linhas e juntar linhas vazias."
  - "Clique em **Modo Hacker** para reescrever o texto em leetspeak (`hello` → `h3110`)."
  - "Clique em **Copiar** para mandar o resultado para a área de transferência. As transformações substituem o texto, então copie o original antes se puder precisar dele."
faq:
  - q: "Como as palavras são contadas?"
    a: "O texto é dividido em qualquer sequência de espaços em branco (espaços, tabulações, quebras de linha): `guarda-chuva` é uma palavra e `p. ex. isto` são três. Idiomas escritos sem espaços, como chinês ou japonês, contam uma palavra por bloco, então para eles use a contagem de caracteres."
  - q: "Emoji e letras acentuadas contam como um caractere?"
    a: "Sim. O contador usa o segmentador de grafemas do navegador (`Intl.Segmenter`), então 👍, ã e até um emoji de \"família\" formado por vários code points contam uma vez, como você vê. Algumas plataformas, como SMS, contam de outro jeito (em unidades UTF-16 ou bytes) e chegam ao limite antes."
  - q: "Como o tempo de leitura é estimado?"
    a: "Número de palavras dividido por 200 palavras por minuto, uma média comum para leitura na tela, arredondado para cima. Abaixo de um minuto mostra segundos (`45s`) e acima, minutos inteiros (`4m`). Textos técnicos ou densos costumam ser lidos mais devagar."
  - q: "Remover Duplicados diferencia maiúsculas?"
    a: "Sim, e a comparação é exata: `Maçã`, `maçã` e `maçã ` (com espaço no fim) são três linhas diferentes. Use antes **Recortar Espaços** e **Minúsculas** se quiser uma comparação mais flexível. A ordem das primeiras ocorrências é mantida, e linhas vazias repetidas também viram uma só."
  - q: "Posso desfazer uma transformação?"
    a: "Não há botão de desfazer e, como o texto é substituído por script, o Ctrl+Z nem sempre o recupera em todos os navegadores. Minúsculas, Remover Duplicados, Recortar Espaços e Modo Hacker perdem informação, então guarde uma cópia do original."
  - q: "Dá para converter o leetspeak de volta?"
    a: "Não de forma confiável. Tanto `i` quanto `l` viram `1`, e os dígitos que já estavam no texto não se distinguem das letras substituídas. O Modo Hacker é um efeito de estilo de mão única, não uma codificação."
  - q: "Meu texto é enviado para algum lugar?"
    a: "Não. Contagens e transformações são JavaScript simples dentro da página; nada é salvo nem transmitido. Pode usar tranquilamente com rascunhos, logs ou documentos internos."
---

## Como funciona

Cada tecla pressionada na caixa dispara a mesma pequena análise:

- **Palavras** = número de blocos não vazios depois de dividir o texto (sem espaços nas pontas) nos espaços em branco (`/\s+/`).
- **Caracteres** = número de clusters de grafemas, os caracteres que uma pessoa contaria, via `Intl.Segmenter`; navegadores sem suporte contam code points Unicode. Espaços e quebras de linha contam como caracteres.
- **Linhas** = número de linhas separadas por quebras de linha. Uma caixa vazia mostra 0, e uma quebra no final acrescenta uma última linha vazia.
- **Tempo Leitura** = ⌈palavras ÷ 200 × 60⌉ segundos, em segundos abaixo de um minuto e em minutos arredondados para cima acima disso.

Cada botão aplica uma transformação ao texto inteiro e depois conta de novo:

| Botão | O que faz | Exemplo |
|---|---|---|
| **Maiúsculas** | Maiúsculas Unicode (`toUpperCase`) | `straße` → `STRASSE` |
| **Minúsculas** | Minúsculas Unicode (`toLowerCase`) | `OlÁ` → `olá` |
| **Remover Duplicados** | Mantém a primeira cópia de cada linha idêntica, em ordem | `a, b, a, c` → `a, b, c` |
| **Recortar Espaços** | Apara cada linha, permite no máximo uma linha vazia seguida e apara as pontas | `··texto··` → `texto` |
| **Modo Hacker** | Troca a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Copiar** | Copia o texto com a Clipboard API | — |

Dois detalhes úteis. A conversão de maiúsculas não depende do idioma, então o *i* turco com e sem ponto segue as regras Unicode genéricas. Recortar Espaços só mexe nas pontas das linhas e nas linhas vazias: espaços duplos *dentro* de uma linha ficam, o que mantém a indentação do código e as tabelas legíveis.

## Casos de uso

- **Escrever dentro de um limite.** Confira redações, meta descriptions, resumos ou posts em redes sociais contra um limite de palavras ou caracteres enquanto edita.
- **Limpar listas.** Cole uma coluna de e-mails, hostnames ou IDs exportada de uma planilha e remova duplicados com um clique; passe antes para minúsculas dados como endereços de e-mail.
- **Arrumar logs e saídas coladas.** Tire espaços no fim das linhas e junte as linhas vazias da saída do terminal antes de colar num chamado ou documento.
- **Normalizar identificadores.** Coloque tags ou chaves em minúsculas antes de comparar, ou constantes e palavras-chave SQL em maiúsculas.
- **Texto por diversão.** Transforme um nome de usuário, um banner ou o nome do seu time de CTF em leetspeak.
- **Estimar a duração de uma fala.** O tempo de leitura é uma referência aproximada para roteiros; falando, vai-se mais devagar, normalmente 130–150 palavras por minuto.

Para codificar texto em vez de remodelar, veja o [conversor Base64](/pt/tools/base64-converter/) ou o [gerador de hash](/pt/tools/hash-generator/).
