---
title: "Teste de Impressão Digital do Navegador"
description: "Veja a impressão digital que seu navegador entrega a cada site (canvas, GPU WebGL, áudio, fontes, tela, fuso horário) e uma estimativa de unicidade."
intro: "O **GhostPrint** lê os mesmos sinais que scripts de rastreamento e antifraude leem em silêncio na maioria dos sites, mostra cada um deles e estima o quanto eles tornam seu navegador identificável. Cada medição roda nesta página; nada é enviado."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["teste de impressão digital do navegador", "browser fingerprinting", "fingerprint do navegador", "canvas fingerprint", "webgl fingerprint", "o quanto sou rastreável", "sou único na internet", "rastreamento sem cookies"]
tags: ["privacidade", "segurança", "fingerprinting", "ferramenta"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint, teste de impressão digital do navegador"
tool_height: 2200
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Abra a página: a verificação começa sozinha. O GhostPrint mede 12 sinais em uns dois segundos e lista cada um conforme lê; **Re-scan** repete o processo."
  - "Leia o veredito e o número principal, por exemplo \"1 in 2.1 million\": a estimativa de quantos navegadores seria preciso olhar até achar um com a mesma impressão digital."
  - "Percorra os cartões de sinais. Cada um mostra o valor bruto, os bits de informação identificadora que ele acrescenta e uma explicação de uma linha."
  - "Anote seu **Fingerprint ID**. Abra esta página em uma janela anônima ou depois de apagar os cookies: o ID continua igual, e é exatamente essa a ideia do fingerprinting."
  - "Use **Download shareable card** ou **Copy summary** para comparar navegadores ou mostrar a um colega por que apagar cookies não basta."
faq:
  - q: "O que é browser fingerprinting?"
    a: "É um jeito de reconhecer um navegador sem guardar nada nele. Um script lê dezenas de pequenas propriedades (tamanho da tela, fontes instaladas, modelo da GPU, o jeito como sua máquina desenha uma imagem escondida) e as combina em um identificador. Não há cookie envolvido, então o identificador sobrevive à navegação anônima, à limpeza de cookies e à maioria dos botões de \"apagar dados\"."
  - q: "A nota de unicidade é uma medição?"
    a: "É uma estimativa. Cada sinal recebe um peso fixo em bits, de acordo com quanta informação identificadora esse tipo de sinal costuma carregar segundo as pesquisas publicadas sobre fingerprinting; os pesos são somados, descontados em 18% porque os sinais são correlacionados, e o resultado é limitado a cerca de 5,5 bilhões, o número de usuários da internet. O GhostPrint não compara você com um banco de dados de outros visitantes, e é por isso que funciona sem coletar nada."
  - q: "O modo anônimo impede o fingerprinting?"
    a: "Não. O modo anônimo apaga cookies e histórico quando você o fecha, mas sua GPU, suas fontes, sua tela e a renderização do canvas continuam iguais, então a impressão digital também. Dá para testar: o Fingerprint ID mostrado aqui não muda em uma janela anônima."
  - q: "Quais navegadores resistem melhor ao fingerprinting?"
    a: "O Tor Browser deixa todos os usuários com a mesma cara, a abordagem mais eficaz. O Brave torna aleatórias, por site, as leituras de canvas, WebGL e áudio. O Firefox tem `privacy.resistFingerprinting`, que padroniza muitos valores. O Safari reduz alguns sinais por padrão. Chrome e Edge expõem quase todos, a menos que você instale uma extensão."
  - q: "Extensões anti-fingerprinting ajudam?"
    a: "Algumas sim, principalmente as que tornam aleatórios canvas e áudio, mas uma extensão rara pode virar ela mesma um traço distintivo. Bloquear totalmente um sinal, como o WebGL, também pode deixar você mais incomum. O objetivo é parecer comum, não invisível."
  - q: "Algum dado meu é enviado para o seu servidor?"
    a: "Não. Todas as medições rodam em JavaScript dentro desta página e o resultado é exibido localmente. A ferramenta não faz requisições a serviços de análise ou de fingerprinting, e o cartão para download é gerado em um canvas no seu navegador."
---

## Como funciona

O GhostPrint coleta doze sinais. Cinco são *medidos* ativamente, desenhando ou processando algo; os demais são lidos de APIs padrão do navegador.

**Sinais de renderização**

- **Canvas.** A página desenha texto (com um emoji e letras acentuadas), um retângulo preenchido e um arco em um canvas escondido de 240 × 60, exporta com `toDataURL()` e calcula o hash do resultado com FNV-1a de 32 bits. Fontes, suavização, GPU e driver de vídeo deixam diferenças mínimas nos pixels, então o hash muda de uma máquina para outra. Uma saída vazia ou minúscula é tratada como bloqueada.
- **WebGL.** Abre um contexto WebGL, lê fabricante e renderizador da GPU sem máscara pela `WEBGL_debug_renderer_info` e os combina em um hash com a versão do WebGL, a versão da linguagem de shaders, os tamanhos máximos de textura e de renderbuffer, o limite de atributos de vértice e a lista completa de extensões suportadas.
- **Áudio.** Um `OfflineAudioContext` processa um segundo de onda triangular de 10 kHz passando por um compressor dinâmico. A soma de 1.000 amostras de saída vira um hash; diferenças de ponto flutuante entre pilhas de áudio fazem o valor variar de aparelho para aparelho. Depois de 900 ms a medição desiste.
- **Fontes.** Um texto de teste escondido de 72 px é medido nas três famílias genéricas (serif, sans-serif, monospace) e de novo com cada uma de **53 fontes comuns** na frente. Se a largura ou a altura mudar, a fonte está instalada. Seu conjunto de fontes reflete o sistema operacional, o idioma dele e os programas instalados.

**Sinais só de leitura:** string user-agent, plataforma, resolução da tela com proporção de pixels e profundidade de cor, fuso horário com deslocamento UTC, idiomas preferidos, núcleos da CPU, memória do aparelho e pontos de toque, preferências de tema e de movimento reduzido, e o estado de cookies, Do-Not-Track e Global Privacy Control.

### Dos sinais ao "1 em N"

Cada sinal tem um peso fixo em bits:

| Sinal | Bits |
|---|---|
| Impressão de canvas | 8 |
| Fontes | 0,45 por fonte detectada, máx. 8 |
| Modelo da GPU (WebGL) | 7 |
| User agent | 6 (8 se for incomumente longo) |
| Impressão de áudio | 5 |
| Tela, fuso horário | 2 cada |
| Idiomas, hardware | 1,5 cada |
| Plataforma | 1 |
| Preferências de exibição, sinais de privacidade | 0,5 cada |

Um sinal bloqueado ou aleatorizado conta 0 bit. O total é multiplicado por **0,82** para levar em conta a correlação (uma GPU específica costuma implicar uma plataforma específica, por exemplo) e depois convertido em "1 em 2^bits", com teto de 5,5 bilhões. Os vereditos são *Blending in* abaixo de 10 bits, *Identifiable* a partir de 10, *Highly unique* a partir de 18 e *Ghost-level exposure* a partir de 28.

O **Fingerprint ID** é formado por três hashes FNV-1a de 4 caracteres: do user agent, da plataforma e da tela; dos hashes de WebGL e canvas; e de todos os sinais juntos. O fato de ele continuar igual em janelas anônimas é a demonstração prática.

## Casos de uso

- **Entender por que "apagar cookies" não é privacidade.** Faça o teste, apague tudo, faça de novo: mesmo ID.
- **Comparar navegadores e configurações.** Teste o Firefox com `resistFingerprinting`, o Brave, o Tor Browser e seu navegador de sempre, e veja quais cartões caem para 0 bit.
- **Treinamento de segurança.** Uma demonstração de 30 segundos dos cartões de GPU e fontes deixa o conceito concreto até para colegas não técnicos.
- **Checar premissas antifraude.** Quem desenvolve sistemas de pontuação de risco vê quais sinais são estáveis e quais são fáceis de bloquear.
- **Compartilhar o resultado.** O cartão para download de 1200 × 630 (tamanho de prévia em redes sociais) mostra seu veredito, entropia e ID sem expor os valores brutos.
