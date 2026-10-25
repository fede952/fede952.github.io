---
title: "Aim Trainer e Teste de Reflexos Online"
description: "Treine sua mira no mouse em sessões de 60 segundos: clique nos alvos brilhantes e veja acertos, precisão, tempo médio de reação e uma patente. Grátis."
intro: "O **ReflexGrid** é um aim trainer de 60 segundos: os alvos surgem em qualquer ponto da grade, você clica ou toca o mais rápido possível e, no fim, recebe acertos, precisão, tempo médio até o alvo e uma patente de *Potato* a *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "teste de reflexos", "teste de tempo de reação", "treinar mira", "teste de precisão do mouse", "aim trainer online", "treino fps", "teste de velocidade de clique"]
tags: ["jogos", "gaming", "reflexos", "ferramenta"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid, treinador de mira"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Clique em **Start Training**. O cronômetro de 60 segundos começa e o primeiro alvo aparece."
  - "Clique (ou toque, em telas sensíveis ao toque) em cada círculo brilhante o mais rápido e preciso que conseguir. Assim que acerta, outro aparece."
  - "Fique de olho na barra de cima: tempo restante, acertos e precisão ao vivo. Cliques errados derrubam a precisão."
  - "Quando o tempo acabar, veja os resultados: **Targets Hit**, **Accuracy**, **Avg Reaction** e **Total Clicks**, mais a sua patente."
  - "Clique em **Play Again** para bater seu recorde. Aqueça com algumas rodadas antes de comparar resultados."
faq:
  - q: "Qual é um bom tempo de reação neste teste?"
    a: "A média aqui é o tempo entre o alvo aparecer e você acertar, então inclui mover o mouse, não só reagir. Abaixo de 300 ms (patente *Gamer*) é bom; abaixo de 200 ms (*Pro*), excelente. O tempo de reação visual simples de um adulto costuma ficar em torno de 200–250 ms, por isso os números do ReflexGrid são naturalmente um pouco mais altos."
  - q: "Como as patentes são calculadas?"
    a: "Pelo tempo médio até o alvo: abaixo de 200 ms é *Pro*, abaixo de 300 ms *Gamer*, abaixo de 400 ms *Casual*, abaixo de 500 ms *Novice* e qualquer coisa mais lenta *Potato*. A precisão aparece separada; para evoluir de verdade, mantenha-a acima de uns 80% enquanto reduz o tempo."
  - q: "A sensibilidade ou o DPI do mouse importam?"
    a: "Sim, muito. Treinar mira só adianta com a mesma sensibilidade que você usa para jogar, então mantenha o DPI e as configurações do ponteiro. Desativar \"aprimorar precisão do ponteiro\" (a aceleração do mouse) no Windows deixa os movimentos mais consistentes e fáceis de treinar."
  - q: "Por que alguns alvos são vermelhos?"
    a: "Cerca de 40% dos alvos são vermelhos em vez de ciano, só como variação visual para você não antecipar. Os dois contam igual."
  - q: "Dá para jogar no celular?"
    a: "Sim. O canvas escuta eventos de toque além do mouse, então os toques contam como cliques. Os tempos no toque não são comparáveis aos do mouse; compare-se com você mesmo no mesmo aparelho."
  - q: "Minhas pontuações são salvas ou enviadas?"
    a: "Não. Cada sessão só existe na página; nada é salvo nem enviado. Anote seu melhor resultado se quiser acompanhar a evolução."
---

## Como funciona

O jogo é desenhado em um `<canvas>` HTML ajustado à densidade de pixels da sua tela, com uma grade de fundo animada e uma barra de HUD no topo.

**Alvos.** Cada alvo recebe um raio aleatório entre 20 e 35 pixels e uma posição aleatória, afastada das bordas e do HUD. Ele pulsa ±12%, então nunca fica totalmente parado. O momento em que aparece é guardado com `performance.now()`, o relógio de alta resolução do navegador.

**Acertos e erros.** A cada `mousedown` ou `touchstart`, a distância entre o ponteiro e o centro do alvo é calculada com Pitágoras. Qualquer coisa dentro de 1,3 vez o raio conta como acerto, uma pequena margem para o brilho e a pulsação. Um acerto registra o tempo de reação (agora − momento em que apareceu), toca um tom curto de onda quadrada subindo, gerado pela Web Audio API, solta uma explosão de partículas e faz o próximo alvo aparecer na hora. Um erro toca um tom dente de serra descendo e só aumenta a contagem de cliques.

**Pontuação.** No fim dos 60 segundos:

- **Targets Hit** é o número de cliques certos;
- **Accuracy** é acertos ÷ cliques totais;
- **Avg Reaction** é a média de todos os tempos de reação registrados, em milissegundos;
- a **patente** depende dessa média.

| Tempo médio até o alvo | Patente |
|---|---|
| abaixo de 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| 500 ms ou mais | Potato |

Como cada alvo aparece no instante em que o anterior é acertado, o teste mede a velocidade de *flick*: ver um alvo novo, ir até ele e clicar. Isso se parece mais com o que os FPS exigem do que um teste de "espere a tela ficar verde".

## Casos de uso

- **Aquecer antes de jogar FPS** como Valorant, CS2, Apex Legends ou Overwatch: duas ou três rodadas sincronizam mão e olho.
- **Testar um mouse ou uma sensibilidade nova.** Jogue algumas rodadas com cada configuração e compare precisão e tempo até o alvo.
- **Acompanhar a evolução.** Anote média e precisão todo dia; a prática constante aparece em tempos menores com a mesma precisão.
- **Uma pausa rápida.** Um minuto de cliques concentrados é um bom reset entre sessões longas de trabalho.
- **Ergonomia.** Uma queda repentina de precisão pode ser sinal de cansaço; faça uma pausa.
