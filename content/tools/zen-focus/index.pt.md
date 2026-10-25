---
title: "Timer de Foco e Ruído Branco"
description: "Misture ruído branco, rosa e marrom, chuva, lareira, teclado e café, e use um timer Pomodoro. Sons gerados ao vivo no navegador, sem arquivos de áudio."
intro: "O **ZenFocus** junta um timer de foco a um mixer de sons ambientes de oito canais. Escolha um preset ou monte sua própria mistura de ruído, chuva, lareira, teclas e burburinho de cafeteria, e comece uma sessão de 25 minutos. Cada som é gerado ao vivo no navegador: sem arquivos de áudio e sem conta."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["timer de foco", "timer pomodoro online", "mixer de sons ambientes", "ruído marrom", "ruído branco online", "ruído rosa", "som de chuva para estudar", "ruído de fundo para concentração"]
tags: ["produtividade", "foco", "áudio", "ferramenta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus, timer e mixer de ruídos"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Escolha um preset: **Deep Work** (ruído marrom e chuva), **Coffee Break** (burburinho de cafeteria e lareira) ou **Silence** para zerar todos os canais."
  - "Ou monte sua mistura arrastando o controle de cada cartão. O botão 🔊 de um cartão silencia aquele canal sem perder o nível."
  - "Ajuste o volume geral com o controle **Master**. Comece baixo: o ruído de mascaramento funciona melhor quando mal cobre as distrações."
  - "Ajuste a duração com **−5**, **−1**, **+1** e **+5** (de 1 a 90 minutos, padrão 25) e aperte **Start**."
  - "Trabalhe até o sino tocar. **Pause** para o relógio e **Reset** volta à duração total. Para uma pausa, ajuste 5 minutos e comece de novo."
faq:
  - q: "Qual a diferença entre ruído branco, rosa e marrom?"
    a: "A forma como a energia se distribui pelas frequências. O ruído branco tem a mesma potência em todas e soa chiado. O rosa perde cerca de 3 dB por oitava, então é mais suave, parecido com chuva constante. O marrom (browniano) perde cerca de 6 dB por oitava e soa como um ronco grave ou uma cachoeira distante. Muita gente acha o rosa e o marrom menos cansativos que o branco em sessões longas."
  - q: "Ruído de fundo melhora mesmo a concentração?"
    a: "As evidências são mistas. Um ruído constante mascara de forma confiável sons imprevisíveis, como conversas e notificações, que são o que costuma quebrar a concentração. Alguns estudos relatam benefícios para a atenção, principalmente em pessoas com TDAH; outros não encontram efeito ou veem prejuízo na leitura complexa. Trate como um experimento pessoal: teste uma mistura por uma semana e mantenha se ajudar."
  - q: "O que é a Técnica Pomodoro?"
    a: "Um método de gestão de tempo criado por Francesco Cirillo: você trabalha numa tarefa por 25 minutos, faz 5 minutos de pausa e, depois de quatro rodadas, uma pausa maior de 15–30 minutos. O ZenFocus começa em 25 minutos; para as pausas, ajuste 5. Ele não troca sozinho, então você decide quando começa a próxima rodada."
  - q: "O timer continua numa aba em segundo plano?"
    a: "Sim. A contagem regressiva é calculada a partir de um horário de término fixo, não contando ticks, então continua precisa mesmo quando o navegador desacelera os timers de abas ocultas. O sino toca no fim, desde que a aba continue aberta."
  - q: "Por que não sai som até eu clicar?"
    a: "Os navegadores bloqueiam áudio até você interagir com a página. O ZenFocus liga o motor de áudio no seu primeiro clique num controle, num preset ou em Start, e depois sobe os canais suavemente."
  - q: "Os sons são gravações?"
    a: "Não. Cada canal é sintetizado com a Web Audio API: buffers de ruído moldados por filtros (a chuva, por exemplo, é ruído branco com passa-alta e o trovão ruído marrom com passa-baixa), e o teclado é uma sequência de cliques curtos aleatórios. Nada é baixado nem transmitido, então também funciona offline depois que a página carrega."
  - q: "É seguro ouvir por horas?"
    a: "Mantenha o volume moderado. Uma regra comum é ficar num nível em que você ainda ouve alguém falando ao seu lado, e fazer pausas regulares. Exposição prolongada a som alto em fones pode danificar a audição."
---

## Como funciona

O ZenFocus é uma página única baseada na **Web Audio API**. Na primeira interação, ele cria um `AudioContext` e gera na memória alguns segundos de ruído bruto:

- **Ruído branco**: amostras aleatórias uniformes entre −1 e 1, o que dá um espectro plano.
- **Ruído rosa**: o conhecido filtro de Paul Kellet, um banco de filtros de primeira ordem que aproxima uma inclinação de −3 dB/oitava.
- **Ruído marrom**: um "integrador com vazamento" que acumula passos aleatórios, com −6 dB/oitava.
- **Cliques de teclado**: cerca de cinco pulsos curtos por segundo, com decaimento exponencial e volume aleatório.

Os buffers rosa e marrom são corrigidos para que a última amostra encontre a primeira, assim o ponto de loop não estala. Cada um dos oito canais é uma fonte em loop, opcionalmente passando por um filtro biquad, depois um nó de ganho (o controle do cartão) e, por fim, o ganho master:

| Canal | Fonte | Filtro |
|---|---|---|
| White Noise | branco | nenhum |
| Pink Noise | rosa | nenhum |
| Brown Noise | marrom | nenhum |
| Rain | branco | passa-alta 1,2 kHz |
| Thunder | marrom | passa-baixa 100 Hz |
| Fireplace | branco | passa-banda 700 Hz |
| Keyboard | cliques | passa-banda 2,2 kHz |
| Coffee Shop | rosa | passa-banda largo 1 kHz |

Todos os canais tocam desde o início; mexer num controle só muda o ganho dele, com uma rampa de 50 ms para nunca estalar. O mudo leva o ganho a zero, mas lembra o valor do controle.

**O timer** guarda o instante em que a sessão deve terminar e recalcula o tempo restante quatro vezes por segundo. Os navegadores podem desacelerar o `setInterval` em abas em segundo plano, mas como o mostrador é derivado do relógio e não de ticks contados, uma sessão de 25 minutos termina em 25 minutos. No zero, três tons senoidais (um arpejo de Lá maior: 880, 1109 e 1319 Hz) tocam como um sino suave.

O botão Share usa o painel de compartilhamento nativo do aparelho quando existe e, se não, copia o link da página. Nada mais sai da página: configurações e uso não são salvos.

## Casos de uso

- **Blocos de trabalho profundo.** Ligue o Deep Work, ajuste 50 minutos e feche todo o resto: o ronco constante cobre a conversa do escritório e o barulho da rua.
- **Estudar com o método Pomodoro.** Alterne sessões de 25 minutos e pausas de 5, com uma pausa maior depois de quatro rodadas.
- **Escritórios abertos e casas compartilhadas.** Ruído rosa ou marrom em volume baixo nos fones cobre a fala inteligível, o som que mais distrai a maioria das pessoas.
- **Escrever e ler.** Uma mistura leve de Coffee Shop + Fireplace cria clima de cafeteria sem letras de música disputando sua atenção.
- **Relaxar no fim do dia.** Chuva e ruído marrom são um fundo calmo para ler antes de dormir; use o timer para largar o celular.
- **Timeboxing de tarefas e reuniões.** Ajuste 10 ou 15 minutos para aquela tarefa que você vive adiando: o sino avisa quando parar.
