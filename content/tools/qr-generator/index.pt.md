---
title: "Gerador de QR Code Grátis (PNG)"
description: "Crie QR codes para links ou texto, escolha cores e correção de erros e baixe um PNG pronto para impressão. Códigos estáticos que nunca expiram."
intro: "Digite um link ou qualquer texto e receba um **QR code estático** para baixar como PNG nítido e pronto para impressão. O código é gerado no seu navegador, contém seus dados diretamente e nunca expira. Os modos **Wi-Fi** e **Contato** criam códigos que, com uma só leitura, conectam a uma rede ou salvam um cartão de contato."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["gerador de qr code", "criar qr code grátis", "qr code grátis", "qr code para link", "qr code png", "qr code sem cadastro", "qr code estático", "qr code que não expira"]
tags: ["qr-code", "utilitários", "ferramenta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker, gerador de QR code"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Cole uma URL (com `https://`) ou digite qualquer texto na caixa. Acentos, emoji e alfabetos não latinos também funcionam."
  - "Para uma rede, abra **Wi-Fi** e digite o nome, a senha e a segurança; para um cartão de visita, abra **Contato** e preencha os campos que quiser. O texto exato que será codificado aparece em **Texto codificado**."
  - "Se quiser, escolha uma cor de **Primeiro Plano** e de **Fundo**. Mantenha o primeiro plano bem mais escuro que o fundo, senão muitas câmeras de celular não vão ler."
  - "Escolha o nível de **Correção de Erro**: **M (15%)** é o padrão; use **Q** ou **H** se o código for impresso pequeno, ao ar livre ou com um logotipo por cima."
  - "Clique em **Gerar QR** e confira a pré-visualização apontando a câmera do celular para a tela."
  - "Clique em **Baixar .PNG** para salvar uma imagem de uns 1200 px com a margem branca necessária, pronta para impressão ou slides."
faq:
  - q: "Esses QR codes expiram?"
    a: "Não. São QR codes estáticos: seu link ou texto fica codificado no próprio desenho. Eles não apontam para nenhum servidor nosso, então não há nada para desligar, nenhuma assinatura e nenhum limite de leituras. Em compensação, não dá para mudar o destino depois: se a URL mudar, gere um novo código."
  - q: "Este gerador de QR code é mesmo grátis?"
    a: "Sim, sem conta, sem marca d'água e sem limite de códigos. A página é financiada pelos anúncios exibidos ao redor da ferramenta, não por recursos bloqueados."
  - q: "Qual a diferença entre QR code estático e dinâmico?"
    a: "Um QR code dinâmico contém um link curto para o servidor do fornecedor, que redireciona para a sua URL real. Assim o fornecedor conta as leituras e pode mudar o destino, mas o código para de funcionar se você deixar de pagar ou se o serviço acabar, e cada leitura passa pelos servidores dele. Um código estático, como os daqui, leva direto à sua URL."
  - q: "Qual nível de correção de erro devo escolher?"
    a: "L recupera cerca de 7% dos módulos danificados, M 15%, Q 25% e H 30%. Níveis mais altos deixam o código mais denso para o mesmo conteúdo. M serve para telas e impressões limpas; escolha Q ou H para adesivos pequenos, superfícies ásperas ou se for colocar um logotipo no meio."
  - q: "Quanto texto cabe em um QR code?"
    a: "O gerador escolhe automaticamente a menor das 40 versões de QR em que o conteúdo cabe. No nível M, um código versão 40 guarda cerca de 2.300 bytes de texto, mas códigos tão grandes são difíceis de ler com o celular. Para links, quanto mais curto melhor: uma URL de 30–60 caracteres gera um código limpo e fácil de escanear."
  - q: "Por que meu QR code colorido não lê?"
    a: "Os leitores procuram módulos escuros sobre fundo claro com contraste suficiente. Cores invertidas (claro sobre escuro), combinações com pouco contraste como amarelo sobre branco ou uma imagem atrás do código são as causas mais comuns. Preto ou uma cor escura sobre branco é a escolha mais segura."
  - q: "O que eu digito é enviado para algum lugar?"
    a: "Não. O QR code é calculado por uma biblioteca JavaScript que roda nesta página e desenhado em um canvas. Nada é enviado, o que importa se você estiver codificando uma senha de Wi-Fi, uma URL interna ou uma anotação particular."
  - q: "Como funciona um QR code de Wi-Fi?"
    a: "Ele contém um texto curto no formato `WIFI:` que as câmeras do Android e do iPhone entendem, por exemplo `WIFI:T:WPA;S:Casa;P:segredo;;`. Ao escanear, o celular oferece entrar na rede sem digitar a senha. Caracteres especiais no nome ou na senha (`\\ ; , : \"`) recebem uma barra invertida, como o formato exige, então uma senha como `p;ss:word` também funciona. Qualquer pessoa que escanear o código consegue ler a senha: imprima-o só onde os convidados forem bem-vindos."
  - q: "Que formato é usado para contatos e o que ele pode conter?"
    a: "Um vCard 3.0, a versão que as câmeras dos celulares importam com mais confiabilidade: nome, organização, cargo, celular, e-mail, site, endereço e uma observação. Campos vazios ficam de fora para manter o código pequeno. Vírgulas, ponto e vírgula e quebras de linha são escapados como o padrão vCard exige. Um cartão completo gera um código denso: deixe de fora o que não precisa e mantenha a correção de erros em L ou M."
---

## Como funciona

A ferramenta usa a biblioteca de código aberto **qrcode-generator**, de Kazuhiko Arase (v1.4.4, hospedada neste site), e desenha o resultado em um canvas HTML.

1. **Codificação.** Seu texto é convertido em bytes **UTF-8** e guardado em *modo byte*, então `é`, `ã`, `ç`, `€` e emoji aparecem exatamente como você digitou quando um celular lê o código. (Por padrão a biblioteca guardaria um único byte por caractere e estragaria tudo que não fosse latim básico, por isso a página muda explicitamente para UTF-8.)
2. **Escolha da versão.** A biblioteca escolhe a menor **versão de QR**, da versão 1 (21 × 21 módulos) até a 40 (177 × 177), que comporta seus dados no nível de correção escolhido.
3. **Correção de erros.** Os QR codes acrescentam palavras de correção **Reed–Solomon** para que um leitor consiga reconstruir partes faltando ou sujas: o nível **L** recupera ~7%, **M** ~15%, **Q** ~25% e **H** ~30% das palavras de código.
4. **Desenho.** Cada módulo escuro é desenhado como um quadrado na cor de primeiro plano. Em volta do símbolo a ferramenta deixa uma **zona de silêncio de 4 módulos** na cor de fundo, a margem exigida pelo padrão QR (ISO/IEC 18004); sem ela, os leitores falham assim que o código fica sobre uma página colorida.
5. **Exportação.** A pré-visualização na tela tem uns 300 px. No download, o código é desenhado de novo com cerca de **1200 px**, com cada módulo ocupando um número inteiro de pixels para manter as bordas nítidas, e salvo como `qrcode.png`.

| Conteúdo | Tamanho típico | Versão no nível M | Módulos |
|---|---|---|---|
| URL curta | 25 caracteres | 2 | 25 × 25 |
| URL normal com caminho | 60 caracteres | 4 | 33 × 33 |
| URL longa com parâmetros de rastreamento | 150 caracteres | 8 | 49 × 49 |
| Um parágrafo de texto | 500 caracteres | 17 | 85 × 85 |

Quanto menos módulos, maior fica cada um na impressão e mais fácil é ler o código à distância; por isso tirar os parâmetros de rastreamento de uma URL costuma fazer mais diferença do que o nível de correção.

### Códigos de Wi-Fi e de contato

No modo **Wi-Fi**, a ferramenta escreve `WIFI:T:<WPA|WEP|nopass>;S:<rede>;P:<senha>;H:true;;` (o campo `H` só para redes ocultas); `WPA` cobre WPA, WPA2 e WPA3 Personal, porque o celular negocia a versão exata. No modo **Contato**, escreve um vCard 3.0 com quebras de linha CRLF. Os dois formatos são testados decodificando o PNG baixado e comparando o resultado caractere por caractere, inclusive com nomes e senhas cheios de `; , : " \`.

## Casos de uso

- **Impressão e embalagens.** Coloque um QR code em panfletos, cartões de visita, cardápios ou etiquetas que abra seu site, uma página de avaliações ou um manual. Um código estático funciona enquanto a URL funcionar.
- **Apresentações e cartazes.** Deixe o público abrir seus slides, uma pesquisa ou um repositório sem digitar um endereço longo.
- **Compartilhar texto offline.** Codifique uma nota curta, um número de série ou dados de contato que um celular lê sem internet.
- **Testar seus próprios apps.** Gere códigos para deep links, URLs de homologação ou testes de callback OAuth sem colar endereços internos em um serviço de terceiros.
- **Conscientização em segurança.** O "quishing" (phishing por QR code) esconde links maliciosos atrás de códigos. Gerar os seus permite mostrar aos colegas como é fácil um código apontar para qualquer lugar, e por que vale olhar a URL que o celular mostra antes de tocar.
