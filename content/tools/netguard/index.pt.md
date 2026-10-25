---
title: "Qual é Meu IP? Teste de Privacidade"
description: "Veja seu IP público, provedor e localização, verifique a exposição do IP local via WebRTC, a GPU e a impressão digital do aparelho, com uma nota."
intro: "O **NetGuard** mostra o que qualquer site consegue saber sobre você no momento em que você se conecta: seu endereço IP público, seu provedor e sua localização aproximada, além dos sinais do aparelho que o navegador entrega de graça. Um clique, uma nota de privacidade e explicações claras."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["qual é meu ip", "meu endereço ip", "teste de vazamento de ip", "teste webrtc leak", "teste de privacidade do navegador", "testar vpn", "o que os sites sabem sobre mim", "nota de privacidade"]
tags: ["privacidade", "rede", "vpn", "ferramenta"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard: teste de privacidade do navegador e vazamento de IP"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Clique em **Run Privacy Scan**. A verificação leva uns quatro segundos, quase todos para o teste WebRTC."
  - "Leia **Network & Location**: o IP público, o provedor e a cidade que todo servidor web vê quando você se conecta, obtidos pelo ipwho.is."
  - "Confira o cartão **WebRTC**. Verde significa que o navegador não expôs nenhum endereço de rede privado; em vermelho aparecem os endereços vazados."
  - "Veja os cartões de impressão digital (sistema operacional, navegador, tela, GPU, idioma e fuso horário, bateria): qualquer site lê isso sem pedir permissão."
  - "Compare o **Privacy Score** antes e depois de uma mudança, por exemplo ligando uma VPN, trocando de navegador ou bloqueando o WebGL, e clique em **Scan Again**."
faq:
  - q: "Qual é meu endereço IP e quem pode vê-lo?"
    a: "Seu IP público é o endereço que o provedor de internet (ou a VPN) atribui à sua conexão. Todos os sites, servidores de anúncios e CDNs que você acessa o veem, porque ele é necessário para devolver a página para você. Ele costuma revelar seu provedor e sua cidade ou região, raramente sua rua."
  - q: "Uma VPN esconde meu IP neste teste?"
    a: "Sim: os cartões de IP, provedor e localização passam a mostrar os dados do servidor VPN em vez dos seus, que é exatamente a função da VPN. A nota, porém, não sabe se um endereço é de VPN e desconta os mesmos pontos para qualquer IP visível: compare os cartões, não só o número."
  - q: "O que é um vazamento WebRTC?"
    a: "O WebRTC permite que navegadores façam conexões ponto a ponto para chamadas de vídeo. Para isso ele reúne \"candidatos ICE\", os endereços de rede onde o aparelho pode ser alcançado. Navegadores antigos expunham assim, para qualquer página, o endereço LAN privado do aparelho (como 192.168.1.23). O NetGuard verifica exatamente isso; os navegadores modernos agora escondem esse endereço atrás de um nome aleatório `.local`."
  - q: "O NetGuard consegue dizer se minha VPN vaza meu IP real pelo WebRTC?"
    a: "Não totalmente. O teste roda sem servidor STUN, então revela endereços da rede local, mas não pergunta a um servidor externo como seu endereço público aparece via WebRTC. Para testar esse vazamento específico de VPN, ligue a VPN, abra um teste WebRTC dedicado baseado em STUN e compare o endereço público informado com o IP mostrado aqui."
  - q: "Por que o modelo da minha GPU aparece?"
    a: "Pela extensão WebGL `WEBGL_debug_renderer_info`, uma página pode ler a string exata do renderizador gráfico, por exemplo um modelo de GPU NVIDIA ou Apple. Somado ao tamanho da tela, fuso horário e idioma, isso reduz você a um grupo pequeno de aparelhos. Alguns navegadores devolvem um valor genérico ou bloqueiam, e o NetGuard marca isso como seguro."
  - q: "A ferramenta guarda ou envia meus dados?"
    a: "Só uma requisição sai do seu navegador: a consulta ao ipwho.is que devolve seu IP público e a localização dele, algo que qualquer site visitado poderia fazer. Todo o resto é lido e exibido localmente, e nada fica salvo quando você fecha a página."
---

## Como funciona

A verificação faz cinco testes em sequência, todos dentro da página, e depois os transforma em uma nota.

**1. Identidade de rede.** O navegador chama `https://ipwho.is/`, uma API pública de geolocalização por IP. A resposta traz o endereço de onde partiu a requisição, o provedor ou a organização dona dele e o país, a cidade e as coordenadas aproximadas desse endereço. É a mesma informação que qualquer servidor web tira da sua conexão, por isso o cartão aparece como alerta.

**2. Qualidade da conexão.** Onde existe a **Network Information API** (navegadores baseados em Chromium), `navigator.connection` informa a banda estimada em Mbps, um tipo de conexão efetivo como `4g` e o tempo de ida e volta. Firefox e Safari não expõem essa API, e o cartão avisa.

**3. Impressão digital do aparelho.** O NetGuard lê os sinais que os scripts de fingerprinting mais coletam:

- sistema operacional e versão do navegador extraídos da string `User-Agent`, mais `navigator.platform`;
- resolução da tela, proporção de pixels do aparelho, tamanho da janela e profundidade de cor;
- o **renderizador e o fabricante da GPU**, a partir de um contexto WebGL com a extensão `WEBGL_debug_renderer_info`;
- `navigator.language` e o fuso horário de `Intl.DateTimeFormat().resolvedOptions()`;
- nível e estado de carga da bateria com `navigator.getBattery()`, onde o navegador ainda implementa.

**4. Verificação de endereços locais via WebRTC.** A página cria uma `RTCPeerConnection` sem servidores ICE, abre um canal de dados e gera uma oferta. O navegador então emite candidatos ICE do tipo *host*, cada um com um endereço de rede. O NetGuard coleta os endereços IPv4 e ignora os nomes mDNS terminados em `.local`, que os navegadores modernos usam para esconder o endereço LAN real. Todo endereço coletado aparece como exposto. Depois de quatro segundos o teste termina.

**5. Nota de privacidade.** A nota começa em 100 e perde pontos para cada exposição encontrada:

| Sinal | Pontos |
|---|---|
| IP público e localização consultáveis | −30 |
| IP privado exposto via WebRTC | −20 |
| Sistema, navegador e tela legíveis | −10 |
| Modelo exato da GPU legível | −10 |
| Idioma e fuso horário legíveis | −5 |
| Estado da bateria legível | −5 |

O Chrome no desktop costuma tirar 40 (no nosso teste, exatamente isso); navegadores que escondem a string da GPU ou não implementam a Battery API ganham de 5 a 15 pontos a mais. O número serve para puxar a conversa, não é medição de laboratório: o que importa são os cartões.

## Casos de uso

- **Conferir se a VPN está ligada.** Conecte e faça a verificação: IP, provedor e cidade devem ser os do provedor de VPN, não os da sua internet de casa.
- **Ver o que um site descobre antes do cadastro.** Os cartões mostram exatamente o que um script de análise ou de anúncios consegue ler na primeira visita.
- **Comparar navegadores.** Rode a verificação no Chrome, Firefox, Brave e Safari: os cartões de GPU, bateria e conexão mudam bastante.
- **Entender um bloqueio geográfico.** Se um serviço de streaming acha que você está no país errado, o cartão de localização mostra em que país seu IP parece estar.
- **Explicar o básico.** Uma demonstração de dois minutos com o NetGuard explica endereço IP, fingerprinting e WebRTC melhor que uma apresentação. Para uma análise mais funda da impressão digital, experimente o GhostPrint.
