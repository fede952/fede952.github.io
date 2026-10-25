---
title: "Calculadora de sub-redes IPv4/IPv6 e VLSM"
description: "Calcule rede, broadcast, faixa de hosts, máscara e wildcard de qualquer CIDR IPv4 ou IPv6 e divida um bloco em sub-redes iguais ou VLSM. No seu navegador."
intro: "Uma **calculadora de sub-redes** para IPv4 e IPv6: digite um endereço com prefixo ou máscara e veja na hora a rede, o broadcast, a faixa de hosts utilizáveis, a máscara, o wildcard e o número de hosts, com visão binária. Uma terceira aba divide um bloco em sub-redes iguais ou em sub-redes VLSM dimensionadas pelo número de hosts."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["calculadora de sub-redes", "calculadora cidr", "calcular sub-rede", "calculadora máscara de sub-rede", "calculadora sub-rede ipv6", "calculadora vlsm", "máscara wildcard", "calcular endereço de rede"]
tags: ["redes", "ferramentas-dev", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Calculadora de sub-redes para IPv4, IPv6 e VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Na aba **IPv4**, digite um endereço com prefixo (`10.0.0.5/8`), com máscara decimal (`172.16.5.4 255.255.240.0`) ou com wildcard no estilo Cisco (`192.168.1.1 0.0.0.255`). Um endereço sem prefixo é tratado como `/32`."
  - "Os resultados aparecem enquanto você digita: rede, broadcast, primeiro e último host utilizável, máscara, wildcard, hosts utilizáveis e total de endereços, e o tipo de endereço (privado, público, CGNAT, link-local…)."
  - "Veja a tabela **Binário**: os bits de rede ficam destacados e os de host esmaecidos, para você ver exatamente onde o prefixo corta o endereço."
  - "Na aba **IPv6**, cole um endereço completo ou comprimido com prefixo para obter a forma comprimida segundo a RFC 5952, a forma expandida, o primeiro e o último endereço do prefixo e quantas redes /64 ele contém."
  - "Em **Dividir (VLSM)**, informe o bloco a dividir e escolha **Em sub-redes iguais** (quantas) ou **Por hosts por sub-rede (VLSM)** (uma lista como `100, 50, 20, 2`). Copie qualquer valor com o botão **Copiar** ou o plano inteiro com **Copiar tabela**."
faq:
  - q: "Por que uma /24 tem 254 hosts utilizáveis e não 256?"
    a: "Uma /24 tem 256 endereços, mas o primeiro é o endereço de rede e o último o de broadcast. Nenhum dos dois pode ser atribuído a um host, sobrando 254. A mesma regra (total menos dois) vale para todos os prefixos até /30."
  - q: "Como a calculadora trata /31 e /32?"
    a: "Uma /31 é tratada como enlace ponto a ponto conforme a RFC 3021: os dois endereços são utilizáveis e não há broadcast. Uma /32 é um host único, usada em loopbacks, rotas de host e regras de firewall. Equipamentos antigos sem suporte à RFC 3021 precisam de uma /30 para um enlace."
  - q: "O que é uma máscara wildcard?"
    a: "O inverso bit a bit da máscara de rede: 255.255.255.0 vira 0.0.0.255. As ACLs da Cisco e os comandos network do OSPF usam wildcards, em que um bit 0 significa \"deve coincidir\" e um bit 1 \"qualquer valor\". Você pode digitar um wildcard diretamente no campo IPv4 e a calculadora o converte em prefixo."
  - q: "O que significa VLSM e por que as maiores sub-redes são alocadas primeiro?"
    a: "Variable Length Subnet Masking permite que cada sub-rede tenha seu próprio prefixo: uma LAN de 100 hosts recebe uma /25 e um enlace ponto a ponto uma /31. Alocar do maior pedido para o menor mantém cada sub-rede alinhada ao seu limite sem lacunas desperdiçadas; os resultados são mostrados depois na ordem em que você os digitou."
  - q: "Por que dividir em 3 sub-redes me dá 4?"
    a: "A divisão em partes iguais toma emprestados bits de host, e cada bit dobra o número de sub-redes: 1 bit dá 2 e 2 bits dão 4. Três sub-redes precisam de 2 bits, que produzem 4. Use o modo VLSM se quiser exatamente o número pedido, cada uma do tamanho dos seus hosts."
  - q: "Qual prefixo IPv6 uma LAN deve usar?"
    a: "Uma /64. A autoconfiguração sem estado (SLAAC) e muitos recursos do IPv6 pressupõem um identificador de interface de 64 bits. Uma unidade normalmente recebe uma /48 ou /56 e a divide em /64; a calculadora mostra quantas redes /64 cabem no prefixo informado."
  - q: "O que eu digito é enviado a algum servidor?"
    a: "Não. Todos os cálculos são feitos por um pequeno módulo JavaScript no seu navegador; a página não faz nenhuma requisição com seus dados, então você pode usá-la com planos de endereçamento internos."
---

## Como funciona

### Aritmética IPv4

Um endereço IPv4 é um número de 32 bits. A calculadora lê os quatro octetos (recusando valores acima de 255 e zeros à esquerda ambíguos como `010`), monta a máscara a partir do prefixo ligando os *n* bits mais altos e trabalha com operações bit a bit simples:

- **Endereço de rede** = endereço AND máscara.
- **Wildcard** = NOT máscara.
- **Endereço de broadcast** = rede OR wildcard.
- **Hosts utilizáveis** = 2^(32 − prefixo) − 2, com as duas exceções descritas nas perguntas frequentes: uma /31 tem dois endereços utilizáveis (RFC 3021) e uma /32 tem um.

Uma máscara decimal precisa ser *contígua*: uns seguidos de zeros. `255.255.240.0` é aceita como /20; `255.0.255.0` é recusada. Se o valor não for uma máscara válida, mas for um wildcard válido (zeros seguidos de uns), ele é lido como wildcard, então `0.0.15.255` também significa /20.

O tipo de endereço vem dos registros de uso especial da IANA: faixas privadas RFC 1918 (10/8, 172.16/12, 192.168/16), espaço compartilhado para NAT de operadora (100.64/10, RFC 6598), loopback (127/8), link-local (169.254/16), as três faixas de documentação, multicast (224/4) e espaço reservado.

### IPv6

Endereços IPv6 são números de 128 bits, tratados como `BigInt` do JavaScript para não perder precisão. O analisador aceita a forma completa, a compressão `::` (uma vez por endereço) e um final IPv4 como `::ffff:192.0.2.1`. A saída segue a **RFC 5952**, a forma de texto canônica: hexadecimal minúsculo, sem zeros à esquerda nos grupos e a sequência mais longa de dois ou mais grupos zerados substituída por `::` (a mais à esquerda em caso de empate). Um único grupo zerado nunca é comprimido.

Para um prefixo, o primeiro endereço é o endereço AND a máscara, o último liga todos os bits de host e o tamanho é 2^(128 − prefixo). O IPv6 não tem broadcast, então não há o "menos dois".

### Dividir um bloco

*Em sub-redes iguais* acrescenta ⌈log₂ n⌉ bits ao prefixo e lista todas as sub-redes resultantes (até 1.024 linhas). *VLSM* calcula, para cada número de hosts, o menor prefixo que o comporta, ordena os pedidos do maior para o menor e aloca cada um no próximo endereço alinhado ao seu tamanho. Se um pedido não couber no espaço restante, você recebe um erro que o identifica em vez de um plano com sobreposições.

## Casos de uso

- **Projetar um plano de endereçamento.** Divida uma /22 para um novo escritório em VLANs de usuários, voz, impressoras e gerência conforme o número de pessoas e cole a tabela na documentação.
- **Escrever regras de firewall e ACLs.** Obtenha a rede/prefixo ou o wildcard exato para um grupo de objetos e confira se uma /20 cobre mesmo a faixa que você imagina.
- **Solução de problemas.** Dois hosts não se comunicam: informe os dois endereços com suas máscaras e veja se estão de fato na mesma sub-rede.
- **Redes em nuvem.** Planeje CIDRs de VPC e sub-redes sem sobreposição, lembrando que os provedores reservam alguns endereços por sub-rede além de rede e broadcast.
- **Estudos e provas.** Confira exercícios de subnetting para CCNA, Network+ ou entrevistas; a visão binária mostra por que o resultado é aquele.
