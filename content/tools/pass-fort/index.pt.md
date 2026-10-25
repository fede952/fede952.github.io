---
title: "Testar Força da Senha e Gerador de Senhas"
description: "Descubra se uma senha é forte (entropia em bits, tempo para quebrá-la) e gere senhas ou frases-senha aleatórias. Tudo roda no seu navegador."
intro: "O **PassFort** gera senhas e frases-senha aleatórias com o gerador criptográfico do seu navegador e avalia a entropia e o tempo de ataque por força bruta de qualquer senha. Nada do que você digita sai desta página."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["testar força da senha", "gerador de senha forte", "gerador de senhas", "gerador de frase-senha", "entropia de senha", "quanto tempo para quebrar minha senha", "senha aleatória", "verificador de senha"]
tags: ["segurança", "senhas", "privacidade", "ferramenta"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort: gerador e verificador de senhas"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Abra a aba **Generator**. Escolha o tamanho (de 8 a 128 caracteres) e os grupos de caracteres: maiúsculas, minúsculas, números e símbolos."
  - "Para algo que você consiga digitar e lembrar, marque **Passphrase Mode** e escolha de 3 a 8 palavras. Para uma senha mestra, use pelo menos 6."
  - "Clique em **Generate Password** até gostar do resultado; o botão da área de transferência copia a senha. Cole direto no seu gerenciador de senhas."
  - "Para conferir uma senha que você já usa, vá para a aba **Auditor** e digite ou cole a senha. O botão do olho mostra ou esconde o texto."
  - "Veja o medidor de entropia, o tempo estimado para quebrar e a lista de verificação: o que estiver em vermelho deve ser corrigido antes de reutilizar essa senha."
faq:
  - q: "É seguro digitar minha senha de verdade neste verificador?"
    a: "Sim. O auditor é JavaScript rodando dentro desta página: ele nunca envia pela rede o que você digita, e o valor some assim que você limpa o campo ou fecha a aba. Dá para confirmar nas ferramentas de desenvolvedor do navegador (aba Rede) enquanto digita. Se preferir, teste uma senha que *siga o mesmo padrão* da verdadeira."
  - q: "Quantos bits de entropia uma senha forte precisa ter?"
    a: "Para contas protegidas por um hash lento e com salt, 60–70 bits de entropia *aleatória* resistem por muito tempo a um ataque de força bruta offline. Para a senha mestra do gerenciador ou criptografia de disco, mire em 80–100 bits. Uma senha aleatória de 16 caracteres com os quatro grupos tem cerca de 103 bits; uma frase-senha do PassFort com 7 palavras, cerca de 72 bits."
  - q: "Frase-senha ou senha aleatória: qual é melhor?"
    a: "As duas são fortes quando as palavras ou caracteres são escolhidos ao acaso por uma máquina. Senhas de caracteres aleatórios têm mais entropia por caractere e são ideais quando o gerenciador digita por você. Frases-senha são mais fáceis de digitar e lembrar, então são a melhor escolha para as poucas senhas que você digita à mão, desde que use palavras suficientes."
  - q: "Por que o verificador diz \"séculos\" para uma senha que eu sei que é fraca?"
    a: "A estimativa supõe que cada caractere foi escolhido ao acaso. Um atacante real começa por dicionários, listas de senhas vazadas e regras como \"maiúscula no início, ano no final\", então `Verao2024!` cai em segundos mesmo que a entropia bruta pareça razoável. O PassFort só detecta alguns padrões óbvios (começar com 123, abc, password, qwerty, 111 ou aaa); para uma senha inventada por uma pessoa, encare a pontuação como um limite máximo."
  - q: "O que significa \"10 bilhões de tentativas por segundo\"?"
    a: "É a velocidade de ataque que a estimativa assume: mais ou menos uma GPU moderna contra um hash rápido e sem salt, como MD5 ou NTLM. Contra bcrypt, scrypt ou Argon2 o atacante é milhares de vezes mais lento, então os tempos reais costumam ser maiores. Contra um formulário de login online com limite de tentativas, muito maiores."
  - q: "O PassFort salva ou registra as senhas que gera?"
    a: "Não. As senhas geradas existem só na memória da página até você copiá-las. Não há conta, armazenamento nem servidor por trás da ferramenta. Guarde a senha em um gerenciador: depois de fechar a aba, não dá para recuperá-la."
  - q: "Qual deve ser o tamanho de uma senha em 2026?"
    a: "Se um gerenciador de senhas gera e guarda, use pelo menos 16 caracteres aleatórios: não custa nada. Se você precisa decorar, use uma frase-senha de 6 ou mais palavras aleatórias. Tamanho vence regras de complexidade: uma senha longa e aleatória só com minúsculas é mais forte que uma curta cheia de símbolos."
---

## Como funciona

### O gerador

Cada caractere vem de `crypto.getRandomValues()`, o gerador de números aleatórios criptograficamente seguro da Web Crypto API, que o navegador alimenta com a fonte de entropia do sistema operacional. `Math.random()` nunca é usado.

Para transformar um número aleatório de 32 bits em uma posição no conjunto de caracteres, o PassFort usa **amostragem por rejeição**: valores que caem no último "bloco" incompleto da faixa de 32 bits são descartados e sorteados de novo. O simples `aleatório % tamanho` deixaria os primeiros caracteres do conjunto um pouco mais prováveis. O viés é minúsculo, mas não há motivo para aceitá-lo.

Os quatro grupos são 26 maiúsculas, 26 minúsculas, 10 números e 26 símbolos (`!@#$%^&*()_+-=[]{}|;:,.<>?`), 88 caracteres no total. Cada caractere acrescenta log₂(88) ≈ **6,46 bits** de entropia:

| Tamanho | Os quatro grupos | Só minúsculas |
|---|---|---|
| 12 | ≈ 77 bits | ≈ 56 bits |
| 16 | ≈ 103 bits | ≈ 75 bits |
| 20 (padrão) | ≈ 129 bits | ≈ 94 bits |

Os caracteres são sorteados de forma independente, então não é *garantido* que uma senha curta tenha todos os grupos marcados. Gere outra se um site exigir, por exemplo, um número.

### O modo frase-senha

O modo frase-senha escolhe palavras de uma lista interna de **1.207 palavras em inglês** com o mesmo índice aleatório sem viés, coloca a inicial de cada uma em maiúscula e as une com hífens (por exemplo `Harbor-Canyon-Crisp-Velvet`). Cada palavra acrescenta log₂(1207) ≈ **10,24 bits**: 4 palavras dão cerca de 41 bits, 6 palavras cerca de 61 bits e o máximo de 8 palavras cerca de 82 bits.

É menos por palavra do que uma lista Diceware completa de 7.776 palavras (12,9 bits), e por isso esta página recomenda pelo menos 6 palavras para qualquer coisa importante. As maiúsculas e os hífens são fixos, então não acrescentam entropia.

### O auditor

O auditor estima o tamanho do "alfabeto" de onde vem a sua senha: 26 se houver uma minúscula, +26 para maiúsculas, +10 para números e +33 para qualquer outro caractere. A entropia é então `tamanho × log₂(alfabeto)`.

O tempo para quebrar é o necessário para testar todas as 2^entropia combinações a **10¹⁰ tentativas por segundo**, mostrado em unidades compreensíveis até "séculos". O medidor fica cheio em 100 bits e passa de vermelho para laranja, amarelo e verde em 25, 50 e 75 bits. Abaixo aparecem oito verificações: pelo menos 8 e 12 caracteres, cada classe de caracteres, nenhum padrão inicial comum e pelo menos 60 bits.

É o modelo clássico de "força bruta". É preciso para senhas aleatórias como as do gerador e **otimista para senhas inventadas por pessoas**, porque não enxerga palavras de dicionário, nomes ou datas.

## Casos de uso

- **Contas novas.** Gere uma senha de 16–20 caracteres e guarde no gerenciador de senhas. Você nunca mais vai precisar vê-la.
- **As senhas que você precisa lembrar.** Senha mestra do gerenciador, login do computador, criptografia de disco: use uma frase-senha de 6–8 palavras que você consiga digitar sem errar.
- **Revisar velhos hábitos.** Cole uma senha que você usa há anos, veja a pontuação e troque as fracas, começando pelo e-mail e pelo banco.
- **Senhas de Wi-Fi e segredos compartilhados.** Frases-senha WPA2/WPA3 aceitam até 63 caracteres: uma longa e aleatória não custa nada e impede a quebra offline de um handshake capturado.
- **Treinamento e políticas.** A tabela acima e o medidor ao vivo tornam a entropia concreta quando você explica aos colegas por que "8 caracteres com um símbolo" não é mais uma boa regra.
