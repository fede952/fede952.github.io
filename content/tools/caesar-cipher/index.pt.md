---
title: "Cifra de César: Cifrar e Decifrar (ROT13)"
description: "Cifre e decifre textos com a cifra de César, com qualquer deslocamento de 1 a 25, ROT13 incluído. Entenda como funciona e como é quebrada. Grátis."
intro: "Desloque cada letra do seu texto um número fixo de posições no alfabeto, a cifra que Júlio César usava. Escolha um deslocamento de 1 a 25 (13 dá o **ROT13**) e cifre ou decifre. Um clássico para enigmas, CTFs e para entender por que cifras simples falham."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cifra de césar", "decifrar cifra de césar", "código de césar", "rot13", "cifra de deslocamento", "cifrar texto", "criptografia clássica", "cifra de césar online"]
tags: ["criptografia", "cifra", "ctf", "ferramenta"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Digite ou cole sua mensagem em **Texto de entrada**."
  - "Ajuste o **Deslocamento** no controle (1–25). César usava 3; 13 é o ROT13."
  - "Clique em **Cifrar** para deslocar as letras para a frente, ou em **Decifrar** para voltá-las na mesma quantidade."
  - "Leia o resultado em **Resultado** e clique em **Copiar** para mandá-lo para a área de transferência."
  - "Para quebrar uma mensagem desconhecida, decifre com cada deslocamento até aparecerem palavras legíveis: só há 25 para testar."
faq:
  - q: "Como funciona a cifra de César?"
    a: "Cada letra é trocada pela que está um número fixo de posições à frente no alfabeto, voltando para o A depois do Z. Com deslocamento 3, A vira D, B vira E e Z vira C. Para decifrar, volta-se o mesmo número."
  - q: "O que é ROT13?"
    a: "ROT13 é a cifra de César com deslocamento 13. Como o alfabeto tem 26 letras, aplicar duas vezes devolve o texto original, então a mesma operação cifra e decifra. Era usada em fóruns para esconder spoilers e finais de piada, nunca para segurança."
  - q: "A cifra de César é segura?"
    a: "Não. Só existem 25 chaves úteis, então qualquer pessoa testa todas à mão em segundos. A análise de frequência quebra ainda mais rápido: em português as letras mais comuns são A e E, que aparecem no texto cifrado deslocadas pela chave. Use só para brincadeiras e ensino."
  - q: "O que acontece com números, espaços e letras acentuadas?"
    a: "Ficam iguais. A ferramenta só desloca as 26 letras latinas básicas A–Z e a–z, mantendo maiúsculas e minúsculas. Números, pontuação, espaços e letras como ã ou ç passam do jeito que estão."
  - q: "Como decifrar uma cifra de César sem a chave?"
    a: "Por força bruta: decifre com os deslocamentos de 1 a 25 e procure o que gera texto legível. Em mensagens maiores, conte as letras: a mais frequente costuma ser o A ou o E em português, e a distância entre elas é o deslocamento."
  - q: "Meu texto é enviado para algum lugar?"
    a: "Não. O deslocamento é calculado por poucas linhas de JavaScript nesta página e nada é enviado."
---

## Como funciona

A ferramenta percorre o seu texto caractere por caractere e verifica o código de cada um:

- maiúsculas `A–Z` (códigos 65–90) são deslocadas dentro do alfabeto maiúsculo;
- minúsculas `a–z` (códigos 97–122), dentro do alfabeto minúsculo;
- todo o resto (números, espaços, pontuação, letras acentuadas e não latinas) é copiado sem mudança.

O deslocamento é aritmética modular sobre a posição *p* da letra (0 para A, 25 para Z) e a chave *k*:

**cifrado = (p + k) mod 26**, e a decifração usa −k.

Como em JavaScript o `%` pode devolver números negativos, o código calcula `((p + k) % 26 + 26) % 26`, o que mantém o resultado entre 0 e 25 nos dois sentidos. Depois a posição volta a ser um caractere, com a caixa original.

| Texto claro | Deslocamento 3 | Deslocamento 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Por que é tão fácil de quebrar

A cifra de César tem um espaço de chaves de 25. Um computador, ou uma pessoa paciente, testa todas as chaves num instante. E como cada letra sempre corresponde à mesma letra, o texto cifrado guarda a impressão estatística do idioma: o símbolo mais frequente de um texto cifrado é quase sempre uma das letras mais comuns deslocada pela chave. Essas duas fraquezas, espaço de chaves minúsculo e frequências preservadas, são exatamente o que cifras modernas como o AES foram feitas para evitar.

## Casos de uso

- **Desafios de CTF e enigmas.** César e ROT13 aparecem o tempo todo em CTFs para iniciantes, escape rooms e geocaching.
- **Ensinar criptografia.** Mostre cifragem, chaves e força bruta com algo que dá para fazer no papel, e depois explique por que falha.
- **Esconder spoilers.** O ROT13 ainda esconde o final de uma piada ou uma solução de uma leitura sem querer.
- **Exercícios de programação.** Compare a sua implementação com esta: a aritmética modular e o tratamento de maiúsculas são as pegadinhas comuns.
- **Curiosidade histórica.** Codifique uma mensagem como os generais romanos faziam, com deslocamento 3.
