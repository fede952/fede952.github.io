---
title: "Gerador de Senhas Fortes e Aleatórias"
description: "Gere senhas aleatórias fortes de até 64 caracteres com o gerador criptográfico do navegador. Entropia ao vivo e cópia com um clique, sem servidor."
intro: "Um **gerador de senhas fortes** com um clique: escolha o tamanho e os tipos de caracteres e receba uma senha aleatória tirada do gerador criptográfico do seu navegador, com a força indicada em bits."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["gerador de senhas", "gerador de senha forte", "gerador de senha aleatória", "criar senha segura", "gerar senha online", "senha de 16 caracteres", "senha forte"]
tags: ["segurança", "senhas", "ferramenta"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Arraste o controle **Tamanho** (de 8 a 64 caracteres). A cada movimento uma nova senha é gerada na hora."
  - "Desmarque os grupos de caracteres que o site não aceita: maiúsculas **A–Z**, minúsculas **a–z**, números **0–9** ou símbolos **!@#**."
  - "Confira a linha abaixo da senha: ela mostra a entropia em bits e uma classificação (Fraca, Boa, Forte)."
  - "Clique em **Gerar senha** para obter outra; o botão de copiar ao lado do campo manda a senha para a área de transferência."
  - "Cole no seu gerenciador de senhas *antes* de fechar a página: o gerador não guarda histórico."
faq:
  - q: "Este gerador de senhas é realmente aleatório?"
    a: "Sim. Cada caractere é escolhido com `crypto.getRandomValues()`, o gerador de números aleatórios criptograficamente seguro do navegador, com amostragem por rejeição para que todos os caracteres do conjunto tenham exatamente a mesma probabilidade. Ele não usa `Math.random()`, que é previsível e não serve para segredos."
  - q: "O site consegue ver as senhas que eu gero?"
    a: "Não. O gerador são poucas linhas de JavaScript rodando no seu navegador: nenhuma requisição a servidor, nenhum log, nenhum armazenamento. Desconecte da internet depois de carregar a página e ele continua funcionando, que é a prova mais simples."
  - q: "Qual tamanho devo escolher?"
    a: "Com os quatro grupos, 16 caracteres dão cerca de 104 bits de entropia, muito além do alcance de qualquer ataque de força bruta. Use 20 ou mais para contas muito sensíveis, se o site permitir. Só fique abaixo de 12 se um sistema antigo obrigar."
  - q: "Por que minha senha não tem nenhum símbolo se os símbolos estão ativados?"
    a: "Cada caractere é sorteado de forma independente dentro de todo o conjunto, então a senha não é obrigada a ter um caractere de cada tipo. Com 16 caracteres isso quase sempre acontece. Se um site recusar a senha por falta de símbolo ou número, gere outra."
  - q: "O que significam Fraca, Boa e Forte?"
    a: "São faixas de entropia: abaixo de 60 bits é Fraca, de 60 a 90 bits é Boa e de 90 bits para cima é Forte. Como a senha é gerada ao acaso, o número é exato, ao contrário dos medidores que tentam adivinhar a entropia de uma senha que você mesmo criou."
  - q: "Preciso decorar essas senhas?"
    a: "Não: guarde-as em um gerenciador de senhas e deixe que ele preencha. Para a uma ou duas senhas que você precisa mesmo decorar, como a senha mestra do gerenciador, uma frase-senha longa e aleatória é mais prática; o PassFort, neste site, gera uma."
---

## Como funciona

O gerador monta um conjunto com os grupos marcados: 26 maiúsculas, 26 minúsculas, 10 números e 29 símbolos (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), até **91 caracteres**. Para cada posição, ele pede à Web Crypto API um número aleatório de 32 bits com `crypto.getRandomValues()` e o converte em um caractere.

Essa conversão usa **amostragem por rejeição**. 2³² não é múltiplo de 91, então o simples `aleatório % 91` deixaria alguns caracteres um pouquinho mais prováveis que os outros. Em vez disso, qualquer valor que caia na última faixa incompleta do intervalo de 32 bits é descartado e sorteado de novo, e todo caractere fica com exatamente a mesma probabilidade.

A linha de força não é um chute. Como cada caractere é uniformemente aleatório, a entropia é exatamente **tamanho × log₂(tamanho do conjunto)**:

| Configuração | Bits por caractere | 12 car. | 16 car. | 24 car. |
|---|---|---|---|---|
| Os quatro grupos (91) | 6,51 | 78 | 104 | 156 |
| Letras + números (62) | 5,95 | 71 | 95 | 143 |
| Minúsculas + números (36) | 5,17 | 62 | 83 | 124 |
| Só números (10) | 3,32 | 40 | 53 | 80 |

A classificação é **Fraca** abaixo de 60 bits, **Boa** de 60 a 90 bits e **Forte** a partir de 90 bits; a barra fica cheia em 128 bits. Mudar o tamanho ou uma caixa gera uma nova senha na hora, então o que você vê sempre corresponde à configuração.

A cópia usa a Clipboard API assíncrona quando a página é servida por HTTPS, com uma alternativa para navegadores antigos. A senha só existe no campo de texto: recarregue a página e ela some.

### Por que a entropia é a medida certa

Um atacante que conheça este gerador em detalhe, conjunto e tamanho incluídos, ainda precisa testar em média metade das 2^bits combinações. Com 104 bits, são cerca de 10³¹ tentativas: mesmo a 10 bilhões por segundo levaria muito mais que a idade do universo. É por isso que uma senha de um bom gerador é forte *por construção*, enquanto uma senha inventada só é forte se o dicionário do atacante for pequeno.

## Casos de uso

- **Criar conta em um serviço novo.** Gere 16 ou mais caracteres, guarde no gerenciador de senhas e pronto.
- **Trocar a senha depois de um vazamento.** Substitua uma senha reutilizada ou vazada por uma única e aleatória, começando pelo e-mail, porque por ele dá para redefinir todas as outras.
- **Chaves de API, usuários de banco de dados e contas de serviço.** Desmarque os símbolos se uma string de conexão ou um script de shell der problema com eles, e aumente o tamanho para manter a entropia acima de 100 bits.
- **Redes Wi-Fi.** Gere uma chave de 20–30 caracteres para o roteador; você só digita uma vez por aparelho.
- **Credenciais temporárias.** Crie uma senha descartável para uma conta de convidado ou um documento compartilhado e apague a conta quando terminar.

Para testar a força de uma senha que você já usa, e saber se ela aparece em um vazamento de dados conhecido, experimente o [PassFort](/pt/tools/pass-fort/).
