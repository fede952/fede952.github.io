---
title: "Ocultar dados em captura de tela"
description: "Cubra e-mails, nomes, IBAN e outras partes sensíveis de uma captura de tela. Caixas sólidas gravadas nos pixels, metadados removidos, tudo no navegador."
intro: "Cole uma captura (Ctrl+V), arraste uma imagem ou escolha uma, e depois **arraste para cobrir** o que for sensível: endereços de e-mail, nomes, números de conta, rostos, URLs. As áreas cobertas são **caixas sólidas gravadas nos pixels** — sem camadas para remover — e o PNG ou JPEG exportado **não tem metadados**. Uma ajuda opcional pode **sugerir caixas** sobre e-mails, IBAN, números de cartão e telefone e endereços IP. Nada é enviado."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["ocultar dados em captura de tela", "tarjar texto em imagem", "censurar print", "esconder informações sensíveis em print", "desfocar imagem online", "pixelar imagem online", "apagar dados pessoais de print", "cobrir texto em imagem"]
tags: ["privacidade", "imagens", "segurança", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Ocultador de capturas de tela"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Cole uma captura com **Ctrl+V** (⌘V no Mac), arraste uma imagem para a caixa ou clique em **Escolher uma imagem**."
  - "Mantenha **Caixa sólida** selecionada (preta por padrão; escolha outra **Cor** se quiser) e arraste sobre cada área a esconder. No celular, arraste com um dedo e use **Mover** para rolar uma imagem ampliada."
  - "Opcional: clique em **Sugerir áreas** para encontrar e-mails, IBAN, números de cartão, telefones e endereços IP com reconhecimento de texto no seu dispositivo. Desmarque as sugestões que quer manter visíveis e **cubra** o resto."
  - "Use **Desfazer** / **Refazer** (Ctrl+Z / Ctrl+Y) e os botões de zoom para conferir as bordas de cada caixa."
  - "Escolha **PNG** (texto nítido) ou **JPEG** (fotos mais leves) e clique em **Baixar a imagem ocultada**, ou **Copiar imagem** para colar direto num chat ou chamado."
faq:
  - q: "Minha imagem é enviada para algum lugar?"
    a: "Não. A imagem é decodificada, editada e exportada no seu navegador. O reconhecimento de texto opcional também roda no seu dispositivo; na primeira vez ele baixa os arquivos de reconhecimento (cerca de 10 MB) deste site, nunca de terceiros, e a imagem em si não é enviada a lugar nenhum."
  - q: "Por que uma caixa sólida é mais segura que desfoque ou pixelização?"
    a: "Uma caixa sólida substitui os pixels por uma só cor: nada do original sobra. Desfoque e pixelização guardam uma versão reduzida dos pixels originais. Com textos curtos ou previsíveis — números, dígitos de cartão, nomes numa fonte conhecida — às vezes isso basta para reconstruir ou adivinhar o conteúdo, por exemplo desfocando ou pixelando do mesmo jeito textos candidatos e comparando os resultados. Use esses modos só para o que precisa apenas chamar menos atenção."
  - q: "Dá para remover a ocultação do arquivo baixado?"
    a: "Não. A exportação é uma imagem nova desenhada a partir dos pixels editados: sem camadas, sem original escondido e sem histórico de edição no arquivo. Essa é a diferença em relação a cobrir texto com uma forma num documento ou PDF, onde muitas vezes o texto embaixo ainda pode ser selecionado."
  - q: "Remove os dados EXIF e GPS?"
    a: "Sim. O PNG ou JPEG exportado é codificado do zero pelo navegador e não contém metadados: nem modelo da câmera, nem data, nem posição GPS. A orientação da foto é aplicada antes aos pixels, então a imagem continua na posição certa."
  - q: "O que a sugestão automática encontra?"
    a: "Endereços de e-mail, IBAN (verificados pelo dígito de controle mod 97), números de cartão (verificados pelo algoritmo de Luhn), telefones e endereços IPv4 e IPv6. Funciona com texto de tela em alfabeto latino. Não detecta nomes, rostos, endereços nem escrita à mão — confira sempre a imagem antes de compartilhar."
  - q: "Que formatos de imagem posso abrir?"
    a: "Qualquer um que o seu navegador consiga exibir: PNG, JPEG, WebP, GIF (primeiro quadro) e normalmente AVIF e BMP. Fotos HEIC do iPhone precisam ser convertidas antes, por exemplo com o conversor HEIC deste site."
---

## Como funciona

### As áreas cobertas são pixels, não camadas

A imagem é decodificada num canvas em resolução total, com a orientação EXIF da foto aplicada. Cada caixa que você desenha é guardada como um retângulo, e a composição de imagem mais caixas é refeita a partir dos pixels originais a cada desenho, desfazer ou refazer. Na exportação, essa composição é codificada num PNG ou JPEG totalmente novo. O arquivo contém só os pixels finais: o que estava sob uma caixa não existe mais nele.

É por isso que tarjas feitas em editores de documentos falham tantas vezes: um retângulo preto desenhado sobre um texto num documento ou PDF é um objeto separado, e o texto embaixo ainda pode ser selecionado ou extraído. Aqui não há nada embaixo.

### Por que desfoque e pixelização vêm com um aviso

A pixelização troca cada bloco de pixels pela sua cor média; o desfoque espalha cada pixel pelos vizinhos. Os dois descartam informação, mas não toda. Num texto, o formato de cada letra continua influindo no resultado, e os originais possíveis costumam ser poucos: um número de cartão tem só dez dígitos possíveis por posição, e capturas de tela usam um punhado de fontes conhecidas. Dá para escrever textos candidatos na mesma fonte, pixelar ou desfocar do mesmo jeito e ficar com o que bate. Ferramentas públicas e pesquisas já mostraram isso funcionando com senhas e números pixelados. Uma caixa sólida não deixa nada para comparar: por isso ela é o modo padrão e o único recomendado para o que é secreto.

### As sugestões opcionais

O reconhecimento de texto usa o Tesseract, um motor de OCR de código aberto compilado para WebAssembly e servido por este site. Ele só carrega quando você clica em **Sugerir áreas**. As palavras reconhecidas são comparadas com padrões de e-mail, IBAN, cartão, telefone e endereço IP; IBAN e cartões ainda precisam passar no dígito verificador, o que reduz alarmes falsos. Cada correspondência vira uma caixa tracejada que você aceita ou descarta.

## Casos de uso

- **Relatos de bug e chamados de suporte** — compartilhe o print de um erro sem o seu e-mail, o ID da conta ou uma chave de API.
- **Redes sociais e fóruns** — publique uma conversa ou um recibo com nomes, telefones e números de pedido cobertos.
- **Documentação e tutoriais** — esconda URLs internas, endereços IP e dados de clientes em prints de painéis de administração.
- **Prestação de contas** — envie a foto de um recibo ou transferência com o número da conta tarjado.
- **Trabalho de segurança** — inclua evidências num relatório sem vazar as credenciais ou os dados pessoais que elas contêm.
