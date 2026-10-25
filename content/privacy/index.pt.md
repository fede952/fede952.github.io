---
title: "Política de Privacidade"
description: "Como o federicosella.com trata seus dados: ferramentas que processam tudo localmente no navegador sem uploads, estatísticas sem cookies, anúncios com consentimento e links de afiliado sinalizados."
date: 2026-07-04
lastmod: 2026-10-26
hidemeta: true
showToc: true
---

**Última atualização: 24 de outubro de 2026**

## 1. Controlador dos dados

**Federico Sella** — Itália
E-mail: [privacy@federicosella.com](mailto:privacy@federicosella.com)

## 2. Resumo

- **As ferramentas web deste site processam seus dados localmente, no seu navegador.** Arquivos, senhas, imagens e textos que você insere nas ferramentas **nunca são enviados** a nenhum servidor, nosso ou de terceiros. A única exceção (a consulta de IP do NetGuard) está descrita na seção 3.
- Sem contas, sem newsletter, e nunca vendemos dados pessoais.
- O site é financiado pelo **Google AdSense**. O banner de consentimento do Google pede sua permissão antes de usar qualquer cookie de publicidade.
- As estatísticas são **sem cookies** (Umami). Este site não usa Google Analytics.
- Algumas páginas contêm **links de afiliado** claramente sinalizados (seção 7).
- Você pode alterar ou retirar seu consentimento a qualquer momento em **"Configurações de Cookies"** no rodapé.

## 3. As ferramentas web: processamento local

Todas as ferramentas interativas do site (gerador e verificador de senhas, limpador de EXIF, compressor de imagens, gerador de QR code, JWT inspector, scanner de segredos, conversores e as demais) funcionam no seu navegador com JavaScript e APIs web padrão como a Web Crypto API e a Canvas API. Os dados que você insere ou os arquivos que abre com elas:

- são processados **somente no seu dispositivo**;
- **nunca são transmitidos** aos nossos servidores ou a terceiros;
- são descartados quando você fecha ou recarrega a página, a menos que você mesmo salve o resultado.

**Uma exceção, intencional:** o **NetGuard** mostra seu endereço IP público e sua localização aproximada. Para isso, seu navegador envia uma requisição ao serviço de consulta de IP [ipwho.is](https://ipwho.is/). Como qualquer requisição web, ela revela a esse serviço seu endereço IP (e o user-agent do navegador). Nada mais é enviado, e a requisição só é feita quando você clica em Scan no NetGuard.

**Uma segunda exceção, opcional:** o auditor do **PassFort** pode verificar se uma senha aparece em vazamentos de dados conhecidos. Isso só acontece quando você clica em **Check against known breaches**. O navegador calcula então o hash SHA-1 da senha e envia só os 5 primeiros caracteres ao serviço Pwned Passwords do Have I Been Pwned em [api.pwnedpasswords.com](https://haveibeenpwned.com/Passwords) (k-anonimato); a senha e o resto do hash nunca são enviados, e a comparação acontece no seu dispositivo. Como qualquer requisição web, ela revela a esse serviço seu endereço IP e o user-agent do navegador.

**Uma terceira exceção, sob demanda:** o **Verificador de SPF, DKIM e DMARC** consulta os registros DNS públicos de um domínio. Quando você clica em **Verificar**, seu navegador envia consultas DNS do domínio digitado (registros TXT de SPF, DMARC, seletores DKIM e BIMI, e registros MX) ao resolvedor público DNS-over-HTTPS da Cloudflare, [cloudflare-dns.com](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/). Nada mais é enviado, e nada sai antes de você clicar no botão. Como qualquer requisição web, isso revela à Cloudflare seu endereço IP e o user-agent do navegador.

Algumas ferramentas também oferecem links para serviços externos (por exemplo "verificar esta URL no VirusTotal" no Link Hazmat, ou os botões de compartilhar). São links comuns: nada é enviado até você clicar.

Você pode conferir tudo isso nas ferramentas de desenvolvedor do navegador (aba Rede).

## 4. Hospedagem e recursos das páginas

Este é um site estático hospedado no **GitHub Pages** (GitHub, Inc.). Como qualquer hospedagem, o GitHub trata seu endereço IP para entregar as páginas e pode manter logs do servidor por motivos de segurança. Veja a [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

Fontes e bibliotecas JavaScript são **hospedadas neste domínio**. O site não carrega Google Fonts nem nenhuma CDN pública, então visitar uma página não envia requisições a esses serviços.

## 5. Estatísticas (Umami, sem cookies)

Usamos o [Umami](https://umami.is/) para contar visualizações de página. O Umami **não usa cookies** nem **identificadores persistentes**. Ele registra apenas estatísticas anônimas e agregadas (páginas vistas, site de origem, tipo de navegador e dispositivo, país) que não podem ser associadas a você. Como nenhum dado pessoal é armazenado e nada é gravado no seu dispositivo, isso se baseia no nosso legítimo interesse em entender quais conteúdos são úteis.

## 6. Publicidade (Google AdSense)

A publicidade mantém todas as ferramentas do site gratuitas. Usamos o **Google AdSense** (Google Ireland Ltd. / Google LLC). Para visitantes do EEE, Reino Unido e Suíça, a **plataforma de gerenciamento de consentimento certificada** do Google (IAB Transparency & Consent Framework) pede sua escolha antes de usar qualquer cookie de publicidade:

- Com consentimento, o Google e seus parceiros podem exibir **anúncios personalizados** e usar cookies de publicidade.
- Sem consentimento, só podem ser exibidos anúncios **não personalizados** ou limitados, sem cookies de personalização.

Os anúncios aparecem apenas nas páginas de ferramentas e guias, nunca dentro das ferramentas. Como o Google usa dados de sites parceiros: [policies.google.com/technologies/partner-sites](https://policies.google.com/technologies/partner-sites). Gerencie suas preferências de anúncios: [adssettings.google.com](https://adssettings.google.com).

## 7. Links de afiliado

Algumas páginas recomendam produtos de terceiros (por exemplo uma VPN ou um gerenciador de senhas) por meio de **links de afiliado**, marcados com "Link de afiliado" ao lado do link. Se você clicar e comprar algo, posso receber uma comissão **sem nenhum custo extra para você**. As recomendações são escolhidas por combinarem com a ferramenta que você está usando, não pela comissão.

Ao clicar em um link de afiliado você vai para o site do parceiro, que pode definir seus próprios cookies para atribuir a indicação. Isso acontece no site dele, sob a política de privacidade dele. Este site não recebe dos parceiros nenhum dado pessoal sobre você, apenas relatórios agregados de comissões.

## 8. Bases legais (RGPD/LGPD)

- **Consentimento** (art. 6(1)(a) RGPD): cookies de publicidade.
- **Legítimo interesse** (art. 6(1)(f) RGPD): funcionamento e segurança do site, estatísticas agregadas sem cookies.

## 9. Seus direitos

Pelo RGPD (e pela LGPD, para visitantes do Brasil) você tem direito de acessar, corrigir e excluir seus dados, de limitar ou se opor ao tratamento, à portabilidade e de retirar o consentimento a qualquer momento (em **Configurações de Cookies** no rodapé). Para exercer qualquer direito, escreva para [privacy@federicosella.com](mailto:privacy@federicosella.com). Você também pode apresentar reclamação à autoridade italiana ([Garante per la Protezione dei Dati Personali](https://www.garanteprivacy.it/)) ou à autoridade do seu país (no Brasil, a [ANPD](https://www.gov.br/anpd/)).

## 10. Transferências internacionais

O Google e o GitHub podem tratar dados nos Estados Unidos. Essas transferências se baseiam no **EU–U.S. Data Privacy Framework** e/ou em **Cláusulas Contratuais Padrão**.

## 11. Retenção de dados

Este site **não armazena dados pessoais em servidores próprios**: é um site estático sem banco de dados. O Umami guarda apenas agregados anônimos. O Google e os parceiros de afiliados retêm dados conforme suas próprias políticas.

## 12. Menores

Este site não se destina a menores de 16 anos, e não coletamos conscientemente seus dados.

## 13. Alterações

As atualizações serão publicadas nesta página com uma nova data de "Última atualização".

## 14. Documentos relacionados

- [Política de Cookies](/pt/cookies/)
- [Contato](/pt/contact/)
- Procurando a política de privacidade do app **Pasta Stack**? Veja [Pasta Stack — App Privacy Policy](/en/apps/pasta-stack/privacy/) (em inglês).
