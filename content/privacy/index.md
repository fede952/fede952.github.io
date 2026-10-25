---
title: "Privacy Policy"
description: "How federicosella.com handles your data: browser tools that process everything locally with zero uploads, cookieless analytics, consent-based ads and disclosed affiliate links."
date: 2026-07-04
lastmod: 2026-10-25
hidemeta: true
showToc: true
---

**Last updated: October 24, 2026**

## 1. Data Controller

**Federico Sella** — Suisio (Bergamo), Italy
Email: [privacy@federicosella.com](mailto:privacy@federicosella.com)

## 2. The Short Version

- **The web tools on this site process your data locally in your browser.** Files, passwords, images and text you enter in the tools are **never uploaded** to any server, ours or anyone else's. The single exception (NetGuard's IP lookup) is described in section 3.
- No accounts, no newsletters, and we never sell personal data.
- The site is funded by **Google AdSense**. Google's consent banner asks for your consent before any advertising cookies are used.
- Analytics are **cookieless** (Umami). There is no Google Analytics on this site.
- Some pages contain clearly marked **affiliate links** (section 7).
- You can change or withdraw your consent at any time via **"Cookie Settings"** in the footer.

## 3. The Web Tools: Local Processing

Every interactive tool on this site (password generator and auditor, EXIF cleaner, image compressor, QR generator, JWT inspector, secrets scanner, converters and the rest) runs in your browser using JavaScript and standard Web APIs such as the Web Crypto API and the Canvas API. The data you enter or the files you open with these tools:

- are processed **on your device only**;
- are **never transmitted** to our servers or to third parties;
- are discarded when you close or reload the page, unless you save the result yourself.

**One exception, by design:** **NetGuard** shows you your public IP address and its approximate location. To do that, your browser sends a request to the IP-lookup service [ipwho.is](https://ipwho.is/). Like any web request, this reveals your IP address (and browser user-agent) to that service. Nothing else is sent, and the request is made only when you click Scan in NetGuard.

**A second exception, opt-in:** the **PassFort** auditor can check whether a password appears in known data breaches. This happens only when you press **Check against known breaches**. Your browser then computes the password's SHA-1 hash and sends only its first 5 characters to Have I Been Pwned's Pwned Passwords service at [api.pwnedpasswords.com](https://haveibeenpwned.com/Passwords) (k-anonymity); the password and the rest of its hash are never sent, and the comparison happens on your device. Like any web request, it reveals your IP address and browser user-agent to that service.

Some tools also offer links to external services (for example "check this URL on VirusTotal" in Link Hazmat, or share buttons). Those are ordinary links: nothing is sent until you click one.

You can check all of this with your browser's developer tools (Network tab).

## 4. Hosting and Page Resources

This is a static website hosted on **GitHub Pages** (GitHub, Inc.). Like any web host, GitHub processes your IP address to deliver the pages and may keep server logs for security purposes. See the [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

Fonts and JavaScript libraries are **self-hosted** on this domain. The site does not load Google Fonts or any public CDN, so viewing a page sends no request to those services.

## 5. Analytics (Umami, cookieless)

We use [Umami](https://umami.is/) to count page views. Umami uses **no cookies** and **no persistent identifiers**. It records only anonymous, aggregated statistics (pages viewed, referrer, browser and device type, country) that cannot be tied to you. Because no personal data is stored and nothing is written to your device, it runs on the basis of our legitimate interest in understanding which content is useful.

## 6. Advertising (Google AdSense)

Advertising keeps every tool on this site free. We use **Google AdSense** (Google Ireland Ltd. / Google LLC). For visitors in the EEA, the UK and Switzerland, Google's **certified consent management platform** (IAB Transparency & Consent Framework) asks for your choice before any advertising cookies are used:

- With consent, Google and its partners may show **personalized ads** and use advertising cookies.
- Without consent, only **non-personalized** or limited ads may be shown, which use no cookies for personalization.

Ads are shown only on tool and guide pages, never inside the tools themselves. How Google uses data from partner sites: [policies.google.com/technologies/partner-sites](https://policies.google.com/technologies/partner-sites). Manage your ad preferences: [adssettings.google.com](https://adssettings.google.com).

## 7. Affiliate Links

Some pages recommend third-party products (for example a VPN or a password manager) through **affiliate links**. They are labelled "Affiliate link" next to the link. If you click one and buy something, I may earn a commission **at no extra cost to you**. Recommendations are chosen because they fit the tool you are using, not because of the commission.

Clicking an affiliate link takes you to the partner's website, which may set its own cookies to attribute the referral. That happens on their site, under their privacy policy. This site receives no personal data about you from affiliate partners, only aggregated commission reports.

## 8. Legal Bases (GDPR)

- **Consent** (Art. 6(1)(a)): advertising cookies.
- **Legitimate interest** (Art. 6(1)(f)): delivering and securing the site, cookieless aggregate statistics.

## 9. Your Rights

Under the GDPR you have the right to access, rectify and erase your data, to restrict or object to processing, to data portability, and to withdraw consent at any time (via **Cookie Settings** in the footer). To exercise any right, email [privacy@federicosella.com](mailto:privacy@federicosella.com). You may also lodge a complaint with the Italian supervisory authority ([Garante per la Protezione dei Dati Personali](https://www.garanteprivacy.it/)) or your local authority.

## 10. International Transfers

Google and GitHub may process data in the United States. Such transfers rely on the **EU–U.S. Data Privacy Framework** and/or **Standard Contractual Clauses**.

## 11. Data Retention

This website stores **no personal data on its own servers**: it is a static site with no database. Umami keeps only anonymous aggregates. Google and affiliate partners retain data according to their own policies.

## 12. Children

This site is not directed at children under 16, and we do not knowingly collect their data.

## 13. Changes

Updates will be posted on this page with a new "Last updated" date.

## 14. Related Documents

- [Cookie Policy](/en/cookies/)
- [Contact](/en/contact/)
- Looking for the **Pasta Stack** mobile app privacy policy? See [Pasta Stack — App Privacy Policy](/en/apps/pasta-stack/privacy/).
