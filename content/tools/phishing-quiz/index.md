---
title: "Phishing Quiz: Can You Spot the Phish?"
description: "Free phishing test: 10 realistic emails, SMS, login pages, QR codes and links. Spot the phish, see the red flags on each one, and share your score."
intro: "Ten realistic scenarios — **emails, text messages, login pages, QR codes and links** — drawn at random from a pool of 32. Decide for each one: **phishing or legitimate?** After every answer the red flags are highlighted right on the mockup, with a one-line explanation. Every brand and domain is fictional, and nothing you do leaves your browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["phishing quiz", "phishing test", "spot the phish", "phishing awareness quiz", "phishing simulation", "how to recognize phishing", "smishing quiz", "security awareness training"]
tags: ["security", "phishing", "awareness", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Phishing Quiz"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "I scored {score}/10 on the Phishing Quiz"
howto:
  - "Press **Start the quiz**. You get 10 scenarios; three or four of them are legitimate, so \"everything is phishing\" won't win."
  - "Read the context line, then inspect the mockup like the real thing: the sender address, where the link really goes (hover or focus the button), the address bar, the attachment name."
  - "Answer **Phishing** or **Legitimate**. The red flags (or the signs of a genuine message) are numbered on the mockup and explained underneath."
  - "At the end you get a score, a rank and the topics to review, with links to tools that help with each one."
  - "Use **Share my score** to send the result: the shared text contains only the score and a link."
faq:
  - q: "Are the companies in the quiz real?"
    a: "No. Every brand, person, phone number and domain is invented, and all web addresses use domains reserved for documentation (.example, .test) or the 192.0.2.x documentation IP range, so nothing in the quiz points at a real organisation."
  - q: "Is my score or anything I click sent anywhere?"
    a: "No. The quiz runs entirely in your browser and makes no network request. Nothing is stored. Sharing is up to you: the share button only passes the score and the quiz address to your phone's share menu, or copies them."
  - q: "How are the questions chosen?"
    a: "Each round draws 10 of 32 scenarios at random, with three or four legitimate ones and at least three different kinds (email, SMS, login page, QR code, link). Playing again gives you a different mix."
  - q: "What are smishing and quishing?"
    a: "Smishing is phishing by SMS or chat message. Quishing is phishing through a QR code: on a sticker, a poster or inside an email. A QR code hides the address until you scan it, and it moves you to your phone, where you can't hover over a link before opening it."
  - q: "What should I do with a real phishing message?"
    a: "Don't click, reply or open attachments. Report it — at work to your IT or security team, otherwise with your email provider's \"Report phishing\" option — then delete it. If you already typed a password, change it at once on the real site and turn on two-factor authentication."
  - q: "Can I use it for security awareness training?"
    a: "Yes, it's free and needs no sign-up. See \"Use it for team training\" below for a simple way to run it in a meeting."
---

## How it works

Each scenario is a mockup built from real page elements, not a picture, so it can be read with a screen reader and played with the keyboard alone. It comes with a context line ("You are waiting for a delivery…"), because whether a message is suspicious often depends on what you were doing.

The scenarios cover the patterns behind most phishing:

- **Sender and lookalike domains** — `velorabank-alerts.test` instead of `velorabank.example`, a digit 1 in place of an l.
- **Where a link really goes** — the visible text says one thing, the target another; a familiar name only as a subdomain of someone else's domain; the `@` trick.
- **Pressure** — deadlines, threats of suspension, secrecy, "I can't talk right now".
- **Requests no genuine service makes** — card PINs, gift cards, fees to release a parcel.
- **Attachments and QR codes** — disguised file types, QR codes that move you to your phone.

Legitimate messages are in the pool too, because over-suspicion has a cost: real security alerts, receipts and password resets you asked for. After you answer, the elements that decided the case are numbered on the mockup.

The score page ranks you and lists the topics behind your mistakes, with links to tools that help: the [Link Hazmat](../link-hazmat/) link checker for suspicious links and the Email Header Analyzer for sender checks.

## Use it for team training

The quiz works well as a 15-minute segment in a team meeting:

1. **Share your screen** and open this page. Start the quiz.
2. **Read each scenario aloud** and give the room 30 seconds. Let people vote, by show of hands or in the chat, before anyone clicks.
3. **Answer with the majority**, then go through the numbered red flags together. Ask who noticed each one.
4. **After the round**, ask everyone to play once on their own and share their score in the chat. The shared message holds only the score and the link.
5. **Close with your own reporting route**: who to tell, how, and what happens after someone reports a message.

Because every round is different, the same people can play again in a later session. Nothing is tracked, so the quiz is a learning exercise, not an assessment of individuals.

## Use cases

- **Security awareness** for teams, schools and families, without accounts or data collection.
- **Onboarding**: a quick, practical introduction to the messages new staff will receive.
- **Self-check** before you open that delivery or banking message you weren't expecting.
- **Teaching** the difference between a suspicious message and a genuine one, using the mockups as discussion material.
