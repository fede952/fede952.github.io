---
title: "Pacchetti Dormienti in Ruby Gems e Go Modules Mirano alle Pipeline CI/CD"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "it"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Gli attaccanti utilizzano pacchetti dormienti per distribuire payload dannosi, rubare credenziali, manomettere GitHub Actions e stabilire persistenza SSH in attacchi alla supply chain del software."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "Pipeline CI/CD e supply chain del software"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Gli attaccanti utilizzano pacchetti dormienti per distribuire payload dannosi, rubare credenziali, manomettere GitHub Actions e stabilire persistenza SSH in attacchi alla supply chain del software.

{{< cyber-report severity="High" source="The Hacker News" target="Pipeline CI/CD e supply chain del software" >}}

È stata osservata una nuova campagna di attacco alla supply chain del software che utilizza pacchetti dormienti come canale per inviare successivamente payload dannosi che hanno permesso il furto di credenziali, la manomissione di GitHub Actions e la persistenza SSH. L'attività è stata attribuita all'account GitHub "BufferZoneCorp," che ha pubblicato una serie di repository associati a Ruby gems e Go modules dannosi.

{{< ad-banner >}}

L'attacco sfrutta pacchetti inizialmente apparentemente innocui che successivamente ricevono aggiornamenti dannosi, una tecnica nota come pacchetti "dormienti" o "troianizzati". Una volta installati in ambienti CI/CD, i payload rubano credenziali, modificano i workflow di GitHub Actions e stabiliscono accesso SSH persistente, rappresentando una minaccia significativa per le pipeline di sviluppo.

Le organizzazioni che utilizzano Ruby gems o Go modules da fonti non affidabili dovrebbero verificare le proprie dipendenze e monitorare attività sospette nei repository. La campagna evidenzia la crescente sofisticazione degli attacchi alla supply chain che mirano all'infrastruttura degli sviluppatori.

{{< netrunner-insight >}}

Questa campagna sottolinea la necessità di un blocco rigoroso delle dipendenze e della verifica dell'integrità nelle pipeline CI/CD. Gli analisti SOC dovrebbero monitorare modifiche anomale di GitHub Actions e aggiunte di chiavi SSH, mentre gli ingegneri DevSecOps dovrebbero implementare l'accesso con privilegio minimo e considerare l'uso di ambienti di build effimeri per limitare il raggio d'esplosione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
