---
title: "Evooo1Bot: La botnet Linux si evolve oltre il DDoS verso un set completo di strumenti per attaccanti"
date: "2026-08-19T07:33:20Z"
original_date: "2026-08-17T15:44:34"
lang: "it"
translationKey: "evooo1bot-linux-botnet-evolves-beyond-ddos-to-full-attacker-toolset"
slug: "evooo1bot-linux-botnet-evolves-beyond-ddos-to-full-attacker-toolset"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Bot aggiunge sfruttamento di vulnerabilità, furto di credenziali e reverse SOCKS per trasformare i dispositivi Linux compromessi in infrastruttura di attacco persistente."
original_url: "https://www.darkreading.com/cyber-risk/linux-botnet-evooo1bot-mirai-capabilities-beyond-ddos"
source: "Dark Reading"
severity: "High"
target: "Dispositivi Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Bot aggiunge sfruttamento di vulnerabilità, furto di credenziali e reverse SOCKS per trasformare i dispositivi Linux compromessi in infrastruttura di attacco persistente.

{{< cyber-report severity="High" source="Dark Reading" target="Dispositivi Linux" >}}

La botnet Evooo1Bot, inizialmente nota per le capacità DDoS, ha ampliato significativamente il suo arsenale. Secondo Dark Reading, ora include moduli di sfruttamento, furto di credenziali e relay reverse SOCKS, trasformando i dispositivi Linux compromessi in infrastruttura di attacco persistente.

{{< ad-banner >}}

Questa evoluzione segna un passaggio da un semplice denial-of-service a un set di strumenti più versatile in grado di supportare un'ampia gamma di attività dannose. L'aggiunta del furto di credenziali e dei relay reverse SOCKS suggerisce che la botnet viene utilizzata non solo per interruzioni, ma potenzialmente per l'esfiltrazione di dati e il movimento laterale all'interno delle reti.

Per i difensori, ciò significa che i sistemi Linux, spesso considerati più sicuri, sono ora a rischio da una botnet che non solo può sopraffare i servizi, ma anche rubare informazioni sensibili e mantenere un accesso nascosto. Le organizzazioni dovrebbero dare priorità alla correzione delle vulnerabilità note e al monitoraggio di attività di rete insolite, specialmente su server Linux e dispositivi IoT.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero trattare qualsiasi dispositivo Linux come un potenziale nodo botnet, non solo come una fonte DDoS. Monitorare le connessioni in uscita insolite, in particolare verso IP sconosciuti su porte alte, e indagare su qualsiasi segno di raccolta di credenziali o traffico SOCKS inaspettato. I team DevSecOps dovrebbero indurire le immagini Linux e applicare il principio del minimo privilegio per limitare l'impatto di tali compromissioni.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Dark Reading ›](https://www.darkreading.com/cyber-risk/linux-botnet-evooo1bot-mirai-capabilities-beyond-ddos)**
