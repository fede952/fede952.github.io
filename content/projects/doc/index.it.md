---
title: "Portfolio Personale & Blog"
description: "Sviluppo di un sito statico utilizzando Hugo e GitHub Actions."
date: 2025-12-25
tags: ["Hugo", "Go", "CI/CD", "Web Development", "Open Source"]
---

### 🛠 Stack Tecnologico

Il progetto è costruito su **Hugo**, uno dei framework open-source più veloci per la creazione di siti web, scritto in **Go**.

* **Core Framework:** [Hugo](https://gohugo.io/) (Static Site Generator).
* **Linguaggi:** HTML5, CSS3, Markdown (per i contenuti).
* **Templating:** Go Templates (per la logica dei layout e partials).
* **Gestione Contenuti:** I progetti e gli articoli sono scritti in **Markdown**, garantendo portabilità e una facile gestione del versionamento.

### 🚀 Architettura e Deployment (CI/CD)

L'infrastruttura del sito è completamente *serverless* e automatizzata.

1.  **Version Control:** Il codice sorgente è ospitato su **GitHub** nel repository pubblico `fede952/fede952.github.io`.
2.  **Hosting:** Il sito è servito tramite **GitHub Pages**, che garantisce tempi di risposta rapidissimi e un uptime elevato.
3.  **Custom Domain:** Configurazione DNS personalizzata tramite file `CNAME` per puntare al dominio `www.federicosella.com`.
4.  **Automazione (CI/CD):**
    Ho implementato una pipeline di Continuous Deployment utilizzando **GitHub Actions** (presenti nella cartella `.github/workflows`).
    * **Workflow:** Ad ogni *push* sul ramo `main`, GitHub avvia un container, installa Hugo, compila il sito statico dai file Markdown e distribuisce automaticamente la nuova versione in produzione.

### 💡 Perché Hugo?
La scelta di Hugo rispetto a soluzioni basate su JavaScript (come Next.js o React) per questo specifico caso d'uso è stata dettata dalla volontà di ottenere il massimo punteggio nei **Core Web Vitals**. Non dovendo caricare bundle JavaScript client-side, il sito offre un'esperienza di navigazione istantanea.

---
*Il codice sorgente di questo sito è open source e disponibile su [GitHub](https://github.com/fede952/fede952.github.io).*