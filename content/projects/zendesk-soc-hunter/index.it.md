---
title: "Zendesk SOC Hunter"
date: 2025-01-18
draft: false
description: "L'estensione browser per Analisti SOC e supporto Helpdesk che utilizzano Zendesk"
tags: ["Javascript", "WebExtension", "Automation", "ShadowDOM", "CrossBrowser", "JSON", "Zendesk", "IncidentResponse"]
categories: ["Projects", "Coding", "Cybersecurity Tools", "Browser Extensions", "Threat Intelligence", "Productivity"]
externalLink: "https://github.com/fede952/Zendesk-SOC-Hunter"
---

# Hunter - Assistente SOC per Zendesk

**Hunter** è un'estensione browser leggera e ad alte prestazioni, progettata per assistere gli analisti del Security Operation Center (SOC) e i team di supporto IT. Agisce come uno scanner passivo che evidenzia il contesto critico direttamente all'interno dell'interfaccia del tuo sistema di ticketing.

## 🔗 Link
- [**Repository GitHub**](https://github.com/fede952/Zendesk-SOC-Hunter)
- [**Scarica per Chrome**](#) *(presto disponibile)*
- [**Scarica per Firefox**](#) *(presto disponibile)*

---

## 🎯 Il Problema
Gli analisti che gestiscono centinaia di ticket spesso perdono il contesto. Questo ticket proviene da un cliente VIP? L'indirizzo IP menzionato nella descrizione fa parte di un incidente noto? Controllare manualmente elenchi esterni per ogni ticket richiede molto tempo ed è un'attività soggetta a errori.

## 💡 La Soluzione
Hunter lavora silenziosamente nel tuo browser. Quando apri un ticket su **Zendesk** (o qualsiasi pagina web), scansiona il testo visibile confrontandolo con il tuo database locale di regole.

Se trova una corrispondenza (Nome Organizzazione, Indirizzo IP, Range CIDR o stringhe specifiche), mostra un **alert in sovrimpressione non intrusivo** nell'angolo in basso a destra.

---

## ✨ Panoramica Funzionalità

### 1. Interfaccia "Tower Stack"
A differenza dei classici avvisi del browser che bloccano la visuale, Hunter utilizza un sistema intelligente a "Torre".
- Gli avvisi appaiono nell'angolo in basso a destra.
- Rilevamenti multipli si impilano verso l'alto.
- **Tecnologia Shadow DOM**: Gli avvisi sono isolati dal CSS del sito web. Questo significa che gli aggiornamenti di Zendesk non romperanno l'aspetto dell'estensione, e l'estensione non romperà il layout di Zendesk.

### 2. Drag & Drop
Un avviso copre il pulsante "Invia"? Nessun problema.
- **Clicca e Trascina**: Sposta qualsiasi finestra di avviso ovunque sullo schermo.
- **Allineamento Automatico**: Gli altri avvisi scorreranno automaticamente per riempire lo spazio vuoto o seguire l'avviso principale.
- **Memoria Posizione**: L'estensione ricorda dove preferisci posizionare i tuoi avvisi.

### 3. Rilevamento Intelligente
Hunter supporta tre tipi di indicatori:
* **Nome Organizzazione**: Corrisponde al nome del cliente nella pagina.
* **IP / CIDR**: Rileva IP specifici (es. `192.168.1.5`) o controlla se un IP appartiene a una sottorete monitorata (es. `192.168.0.0/24`).
* **Stringhe**: Ricerca case-insensitive per termini specifici (es. `confidential`, `malware`).

### 4. Condivisione in Team
Non è necessario configurare manualmente la macchina di ogni analista.
1.  Configura le regole su una macchina.
2.  Clicca **Esporta Regole** (salva un file `.json`).
3.  Condividi il file con il tuo team.
4.  Loro cliccano **Importa Regole** per sincronizzare istantaneamente.

---

## 📖 Guida Utente

### Configurazione Iniziale
1.  Clicca l'**icona di Hunter** nella barra degli strumenti del browser.
2.  Se l'interfaccia è rossa, clicca l'interruttore per impostarlo su **ATTIVO**.
3.  Vedrai un avviso: *"Nessuna regola configurata"*.

### Aggiungere una Regola
1.  **Nome Organizzazione**: Inserisci il nome (es. `Ferrari`).
2.  **Motivo**: Perché viene monitorato? (es. `Progetto X in corso`).
3.  **Indicatori**: Aggiungi valori separati da virgola (es. `10.0.0.1, server-log`).
4.  Clicca **Aggiungi Regola**.

### Gestione Regole
- **Modifica**: Clicca l'icona della matita ✏️ accanto a una regola.
- **Elimina**: Clicca l'icona del cestino 🗑️ per rimuovere una regola.
- **Elimina Tutto**: Usa il pulsante rosso `All` per cancellare l'intera configurazione.

---

## ❓ FAQ

**D: Hunter invia dati al cloud?**
R: **No.** Hunter è locale al 100%. Le tue regole e la scansione del testo avvengono interamente nel tuo browser (Client-side). Nessun dato viene inviato a server esterni.

**D: Perché il popup non appare?**
R: Assicurati di aver aggiunto almeno una regola. Se il banner giallo "Nessuna regola configurata" non è visibile, prova ad aggiornare la pagina.

**D: Posso usarlo al di fuori di Zendesk?**
R: Sì, Hunter scansiona il DOM della scheda attiva. Sebbene ottimizzato per Zendesk, funziona su qualsiasi sito web basato su testo.

---

*Progetto sviluppato da Federico Sella. Rilasciato sotto licenza MIT.*