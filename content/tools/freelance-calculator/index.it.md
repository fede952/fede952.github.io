---
title: "Calcolatore Tariffa Oraria Freelance"
description: "Calcola la tariffa oraria e giornaliera che ti serve da freelance partendo da netto desiderato, giorni e ore fatturabili, tasse e spese. Gratis e privato."
intro: "**RateMate** trasforma il reddito che vuoi portarti a casa nella tariffa che devi chiedere. Inserisci netto annuo desiderato, giorni e ore fatturabili, aliquota fiscale e spese mensili, e ottieni subito tariffa oraria, tariffa giornaliera e fatturato mensile necessario."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["calcolo tariffa oraria freelance", "quanto farsi pagare freelance", "calcolatore tariffa giornaliera", "tariffa partita iva", "calcolo compenso orario", "prezzo freelance", "tariffa consulente", "tariffa oraria libero professionista"]
tags: ["freelance", "finanza", "lavoro", "strumento"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate, calcolatore della tariffa freelance"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Scegli la valuta ($, € o £) e inserisci il **Desired Annual Net Salary**: quello che vuoi tenere dopo tasse e costi dell'attività."
  - "Imposta **Billable Days per Year**. Il valore predefinito è 220: togli con onestà ferie, malattia, amministrazione e tempo dedicato a cercare clienti."
  - "Imposta **Daily Billable Hours**: le ore che puoi davvero fatturare, di solito 5–7 e non 8."
  - "Porta il cursore **Tax Rate** sulla tua aliquota effettiva di tasse e contributi e inserisci le **Monthly Expenses** (software, attrezzatura, assicurazione, coworking, commercialista)."
  - "Leggi **Your Hourly Rate**, il **Daily Rate** e il **Monthly Gross** da fatturare. Il grafico ad anello mostra come ogni euro fatturato si divide tra reddito, tasse e spese."
faq:
  - q: "Come si calcola la tariffa oraria da freelance?"
    a: "Parti dal reddito che ti serve, non da quanto chiedono gli altri. Aggiungi le spese annuali dell'attività, lordizza il totale per le tasse e dividi per le ore che puoi fatturare realisticamente. Con i valori predefiniti (60.000 netti, 500 al mese di spese, 25% di tasse, 220 giorni da 6 ore fatturabili) fa (60.000 + 6.000) ÷ 0,75 = 88.000 all'anno, 400 al giorno, circa 67 all'ora."
  - q: "Quanti giorni fatturabili all'anno devo considerare?"
    a: "Un anno ha circa 260 giorni lavorativi. Togli le festività (8–14 a seconda del paese), 20–25 giorni di ferie, qualche giorno di malattia e il tempo per vendita, amministrazione e formazione. La maggior parte dei freelance finisce tra 180 e 220 giorni fatturabili; chi è agli inizi e non ha ancora un flusso stabile di clienti spesso ne fattura meno."
  - q: "Perché le ore fatturabili sono meno delle ore lavorate?"
    a: "Email, fatture, preventivi, riunioni non addebitabili e cambi di contesto si mangiano tempo. Sei ore fatturabili in una giornata di otto sono un valore comune e sostenibile. Se fatturi otto ore ogni giorno, probabilmente ne lavori dieci."
  - q: "Che aliquota fiscale devo inserire?"
    a: "La tua aliquota *effettiva*: imposte più contributi previdenziali divisi per il fatturato lordo, non lo scaglione marginale più alto. Cambia molto da paese a paese e da regime a regime (in Italia, per esempio, tra forfettario e ordinario); per una prima stima usa i dati dell'anno scorso o chiedi al commercialista, poi prova qualche valore per vedere quanto cambia la tariffa."
  - q: "Il calcolatore considera le spese deducibili?"
    a: "No. Applica l'aliquota a tutto il lordo, spese comprese, il che dà una tariffa un po' più alta e prudente. Dove le spese sono interamente deducibili, il lordo necessario è invece netto ÷ (1 − aliquota) + spese: con i valori predefiniti 86.000 invece di 88.000, circa 65 all'ora invece di 67."
  - q: "Meglio una tariffa oraria, giornaliera o a progetto?"
    a: "Usa la cifra oraria come soglia minima. Molti freelance propongono una tariffa giornaliera (mostrata qui) o un prezzo fisso per progetto ricavato da essa, che premia l'efficienza invece delle ore. Qualunque sia il preventivo, controlla che non scenda mai sotto la tariffa oraria di questo calcolatore."
  - q: "I miei dati economici vengono salvati?"
    a: "No. Il calcolo avviene nel browser e non viene salvato né inviato nulla. Chiudi la pagina e i numeri spariscono."
---

## Come funziona

RateMate ragiona a ritroso, partendo dai soldi che vuoi tenere.

1. **Spese annuali** = spese mensili × 12.
2. **Lordo annuo necessario** = (netto desiderato + spese annuali) ÷ (1 − aliquota).
   L'aliquota è trattata come una quota fissa di tutto ciò che fatturi, quindi la formula lordizza sia il tuo stipendio sia i costi.
3. **Tasse annuali** = lordo − netto − spese.
4. **Tariffa giornaliera** = lordo ÷ giorni fatturabili.
5. **Tariffa oraria** = tariffa giornaliera ÷ ore fatturabili al giorno.
6. **Lordo mensile** = lordo ÷ 12, cioè quanto devi fatturare in media ogni mese.

Il grafico ad anello, disegnato con Chart.js, mostra le tre quote del lordo: reddito netto, tasse e spese. Ogni campo ricalcola mentre scrivi, quindi puoi trascinare il cursore delle tasse (0–60%) e vedere la tariffa muoversi.

### Esempio pratico

| Dato | Valore |
|---|---|
| Netto desiderato | 60.000 |
| Spese mensili | 500 (6.000 all'anno) |
| Aliquota | 25% |
| Giorni fatturabili | 220 |
| Ore fatturabili al giorno | 6 |

Lordo = 66.000 ÷ 0,75 = **88.000** all'anno → **400** al giorno → **≈ 67** all'ora → **≈ 7.333** da fatturare al mese. Su ogni 100 fatturati, circa 68 sono reddito, 25 tasse e 7 coprono le spese.

Cambia una sola ipotesi e capisci perché le tariffe variano tanto. Con 180 giorni fatturabili la tariffa oraria sale a circa 81; con 5 ore fatturabili al giorno invece di 6, a 80. La leva più forte di solito non è l'aliquota, ma quanto del tuo tempo riesci davvero a fatturare.

### Cosa il modello non considera

Il calcolatore resta volutamente su un'unica aliquota effettiva. Non modella scaglioni progressivi, IVA (che si aggiunge alla tariffa e si versa), contributi pensionistici oltre a quelli che includi nel "netto", né i periodi scoperti tra un contratto e l'altro. Se ti riguardano, aggiungi un margine o alza il netto.

## Casi d'uso

- **Passare alla libera professione.** Trasforma il tuo stipendio da dipendente nella tariffa che ti serve, e capisci subito perché un freelance deve chiedere molto più di stipendio ÷ 2.080 ore.
- **Preparare un preventivo.** Controlla che il prezzo di un progetto, diviso per i giorni che richiede, resti sopra la tua tariffa giornaliera.
- **Aumentare le tariffe.** Inserisci le spese e l'aliquota reali di quest'anno e verifica se la tariffa attuale le copre ancora.
- **Confrontare offerte.** Metti a confronto la tariffa giornaliera di un contratto e uno stipendio da dipendente a parità di condizioni.
- **Pianificare un anno sabbatico o un corso.** Riduci i giorni fatturabili e guarda di quanto deve salire la tariffa per mantenere lo stesso reddito.
