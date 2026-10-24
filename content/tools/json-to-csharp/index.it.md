---
title: "Convertire JSON in Classi C# Online"
description: "Incolla un JSON e ottieni classi C# con proprietà PascalCase, attributi [JsonPropertyName], classi annidate e List<T> per System.Text.Json. Gratis."
intro: "Incolla un documento JSON e ottieni subito **classi modello C#** pronte all'uso: proprietà in PascalCase, attributi `[JsonPropertyName]` che conservano le chiavi originali, classi annidate per gli oggetti annidati e `List<T>` per gli array. Funziona offline nel browser."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json in c#", "convertire json in classe c#", "json to c#", "generare classi c# da json", "json2csharp", "modello system.text.json", "json in poco", "generatore classi c#"]
tags: ["csharp", "dotnet", "json", "strumenti-sviluppo"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "Generatore di classi C# da JSON"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Incolla il JSON in **JSON in Input**, per esempio una risposta di esempio di un'API. Parte già con un esempio, così vedi subito il risultato."
  - "Il pannello **Output C#** si aggiorna mentre scrivi. Se il JSON è malformato compare il badge **JSON Non Valido** e il messaggio del parser indica dove."
  - "Controlla i tipi generati: i numeri diventano `int`, `long` o `double`, le date ISO `DateTime`, gli oggetti classi e gli array `List<T>`."
  - "Premi **Copia** e incolla il codice nel progetto, per esempio come `Models/Root.cs`."
  - "Deserializza con `JsonSerializer.Deserialize<Root>(json)`; per un array JSON usa `List<Root>`, come indica il commento nell'output."
faq:
  - q: "Per quale serializzatore sono le classi?"
    a: "System.Text.Json, il serializzatore integrato da .NET Core 3.0. Ogni proprietà ha `[JsonPropertyName(\"chiave_originale\")]`, quindi `full_name` corrisponde a `FullName` senza configurare politiche di naming. Per Newtonsoft.Json sostituisci l'attributo con `[JsonProperty(\"chiave_originale\")]`."
  - q: "Come vengono mappati i numeri JSON?"
    a: "Gli interi che stanno in 32 bit diventano `int`, quelli più grandi `long` e i numeri con parte decimale `double`. Un campo che vale `1` nel tuo esempio ma `1.5` in produzione sarebbe quindi tipizzato `int`: usa un esempio rappresentativo, oppure cambialo in `decimal` per gli importi."
  - q: "Come vengono gestiti gli array di oggetti?"
    a: "Tutti gli oggetti dell'array vengono uniti, così anche una proprietà presente solo in alcuni elementi viene inclusa, e viene generata una classe per il tipo dell'elemento. Il nome è il singolare del nome della proprietà: `orders` diventa `Order`, `categories` diventa `Category`."
  - q: "Perché una proprietà è di tipo object?"
    a: "Perché nell'esempio valeva `null`, quindi non c'è modo di conoscerne il tipo reale. Sostituisci `object` con il tipo giusto (`string?`, `int?`…) o incolla un esempio in cui il campo ha un valore."
  - q: "Genera record o nullable reference types?"
    a: "Genera classi semplici con proprietà `{ get; set; }`, la forma accettata da ogni versione di .NET e da ogni serializzatore. Passare a `record` o aggiungere `?` per i nullable reference types è un passaggio manuale rapido se il progetto li usa."
  - q: "Il mio JSON viene inviato a un server?"
    a: "No. Il parsing e la generazione del codice avvengono in JavaScript in questa pagina, il che conta quando l'esempio è una vera risposta di un'API con dati di clienti o token."
---

## Come funziona

L'input viene letto con `JSON.parse`; qualsiasi errore di sintassi viene segnalato invece di generare codice rotto. La radice deve essere un oggetto, oppure un array di oggetti che viene unito in un'unica classe `Root`.

Ogni oggetto diventa una classe. Per ogni chiave:

1. **Il nome** viene convertito in PascalCase: separatori come `_`, `-` e spazi vengono tolti e la lettera seguente diventa maiuscola (`created_at` → `CreatedAt`). Un nome che inizia con una cifra riceve il prefisso `_` per restare un identificatore C# valido.
2. **Il tipo** viene dedotto dal valore d'esempio:

| Valore JSON | Tipo C# |
|---|---|
| `true` / `false` | `bool` |
| intero entro ±2.147.483.647 | `int` |
| intero più grande | `long` |
| numero con decimali | `double` |
| stringa in formato data ISO 8601 | `DateTime` |
| altra stringa | `string` |
| `null` | `object` |
| oggetto | nuova classe con il nome della proprietà |
| array di oggetti | `List<Item>` con una classe elemento unificata |
| array di primitivi | `List<string>`, `List<int>`… |
| array vuoto | `List<object>` |

3. **La chiave originale** viene conservata in un attributo `[JsonPropertyName]`.

I nomi delle classi annidate vengono resi univoci (`Address`, `Address2`…) quando lo stesso nome compare due volte. Le righe `using` vengono aggiunte solo se servono: `System` per `DateTime`, `System.Collections.Generic` per le liste e sempre `System.Text.Json.Serialization` per l'attributo.

### Esempio

`{"created_at":"2024-01-15T10:30:00Z","orders":[{"order_id":1001,"total":29.99}]}` produce:

```csharp
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

public class Root
{
    [JsonPropertyName("created_at")]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName("orders")]
    public List<Order> Orders { get; set; }
}

public class Order
{
    [JsonPropertyName("order_id")]
    public int OrderId { get; set; }

    [JsonPropertyName("total")]
    public double Total { get; set; }
}
```

## Casi d'uso

- **Consumare un'API REST in .NET.** Incolla una risposta di esempio e ottieni i DTO per `HttpClient.GetFromJsonAsync<Root>()`.
- **Oggetti di configurazione.** Trasforma un file di configurazione JSON in classi di opzioni fortemente tipizzate per `IOptions<T>`.
- **Webhook ed eventi.** Modella il payload di un webhook Stripe, GitHub o Slack prima di scrivere il gestore.
- **Unity e dati di gioco.** Genera classi per livelli, oggetti o salvataggi in JSON.
- **Code review.** Verifica al volo se un modello scritto a mano corrisponde a un payload reale, chiave per chiave.
