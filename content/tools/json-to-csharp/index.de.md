---
title: "JSON in C#-Klassen umwandeln (online)"
description: "JSON einfügen und C#-Klassen mit PascalCase-Properties, [JsonPropertyName]-Attributen, verschachtelten Klassen und List<T> für System.Text.Json erhalten."
intro: "Fügen Sie ein JSON-Dokument ein und erhalten Sie sofort einsatzfertige **C#-Modellklassen**: Properties in PascalCase, `[JsonPropertyName]`-Attribute mit den Originalschlüsseln, verschachtelte Klassen für verschachtelte Objekte und `List<T>` für Arrays. Funktioniert offline im Browser."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json in c#", "json zu c# klasse", "json to c#", "c# klassen aus json generieren", "json2csharp", "system.text.json modell", "json zu poco", "c# klassen generator"]
tags: ["csharp", "dotnet", "json", "entwickler-tools"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "JSON-zu-C#-Klassengenerator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Fügen Sie JSON in **JSON-Eingabe** ein, etwa eine Beispielantwort einer API. Ein Beispiel ist vorgeladen, damit Sie das Ergebnis sofort sehen."
  - "Der Bereich **C#-Ausgabe** aktualisiert sich beim Tippen. Ist das JSON fehlerhaft, erscheint **Ungültiges JSON**, und die Parser-Meldung zeigt, wo."
  - "Prüfen Sie die erzeugten Typen: Zahlen werden zu `int`, `long` oder `double`, ISO-Daten zu `DateTime`, Objekte zu Klassen und Arrays zu `List<T>`."
  - "Klicken Sie auf **Kopieren** und fügen Sie den Code ins Projekt ein, etwa als `Models/Root.cs`."
  - "Deserialisieren Sie mit `JsonSerializer.Deserialize<Root>(json)`; bei einem JSON-Array mit `List<Root>`, wie der Kommentar in der Ausgabe angibt."
faq:
  - q: "Für welchen Serializer sind die Klassen gedacht?"
    a: "Für System.Text.Json, den eingebauten Serializer seit .NET Core 3.0. Jede Property trägt `[JsonPropertyName(\"originaler_schluessel\")]`, sodass `full_name` ohne Naming-Policy auf `FullName` abgebildet wird. Für Newtonsoft.Json ersetzen Sie das Attribut durch `[JsonProperty(\"originaler_schluessel\")]`."
  - q: "Wie werden JSON-Zahlen abgebildet?"
    a: "Ganze Zahlen, die in 32 Bit passen, werden zu `int`, größere zu `long`, Zahlen mit Nachkommastellen zu `double`. Ein Feld, das im Beispiel `1`, in Produktion aber `1.5` ist, würde also `int`. Nutzen Sie ein repräsentatives Beispiel oder ändern Sie Geldbeträge auf `decimal`."
  - q: "Wie werden Arrays von Objekten behandelt?"
    a: "Alle Objekte des Arrays werden zusammengeführt, sodass auch Properties erfasst werden, die nur in manchen Elementen vorkommen, und für den Elementtyp wird eine Klasse erzeugt. Ihr Name ist der Singular des Property-Namens: `orders` wird zu `Order`, `categories` zu `Category`."
  - q: "Warum ist eine Property vom Typ object?"
    a: "Weil sie im Beispiel `null` war und sich der echte Typ nicht ableiten lässt. Ersetzen Sie `object` durch den passenden Typ (`string?`, `int?` …) oder fügen Sie ein Beispiel ein, in dem das Feld einen Wert hat."
  - q: "Werden Records oder Nullable Reference Types erzeugt?"
    a: "Es entstehen einfache Klassen mit `{ get; set; }`-Properties – die Form, die jede .NET-Version und jeder Serializer akzeptiert. Die Umstellung auf `record` oder das Ergänzen von `?` für Nullable Reference Types ist ein schneller manueller Schritt."
  - q: "Wird mein JSON an einen Server geschickt?"
    a: "Nein. Parsing und Codeerzeugung laufen als JavaScript in dieser Seite – wichtig, wenn das Beispiel eine echte API-Antwort mit Kundendaten oder Tokens ist."
---

## So funktioniert es

Die Eingabe wird mit `JSON.parse` gelesen; Syntaxfehler werden gemeldet, statt kaputten Code zu erzeugen. Die Wurzel muss ein Objekt sein oder ein Array von Objekten, das zu einer einzigen Klasse `Root` zusammengeführt wird.

Jedes Objekt wird zu einer Klasse. Für jeden Schlüssel gilt:

1. **Der Name** wird in PascalCase umgewandelt: Trennzeichen wie `_`, `-` und Leerzeichen entfallen, der folgende Buchstabe wird großgeschrieben (`created_at` → `CreatedAt`). Beginnt ein Name mit einer Ziffer, erhält er das Präfix `_`, damit er ein gültiger C#-Bezeichner bleibt.
2. **Der Typ** wird aus dem Beispielwert abgeleitet:

| JSON-Wert | C#-Typ |
|---|---|
| `true` / `false` | `bool` |
| Ganzzahl innerhalb ±2.147.483.647 | `int` |
| größere Ganzzahl | `long` |
| Zahl mit Nachkommastellen | `double` |
| String im ISO-8601-Datumsformat | `DateTime` |
| anderer String | `string` |
| `null` | `object` |
| Objekt | neue Klasse mit dem Namen der Property |
| Array von Objekten | `List<Item>` mit zusammengeführter Elementklasse |
| Array von Primitiven | `List<string>`, `List<int>` … |
| leeres Array | `List<object>` |

3. **Der Originalschlüssel** bleibt in einem `[JsonPropertyName]`-Attribut erhalten.

Namen verschachtelter Klassen werden eindeutig gemacht (`Address`, `Address2` …), wenn ein Name doppelt vorkommt. `using`-Zeilen werden nur bei Bedarf ergänzt: `System` für `DateTime`, `System.Collections.Generic` für Listen und immer `System.Text.Json.Serialization` für das Attribut.

### Beispiel

`{"created_at":"2024-01-15T10:30:00Z","orders":[{"order_id":1001,"total":29.99}]}` ergibt:

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

## Anwendungsfälle

- **REST-APIs in .NET nutzen.** Beispielantwort einfügen und die DTOs für `HttpClient.GetFromJsonAsync<Root>()` erhalten.
- **Konfigurationsobjekte.** Machen Sie aus einer JSON-Konfigurationsdatei stark typisierte Options-Klassen für `IOptions<T>`.
- **Webhooks und Events.** Modellieren Sie den Payload eines Stripe-, GitHub- oder Slack-Webhooks, bevor Sie den Handler schreiben.
- **Unity und Spieldaten.** Erzeugen Sie Klassen für Level-, Item- oder Spielstand-JSON.
- **Code Reviews.** Prüfen Sie schnell, ob ein handgeschriebenes Modell Schlüssel für Schlüssel zu einem echten Payload passt.
