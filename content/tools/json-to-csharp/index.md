---
title: "JSON to C# Class Generator Online"
description: "Paste JSON and get C# classes with PascalCase properties, [JsonPropertyName] attributes, nested classes and List<T> for System.Text.Json. Free, local."
intro: "Paste a JSON document and get ready-to-use **C# model classes** instantly: PascalCase properties, `[JsonPropertyName]` attributes that keep the original keys, nested classes for nested objects and `List<T>` for arrays. Works offline in your browser."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json to c#", "json to c# class", "json to c# converter", "generate c# class from json", "json2csharp", "system.text.json model", "json to poco", "c# class generator"]
tags: ["csharp", "dotnet", "json", "developer-tools"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "JSON to C# class generator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Paste JSON into **Input JSON**, for example a sample API response. A sample is loaded so you can see the result first."
  - "The **C# Output** panel updates as you type. If the JSON is malformed, an **Invalid JSON** badge appears and the parser's message tells you where."
  - "Check the generated types: numbers become `int`, `long` or `double`, ISO dates become `DateTime`, objects become classes and arrays become `List<T>`."
  - "Press **Copy** and paste the code into your project, for example as `Models/Root.cs`."
  - "Deserialize with `JsonSerializer.Deserialize<Root>(json)`; for a JSON array, use `List<Root>` as the comment in the output says."
faq:
  - q: "Which serializer are the classes for?"
    a: "System.Text.Json, the built-in serializer since .NET Core 3.0. Each property carries `[JsonPropertyName(\"original_key\")]`, so `full_name` maps to `FullName` without any naming-policy configuration. For Newtonsoft.Json, replace the attribute with `[JsonProperty(\"original_key\")]`."
  - q: "How are JSON numbers mapped?"
    a: "Whole numbers that fit in 32 bits become `int`, larger whole numbers `long`, and numbers with a fractional part `double`. A field that is `1` in your sample but `1.5` in production would therefore be typed `int`; use a representative sample, or change it to `decimal` for money."
  - q: "How are arrays of objects handled?"
    a: "All objects in the array are merged, so a property that appears only in some items is still included, and a class is generated for the item type. Its name is the singular of the property name: `orders` becomes `Order`, `categories` becomes `Category`."
  - q: "Why is a property typed as object?"
    a: "Because it was `null` in the sample, so there is no way to know its real type. Replace `object` with the right type (`string?`, `int?`…) or paste a sample where the field has a value."
  - q: "Does it generate records or nullable reference types?"
    a: "It generates plain classes with `{ get; set; }` properties, the form every .NET version and serializer accepts. Converting to `record` types or adding `?` for nullable reference types is a quick manual step if your project uses them."
  - q: "Is my JSON sent to a server?"
    a: "No. Parsing and code generation run in JavaScript inside this page, which matters when the sample is a real API response with customer data or tokens."
---

## How it works

The input is parsed with `JSON.parse`; any syntax error is reported instead of generating broken code. The root must be an object, or an array of objects that is merged into one `Root` class.

Each object becomes a class. For every key:

1. **The name** is converted to PascalCase: separators such as `_`, `-` and spaces are removed and the following letter capitalised (`created_at` → `CreatedAt`). A name starting with a digit is prefixed with `_` to stay a valid C# identifier.
2. **The type** is inferred from the sample value:

| JSON value | C# type |
|---|---|
| `true` / `false` | `bool` |
| whole number within ±2,147,483,647 | `int` |
| larger whole number | `long` |
| number with decimals | `double` |
| string in ISO 8601 date format | `DateTime` |
| other string | `string` |
| `null` | `object` |
| object | new class named after the property |
| array of objects | `List<Item>` with a merged item class |
| array of primitives | `List<string>`, `List<int>`… |
| empty array | `List<object>` |

3. **The original key** is preserved in a `[JsonPropertyName]` attribute.

Nested class names are made unique (`Address`, `Address2`…) when the same name appears twice. The `using` lines are added only when needed: `System` for `DateTime`, `System.Collections.Generic` for lists, and always `System.Text.Json.Serialization` for the attribute.

### Example

`{"created_at":"2024-01-15T10:30:00Z","orders":[{"order_id":1001,"total":29.99}]}` produces:

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

## Use cases

- **Consuming a REST API in .NET.** Paste a sample response and get the DTOs for `HttpClient.GetFromJsonAsync<Root>()`.
- **Configuration objects.** Turn a JSON config file into strongly typed options classes for `IOptions<T>`.
- **Webhooks and events.** Model the payload of a Stripe, GitHub or Slack webhook before writing the handler.
- **Unity and game data.** Generate classes for level, item or save-game JSON files.
- **Code reviews.** Quickly check whether a hand-written model matches a real payload, key by key.
