---
title: "Convertir JSON a Clases C# Online"
description: "Pega un JSON y obtén clases C# con propiedades PascalCase, atributos [JsonPropertyName], clases anidadas y List<T> para System.Text.Json. Gratis y local."
intro: "Pega un documento JSON y obtén al instante **clases de modelo en C#** listas para usar: propiedades en PascalCase, atributos `[JsonPropertyName]` que conservan las claves originales, clases anidadas para los objetos anidados y `List<T>` para los arrays. Funciona sin conexión en tu navegador."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json a c#", "convertir json a clase c#", "json to c#", "generar clases c# desde json", "json2csharp", "modelo system.text.json", "json a poco", "generador de clases c#"]
tags: ["csharp", "dotnet", "json", "herramientas-desarrollo"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "Generador de clases C# a partir de JSON"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Pega el JSON en **JSON de Entrada**, por ejemplo una respuesta de muestra de una API. Arranca con un ejemplo para que veas el resultado enseguida."
  - "El panel **Salida C#** se actualiza mientras escribes. Si el JSON está mal formado aparece la etiqueta **JSON Inválido** y el mensaje del parser indica dónde."
  - "Revisa los tipos generados: los números pasan a `int`, `long` o `double`, las fechas ISO a `DateTime`, los objetos a clases y los arrays a `List<T>`."
  - "Pulsa **Copiar** y pega el código en tu proyecto, por ejemplo como `Models/Root.cs`."
  - "Deserializa con `JsonSerializer.Deserialize<Root>(json)`; para un array JSON usa `List<Root>`, como indica el comentario de la salida."
faq:
  - q: "¿Para qué serializador son las clases?"
    a: "System.Text.Json, el serializador integrado desde .NET Core 3.0. Cada propiedad lleva `[JsonPropertyName(\"clave_original\")]`, así que `full_name` se asigna a `FullName` sin configurar ninguna política de nombres. Para Newtonsoft.Json, cambia el atributo por `[JsonProperty(\"clave_original\")]`."
  - q: "¿Cómo se asignan los números JSON?"
    a: "Los enteros que caben en 32 bits pasan a `int`, los mayores a `long` y los números con decimales a `double`. Un campo que vale `1` en tu ejemplo pero `1.5` en producción quedaría como `int`; usa un ejemplo representativo, o cámbialo a `decimal` para importes."
  - q: "¿Cómo se tratan los arrays de objetos?"
    a: "Se fusionan todos los objetos del array, de modo que una propiedad que solo aparece en algunos elementos también se incluye, y se genera una clase para el tipo del elemento. Su nombre es el singular del nombre de la propiedad: `orders` pasa a `Order`, `categories` a `Category`."
  - q: "¿Por qué una propiedad aparece como object?"
    a: "Porque en el ejemplo valía `null`, así que no hay forma de saber su tipo real. Sustituye `object` por el tipo correcto (`string?`, `int?`…) o pega un ejemplo en el que el campo tenga valor."
  - q: "¿Genera records o tipos de referencia anulables?"
    a: "Genera clases sencillas con propiedades `{ get; set; }`, la forma que aceptan todas las versiones de .NET y todos los serializadores. Pasar a `record` o añadir `?` para los tipos de referencia anulables es un paso manual rápido si tu proyecto los usa."
  - q: "¿Se envía mi JSON a un servidor?"
    a: "No. El análisis y la generación de código se hacen en JavaScript dentro de esta página, algo importante cuando el ejemplo es una respuesta real de una API con datos de clientes o tokens."
---

## Cómo funciona

La entrada se analiza con `JSON.parse`; cualquier error de sintaxis se notifica en lugar de generar código roto. La raíz debe ser un objeto, o un array de objetos que se fusiona en una única clase `Root`.

Cada objeto se convierte en una clase. Para cada clave:

1. **El nombre** se pasa a PascalCase: se quitan separadores como `_`, `-` y espacios y se pone en mayúscula la letra siguiente (`created_at` → `CreatedAt`). Un nombre que empieza por cifra recibe el prefijo `_` para seguir siendo un identificador C# válido.
2. **El tipo** se deduce del valor de ejemplo:

| Valor JSON | Tipo C# |
|---|---|
| `true` / `false` | `bool` |
| entero dentro de ±2.147.483.647 | `int` |
| entero mayor | `long` |
| número con decimales | `double` |
| cadena con formato de fecha ISO 8601 | `DateTime` |
| otra cadena | `string` |
| `null` | `object` |
| objeto | nueva clase con el nombre de la propiedad |
| array de objetos | `List<Item>` con una clase de elemento fusionada |
| array de primitivos | `List<string>`, `List<int>`… |
| array vacío | `List<object>` |

3. **La clave original** se conserva en un atributo `[JsonPropertyName]`.

Los nombres de clases anidadas se hacen únicos (`Address`, `Address2`…) cuando un nombre se repite. Las líneas `using` solo se añaden si hacen falta: `System` para `DateTime`, `System.Collections.Generic` para las listas y siempre `System.Text.Json.Serialization` para el atributo.

### Ejemplo

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

## Casos de uso

- **Consumir una API REST en .NET.** Pega una respuesta de ejemplo y obtén los DTO para `HttpClient.GetFromJsonAsync<Root>()`.
- **Objetos de configuración.** Convierte un archivo de configuración JSON en clases de opciones tipadas para `IOptions<T>`.
- **Webhooks y eventos.** Modela el payload de un webhook de Stripe, GitHub o Slack antes de escribir el controlador.
- **Unity y datos de juego.** Genera clases para niveles, objetos o partidas guardadas en JSON.
- **Revisiones de código.** Comprueba rápidamente si un modelo escrito a mano coincide con un payload real, clave por clave.
