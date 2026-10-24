---
title: "Convertir du JSON en Classes C# en Ligne"
description: "Collez du JSON et obtenez des classes C# avec propriétés PascalCase, attributs [JsonPropertyName], classes imbriquées et List<T> pour System.Text.Json."
intro: "Collez un document JSON et obtenez aussitôt des **classes de modèle C#** prêtes à l'emploi : propriétés en PascalCase, attributs `[JsonPropertyName]` qui conservent les clés d'origine, classes imbriquées pour les objets imbriqués et `List<T>` pour les tableaux. Fonctionne hors ligne dans votre navigateur."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json vers c#", "convertir json en classe c#", "json to c#", "générer classes c# depuis json", "json2csharp", "modèle system.text.json", "json vers poco", "générateur de classes c#"]
tags: ["csharp", "dotnet", "json", "outils-développeur"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "Générateur de classes C# depuis JSON"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Collez le JSON dans **JSON en Entrée**, par exemple une réponse d'exemple d'une API. Un exemple est chargé pour voir le résultat tout de suite."
  - "Le panneau **Sortie C#** se met à jour pendant la saisie. Si le JSON est mal formé, le badge **JSON Invalide** apparaît et le message du parseur indique où."
  - "Vérifiez les types générés : les nombres deviennent `int`, `long` ou `double`, les dates ISO `DateTime`, les objets des classes et les tableaux des `List<T>`."
  - "Cliquez sur **Copier** et collez le code dans votre projet, par exemple sous `Models/Root.cs`."
  - "Désérialisez avec `JsonSerializer.Deserialize<Root>(json)` ; pour un tableau JSON, utilisez `List<Root>` comme l'indique le commentaire de la sortie."
faq:
  - q: "Pour quel sérialiseur sont les classes ?"
    a: "System.Text.Json, le sérialiseur intégré depuis .NET Core 3.0. Chaque propriété porte `[JsonPropertyName(\"cle_origine\")]` : `full_name` correspond donc à `FullName` sans configurer de politique de nommage. Pour Newtonsoft.Json, remplacez l'attribut par `[JsonProperty(\"cle_origine\")]`."
  - q: "Comment les nombres JSON sont-ils typés ?"
    a: "Les entiers qui tiennent sur 32 bits deviennent `int`, les plus grands `long`, et les nombres à virgule `double`. Un champ valant `1` dans votre exemple mais `1.5` en production serait donc typé `int` : utilisez un exemple représentatif, ou passez à `decimal` pour les montants."
  - q: "Comment les tableaux d'objets sont-ils gérés ?"
    a: "Tous les objets du tableau sont fusionnés, si bien qu'une propriété présente dans certains éléments seulement est aussi prise en compte, et une classe est générée pour le type de l'élément. Son nom est le singulier du nom de la propriété : `orders` devient `Order`, `categories` devient `Category`."
  - q: "Pourquoi une propriété est-elle typée object ?"
    a: "Parce qu'elle valait `null` dans l'exemple : impossible de connaître son vrai type. Remplacez `object` par le bon type (`string?`, `int?`…) ou collez un exemple où le champ a une valeur."
  - q: "Génère-t-il des records ou des types référence nullables ?"
    a: "Il génère des classes simples avec des propriétés `{ get; set; }`, la forme acceptée par toutes les versions de .NET et tous les sérialiseurs. Passer en `record` ou ajouter `?` pour les types référence nullables est une étape manuelle rapide si votre projet les utilise."
  - q: "Mon JSON est-il envoyé à un serveur ?"
    a: "Non. L'analyse et la génération de code se font en JavaScript dans cette page, ce qui compte quand l'exemple est une vraie réponse d'API contenant des données clients ou des tokens."
---

## Comment ça marche

L'entrée est analysée avec `JSON.parse` ; toute erreur de syntaxe est signalée au lieu de produire du code cassé. La racine doit être un objet, ou un tableau d'objets fusionné en une seule classe `Root`.

Chaque objet devient une classe. Pour chaque clé :

1. **Le nom** est converti en PascalCase : les séparateurs comme `_`, `-` et les espaces sont supprimés et la lettre suivante passe en majuscule (`created_at` → `CreatedAt`). Un nom commençant par un chiffre reçoit le préfixe `_` pour rester un identifiant C# valide.
2. **Le type** est déduit de la valeur d'exemple :

| Valeur JSON | Type C# |
|---|---|
| `true` / `false` | `bool` |
| entier compris dans ±2 147 483 647 | `int` |
| entier plus grand | `long` |
| nombre à virgule | `double` |
| chaîne au format de date ISO 8601 | `DateTime` |
| autre chaîne | `string` |
| `null` | `object` |
| objet | nouvelle classe nommée d'après la propriété |
| tableau d'objets | `List<Item>` avec une classe d'élément fusionnée |
| tableau de primitives | `List<string>`, `List<int>`… |
| tableau vide | `List<object>` |

3. **La clé d'origine** est conservée dans un attribut `[JsonPropertyName]`.

Les noms de classes imbriquées sont rendus uniques (`Address`, `Address2`…) quand un même nom revient. Les lignes `using` ne sont ajoutées que si nécessaire : `System` pour `DateTime`, `System.Collections.Generic` pour les listes, et toujours `System.Text.Json.Serialization` pour l'attribut.

### Exemple

`{"created_at":"2024-01-15T10:30:00Z","orders":[{"order_id":1001,"total":29.99}]}` donne :

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

## Cas d'usage

- **Consommer une API REST en .NET.** Collez une réponse d'exemple et obtenez les DTO pour `HttpClient.GetFromJsonAsync<Root>()`.
- **Objets de configuration.** Transformez un fichier de configuration JSON en classes d'options fortement typées pour `IOptions<T>`.
- **Webhooks et événements.** Modélisez le payload d'un webhook Stripe, GitHub ou Slack avant d'écrire le gestionnaire.
- **Unity et données de jeu.** Générez des classes pour des niveaux, objets ou sauvegardes en JSON.
- **Revues de code.** Vérifiez rapidement qu'un modèle écrit à la main correspond à un vrai payload, clé par clé.
