---
title: "Converter JSON em Classes C# Online"
description: "Cole um JSON e receba classes C# com propriedades PascalCase, atributos [JsonPropertyName], classes aninhadas e List<T> para System.Text.Json. Grátis."
intro: "Cole um documento JSON e receba na hora **classes de modelo em C#** prontas para usar: propriedades em PascalCase, atributos `[JsonPropertyName]` que preservam as chaves originais, classes aninhadas para objetos aninhados e `List<T>` para arrays. Funciona offline no seu navegador."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["json para c#", "converter json em classe c#", "json to c#", "gerar classes c# a partir de json", "json2csharp", "modelo system.text.json", "json para poco", "gerador de classes c#"]
tags: ["csharp", "dotnet", "json", "ferramentas-dev"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-to-csharp/"
tool_title: "Gerador de classes C# a partir de JSON"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Cole o JSON em **JSON de Entrada**, por exemplo uma resposta de exemplo de uma API. Ele já vem com um exemplo para você ver o resultado de cara."
  - "O painel **Saída C#** atualiza enquanto você digita. Se o JSON estiver malformado, aparece o selo **JSON Inválido** e a mensagem do parser mostra onde."
  - "Confira os tipos gerados: números viram `int`, `long` ou `double`, datas ISO viram `DateTime`, objetos viram classes e arrays viram `List<T>`."
  - "Clique em **Copiar** e cole o código no projeto, por exemplo como `Models/Root.cs`."
  - "Desserialize com `JsonSerializer.Deserialize<Root>(json)`; para um array JSON, use `List<Root>`, como diz o comentário na saída."
faq:
  - q: "Para qual serializador são as classes?"
    a: "System.Text.Json, o serializador nativo desde o .NET Core 3.0. Cada propriedade leva `[JsonPropertyName(\"chave_original\")]`, então `full_name` é mapeado para `FullName` sem configurar política de nomes. Para Newtonsoft.Json, troque o atributo por `[JsonProperty(\"chave_original\")]`."
  - q: "Como os números JSON são mapeados?"
    a: "Inteiros que cabem em 32 bits viram `int`, os maiores `long` e números com casas decimais `double`. Um campo que vale `1` no seu exemplo mas `1.5` em produção ficaria como `int`; use um exemplo representativo, ou troque para `decimal` em valores monetários."
  - q: "Como os arrays de objetos são tratados?"
    a: "Todos os objetos do array são mesclados, então uma propriedade que aparece só em alguns itens também entra, e uma classe é gerada para o tipo do item. O nome é o singular do nome da propriedade: `orders` vira `Order`, `categories` vira `Category`."
  - q: "Por que uma propriedade ficou como object?"
    a: "Porque no exemplo ela era `null`, então não há como saber o tipo real. Troque `object` pelo tipo certo (`string?`, `int?`…) ou cole um exemplo em que o campo tenha valor."
  - q: "Ele gera records ou tipos de referência anuláveis?"
    a: "Ele gera classes simples com propriedades `{ get; set; }`, a forma aceita por qualquer versão do .NET e por qualquer serializador. Passar para `record` ou acrescentar `?` para tipos de referência anuláveis é um ajuste manual rápido se o seu projeto usa isso."
  - q: "Meu JSON é enviado para algum servidor?"
    a: "Não. O parsing e a geração de código rodam em JavaScript nesta página, o que importa quando o exemplo é uma resposta real de API com dados de clientes ou tokens."
---

## Como funciona

A entrada é lida com `JSON.parse`; qualquer erro de sintaxe é avisado em vez de gerar código quebrado. A raiz precisa ser um objeto, ou um array de objetos que é mesclado em uma única classe `Root`.

Cada objeto vira uma classe. Para cada chave:

1. **O nome** é convertido para PascalCase: separadores como `_`, `-` e espaços são removidos e a letra seguinte vira maiúscula (`created_at` → `CreatedAt`). Um nome que começa com número recebe o prefixo `_` para continuar sendo um identificador C# válido.
2. **O tipo** é deduzido do valor de exemplo:

| Valor JSON | Tipo C# |
|---|---|
| `true` / `false` | `bool` |
| inteiro dentro de ±2.147.483.647 | `int` |
| inteiro maior | `long` |
| número com casas decimais | `double` |
| string em formato de data ISO 8601 | `DateTime` |
| outra string | `string` |
| `null` | `object` |
| objeto | nova classe com o nome da propriedade |
| array de objetos | `List<Item>` com uma classe de item mesclada |
| array de primitivos | `List<string>`, `List<int>`… |
| array vazio | `List<object>` |

3. **A chave original** é preservada em um atributo `[JsonPropertyName]`.

Os nomes de classes aninhadas ficam únicos (`Address`, `Address2`…) quando um nome se repete. As linhas `using` só entram quando necessárias: `System` para `DateTime`, `System.Collections.Generic` para listas e sempre `System.Text.Json.Serialization` para o atributo.

### Exemplo

`{"created_at":"2024-01-15T10:30:00Z","orders":[{"order_id":1001,"total":29.99}]}` gera:

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

- **Consumir uma API REST no .NET.** Cole uma resposta de exemplo e receba os DTOs para `HttpClient.GetFromJsonAsync<Root>()`.
- **Objetos de configuração.** Transforme um arquivo de configuração JSON em classes de opções fortemente tipadas para `IOptions<T>`.
- **Webhooks e eventos.** Modele o payload de um webhook do Stripe, GitHub ou Slack antes de escrever o handler.
- **Unity e dados de jogo.** Gere classes para fases, itens ou saves em JSON.
- **Code reviews.** Confira rapidinho se um modelo escrito à mão bate com um payload real, chave por chave.
