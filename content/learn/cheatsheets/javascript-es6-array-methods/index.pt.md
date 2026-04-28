---
title: "Cheatsheet de JavaScript Moderno: ES6+, Async/Await e Métodos de Array"
description: "A referência completa de ES6+ para desenvolvedores frontend. Domine arrow functions, destructuring, spread operator, promises, async/await, map/filter/reduce e a Fetch API com exemplos prontos para copiar e colar."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["cheatsheet javascript", "cheatsheet es6", "aprender desenvolvimento web", "sintaxe js", "métodos de array javascript", "tutorial async await", "entrevista frontend", "javascript desenvolvedor react", "map filter reduce", "destructuring javascript", "spread operator", "exemplos fetch api", "encadeamento de promises", "arrow functions", "template literals"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet de JavaScript Moderno: ES6+, Async/Await e Métodos de Array",
    "description": "Referência completa de ES6+ cobrindo arrow functions, destructuring, promises, async/await e métodos de array para desenvolvedores frontend.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Inicializando o Runtime

JavaScript evoluiu de uma simples linguagem de script para a espinha dorsal do desenvolvimento web moderno. ES6 e versões posteriores introduziram recursos que tornam o código mais limpo, previsível e fácil de manter — arrow functions, destructuring, módulos, async/await e poderosos métodos de array que substituem loops verbosos por transformações declarativas. Seja construindo componentes React, lidando com chamadas de API ou se preparando para uma entrevista frontend, este cheatsheet cobre a sintaxe JS que você usará todos os dias. Cada snippet está pronto para produção. Copie, cole, publique.

---

## Declarações de Variáveis

Esqueça `var`. O JavaScript moderno usa `let` e `const` para escopo previsível.

```javascript
// const para valores que não serão reatribuídos
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let para valores que vão mudar
let currentUser = null;
let retryCount = 0;

// const NÃO significa imutável — objetos e arrays ainda podem ser mutados
const config = { theme: "dark" };
config.theme = "light"; // ✅ Isso funciona
// config = {};          // ❌ TypeError: Assignment to constant variable

// Escopo de bloco — let e const ficam confinados ao seu bloco
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Functions

Sintaxe mais curta, binding léxico do `this` e o elemento essencial dos componentes React.

```javascript
// Função tradicional
function add(a, b) {
  return a + b;
}

// Arrow function (return explícito)
const add = (a, b) => {
  return a + b;
};

// Arrow function (return implícito — expressão única)
const add = (a, b) => a + b;

// Parâmetro único — parênteses opcionais
const double = n => n * 2;

// Sem parâmetros — parênteses vazios obrigatórios
const getTimestamp = () => Date.now();

// Retornar um objeto literal — envolver em parênteses
const createUser = (name, role) => ({ name, role, active: true });

// Arrow functions NÃO têm seu próprio `this`
const counter = {
  count: 0,
  // ❌ Arrow function herda `this` do escopo externo (não do objeto)
  incrementBad: () => { this.count++; },
  // ✅ Função regular vincula `this` ao objeto
  increment() { this.count++; },
};
```

---

## Template Literals

Interpolação de strings, strings multilinha e templates com tags.

```javascript
const name = "Federico";
const role = "developer";

// Interpolação de strings
const greeting = `Hello, ${name}! You are a ${role}.`;

// Expressões dentro de templates
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Strings multilinha
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Templates com tags (usados em bibliotecas como styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Extraia valores de objetos e arrays em uma única linha. Sintaxe JS essencial para props do React.

```javascript
// Destructuring de objetos
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Renomear variáveis
const { name: userName, role: userRole } = user;

// Valores padrão
const { name, country = "Unknown" } = user;

// Destructuring aninhado
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Destructuring de arrays
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Pular elementos
const [first, , third] = [1, 2, 3];

// Trocar variáveis sem temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Destructuring de parâmetros de função (padrão React)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest no destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Operadores Spread e Rest

O operador `...` — spread para expandir, rest para coletar.

```javascript
// Spread: expandir um array
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: clonar um array (cópia superficial)
const clone = [...nums];

// Spread: mesclar objetos (chaves posteriores sobrescrevem)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: atualização imutável do estado (padrão React)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: passar array como argumentos de função
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: coletar argumentos restantes
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: coletar elementos restantes do array
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Métodos de Array: map, filter, reduce

A santíssima trindade da transformação de arrays. Substitua loops por operações declarativas e encadeáveis.

### map — Transformar cada elemento

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Transformar em um novo array
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Transformar com índice
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Extrair e remodelar (comum no React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Manter elementos que passam em um teste

```javascript
// Filtrar por condição
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Remover valores falsy
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Remover duplicatas (com Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Encadear map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Acumular em um único valor

```javascript
// Somar um array
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Contar ocorrências
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Agrupar por propriedade
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Achatar arrays aninhados (ou simplesmente use .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline: encadear map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Outros Métodos de Array Essenciais

```javascript
const items = [1, 2, 3, 4, 5];

// find — primeiro elemento que corresponde
items.find(n => n > 3); // 4

// findIndex — índice da primeira correspondência
items.findIndex(n => n > 3); // 3

// some — ALGUM elemento passa no teste?
items.some(n => n > 4); // true

// every — TODOS os elementos passam no teste?
items.every(n => n > 0); // true

// includes — o array contém o valor?
items.includes(3); // true

// flat — achatar arrays aninhados
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten em uma única passada
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — indexação negativa
items.at(-1); // 5 (último elemento)
items.at(-2); // 4

// Array.from — criar arrays a partir de iteráveis
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (iterar objetos como arrays)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promises

Promises representam um valor que estará disponível no futuro. A base do JavaScript assíncrono.

```javascript
// Criar uma promise
const fetchData = () => {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      const success = true;
      if (success) {
        resolve({ id: 1, name: "Ada" });
      } else {
        reject(new Error("Failed to fetch data"));
      }
    }, 1000);
  });
};

// Consumir com .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — executar em paralelo, falha se QUALQUER uma for rejeitada
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — executar em paralelo, nunca rejeita
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — o primeiro a resolver ganha
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Açúcar sintático sobre promises. Escreva código assíncrono que se lê como código síncrono.

```javascript
// Função async básica
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Versão arrow function
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Tratamento de erros com try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Tentativa ${i + 1} falhou, tentando novamente...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Execução sequencial vs paralela
// ❌ Sequencial — cada await espera o anterior (lento)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Paralelo — dispara ambos de uma vez (rápido)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Iteração assíncrona
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // sequencial, um de cada vez
  }
}

// Top-level await (ES2022, suportado em módulos)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

A substituição moderna do XMLHttpRequest. Nativa em todos os navegadores e Node 18+.

```javascript
// Requisição GET
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// Requisição POST com corpo JSON
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// Requisição PUT
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// Requisição DELETE
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Tratar erros HTTP (fetch NÃO rejeita em 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Enviar um arquivo com FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Cancelar uma requisição com AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // timeout de 5s

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("Requisição expirou");
}

// Fetch com cabeçalho de autorização
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Módulos (import / export)

Organize o código em arquivos reutilizáveis e isolados.

```javascript
// Exports nomeados (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Export padrão (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Imports nomeados
import { API_URL, formatDate } from "./utils.js";

// Renomear no import
import { formatDate as fmt } from "./utils.js";

// Import padrão
import UserService from "./UserService.js";

// Importar tudo como namespace
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Import dinâmico (code splitting / carregamento lazy)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-export (padrão barrel file — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining e Nullish Coalescing

Navegue com segurança por objetos aninhados e lide com null/undefined sem verificações verbosas.

```javascript
const user = {
  name: "Ada",
  address: {
    city: "London",
  },
  getFullName() { return this.name; },
};

// Optional chaining (?.)
user.address?.city;      // "London"
user.address?.zipCode;   // undefined (sem erro)
user.social?.twitter;    // undefined (sem erro)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (sem erro)

// Acesso a arrays
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — apenas null/undefined ativam o fallback
const port = config.port ?? 3000;        // 3000 se port for null/undefined
const debug = config.debug ?? false;     // false se debug for null/undefined

// Comparar com || (OU lógico) — 0, "", false ativam o fallback
0 || 42;       // 42  (0 é falsy)
0 ?? 42;       // 0   (0 não é null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Atribuição nullish coalescing (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Truques Modernos de Objetos

```javascript
// Propriedades abreviadas
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Nomes de propriedades computados
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Método abreviado
const api = {
  getUsers() { /* ... */ },      // em vez de getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — inverso de Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Clonagem estruturada (cópia profunda, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // ainda 42
```

---

## Tabela de Referência Rápida

| Recurso | Sintaxe | Caso de uso |
|---|---|---|
| `const` / `let` | `const x = 1` | Declarações com escopo de bloco |
| Arrow function | `(a, b) => a + b` | Callbacks, componentes React |
| Template literal | `` `Hello ${name}` `` | Interpolação de strings |
| Destructuring | `const { a, b } = obj` | Extrair valores de objetos/arrays |
| Spread | `{ ...obj, key: val }` | Clonar, mesclar, atualizações imutáveis |
| Rest | `(...args) => {}` | Coletar argumentos |
| `map` | `arr.map(fn)` | Transformar cada elemento |
| `filter` | `arr.filter(fn)` | Manter elementos que atendem à condição |
| `reduce` | `arr.reduce(fn, init)` | Acumular em um único valor |
| `?.` | `obj?.prop` | Acesso seguro a propriedades aninhadas |
| `??` | `val ?? fallback` | Padrão apenas para null/undefined |
| `async/await` | `const x = await fn()` | Código assíncrono legível |
| `Promise.all` | `await Promise.all([...])` | Operações assíncronas em paralelo |

---

## Fim da Transmissão

Este cheatsheet cobre o JavaScript moderno que todo desenvolvedor frontend precisa conhecer — dos fundamentos do ES6 aos padrões assíncronos e a Fetch API. Salve nos favoritos, consulte durante entrevistas frontend e construa mais rápido com sintaxe JS limpa e declarativa. A web roda em JavaScript. Agora você domina JavaScript.
