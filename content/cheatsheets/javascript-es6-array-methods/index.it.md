---
title: "Cheatsheet JavaScript Moderno: ES6+, Async/Await e Metodi Array"
description: "Il riferimento completo ES6+ per sviluppatori frontend. Padroneggia arrow function, destructuring, spread operator, promise, async/await, map/filter/reduce e la Fetch API con esempi pronti da copiare e incollare."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["cheatsheet javascript", "cheatsheet es6", "imparare web dev", "sintassi js", "metodi array javascript", "tutorial async await", "colloquio frontend", "javascript sviluppatore react", "map filter reduce", "destructuring javascript", "spread operator", "esempi fetch api", "concatenamento promise", "arrow function", "template literal"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet JavaScript Moderno: ES6+, Async/Await e Metodi Array",
    "description": "Riferimento completo ES6+ che copre arrow function, destructuring, promise, async/await e metodi array per sviluppatori frontend.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Runtime

JavaScript si è evoluto da un semplice linguaggio di scripting nella spina dorsale dello sviluppo web moderno. ES6 e versioni successive hanno introdotto funzionalità che rendono il codice più pulito, prevedibile e facile da mantenere — arrow function, destructuring, moduli, async/await e potenti metodi array che sostituiscono i cicli verbosi con trasformazioni dichiarative. Che tu stia costruendo componenti React, gestendo chiamate API o preparandoti per un colloquio frontend, questo cheatsheet copre la sintassi JS che userai ogni singolo giorno. Ogni snippet è pronto per la produzione. Copia, incolla, pubblica.

---

## Dichiarazioni di Variabili

Dimentica `var`. Il JavaScript moderno usa `let` e `const` per uno scoping prevedibile.

```javascript
// const per valori che non verranno riassegnati
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let per valori che cambieranno
let currentUser = null;
let retryCount = 0;

// const NON significa immutabile — oggetti e array possono ancora essere mutati
const config = { theme: "dark" };
config.theme = "light"; // ✅ Funziona
// config = {};          // ❌ TypeError: Assignment to constant variable

// Scoping a blocco — let e const sono confinati al loro blocco
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Function

Sintassi più breve, binding lessicale di `this` e il pane quotidiano dei componenti React.

```javascript
// Funzione tradizionale
function add(a, b) {
  return a + b;
}

// Arrow function (return esplicito)
const add = (a, b) => {
  return a + b;
};

// Arrow function (return implicito — espressione singola)
const add = (a, b) => a + b;

// Parametro singolo — parentesi opzionali
const double = n => n * 2;

// Nessun parametro — parentesi vuote obbligatorie
const getTimestamp = () => Date.now();

// Restituire un oggetto letterale — racchiudere tra parentesi
const createUser = (name, role) => ({ name, role, active: true });

// Le arrow function NON hanno il proprio `this`
const counter = {
  count: 0,
  // ❌ La arrow function eredita `this` dallo scope esterno (non dall'oggetto)
  incrementBad: () => { this.count++; },
  // ✅ La funzione regolare lega `this` all'oggetto
  increment() { this.count++; },
};
```

---

## Template Literal

Interpolazione di stringhe, stringhe multiriga e template con tag.

```javascript
const name = "Federico";
const role = "developer";

// Interpolazione di stringhe
const greeting = `Hello, ${name}! You are a ${role}.`;

// Espressioni nei template
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Stringhe multiriga
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Template con tag (usati in librerie come styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Estrai valori da oggetti e array in una singola riga. Sintassi JS essenziale per le props di React.

```javascript
// Destructuring di oggetti
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Rinominare variabili
const { name: userName, role: userRole } = user;

// Valori predefiniti
const { name, country = "Unknown" } = user;

// Destructuring annidato
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Destructuring di array
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Saltare elementi
const [first, , third] = [1, 2, 3];

// Scambiare variabili senza temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Destructuring dei parametri di funzione (pattern React)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest nel destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Operatori Spread e Rest

L'operatore `...` — spread per espandere, rest per raccogliere.

```javascript
// Spread: espandere un array
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: clonare un array (copia superficiale)
const clone = [...nums];

// Spread: unire oggetti (le chiavi successive sovrascrivono)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: aggiornamento immutabile dello stato (pattern React)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: passare un array come argomenti di funzione
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: raccogliere gli argomenti rimanenti
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: raccogliere gli elementi rimanenti dell'array
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Metodi Array: map, filter, reduce

La sacra trinità della trasformazione degli array. Sostituisci i cicli con operazioni dichiarative e concatenabili.

### map — Trasforma ogni elemento

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Trasforma in un nuovo array
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Trasforma con indice
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Estrarre e rimodellare (comune in React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Mantieni gli elementi che superano un test

```javascript
// Filtrare per condizione
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Rimuovere valori falsy
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Rimuovere duplicati (con Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Concatenare map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Accumulare in un singolo valore

```javascript
// Sommare un array
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Contare le occorrenze
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Raggruppare per proprietà
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Appiattire array annidati (oppure usa .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline: concatenare map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Altri Metodi Array Essenziali

```javascript
const items = [1, 2, 3, 4, 5];

// find — primo elemento che corrisponde
items.find(n => n > 3); // 4

// findIndex — indice della prima corrispondenza
items.findIndex(n => n > 3); // 3

// some — QUALCHE elemento supera il test?
items.some(n => n > 4); // true

// every — TUTTI gli elementi superano il test?
items.every(n => n > 0); // true

// includes — l'array contiene il valore?
items.includes(3); // true

// flat — appiattire array annidati
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten in un solo passaggio
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — indicizzazione negativa
items.at(-1); // 5 (ultimo elemento)
items.at(-2); // 4

// Array.from — creare array da iterabili
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (iterare oggetti come array)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promise

Le Promise rappresentano un valore che sarà disponibile in futuro. La base del JavaScript asincrono.

```javascript
// Creare una promise
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

// Consumare con .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — eseguire in parallelo, fallisce se QUALCUNA viene rifiutata
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — eseguire in parallelo, non rifiuta mai
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — il primo a completarsi vince
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Zucchero sintattico sulle promise. Scrivi codice asincrono che si legge come codice sincrono.

```javascript
// Funzione async di base
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Versione arrow function
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Gestione degli errori con try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Tentativo ${i + 1} fallito, nuovo tentativo...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Esecuzione sequenziale vs parallela
// ❌ Sequenziale — ogni await aspetta il precedente (lento)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Parallelo — lancia entrambi contemporaneamente (veloce)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Iterazione asincrona
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // sequenziale, uno alla volta
  }
}

// Top-level await (ES2022, supportato nei moduli)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

La sostituzione moderna di XMLHttpRequest. Nativa in ogni browser e Node 18+.

```javascript
// Richiesta GET
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// Richiesta POST con corpo JSON
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// Richiesta PUT
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// Richiesta DELETE
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Gestire errori HTTP (fetch NON rifiuta su 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Caricare un file con FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Annullare una richiesta con AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // timeout 5s

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("Richiesta scaduta");
}

// Fetch con header di autorizzazione
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Moduli (import / export)

Organizza il codice in file riutilizzabili e isolati.

```javascript
// Export con nome (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Export predefinito (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Import con nome
import { API_URL, formatDate } from "./utils.js";

// Rinominare all'import
import { formatDate as fmt } from "./utils.js";

// Import predefinito
import UserService from "./UserService.js";

// Importare tutto come namespace
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Import dinamico (code splitting / caricamento lazy)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-export (pattern barrel file — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining e Nullish Coalescing

Naviga in sicurezza negli oggetti annidati e gestisci null/undefined senza controlli verbosi.

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
user.address?.zipCode;   // undefined (nessun errore)
user.social?.twitter;    // undefined (nessun errore)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (nessun errore)

// Accesso agli array
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — solo null/undefined attivano il fallback
const port = config.port ?? 3000;        // 3000 se port è null/undefined
const debug = config.debug ?? false;     // false se debug è null/undefined

// Confronto con || (OR logico) — 0, "", false attivano il fallback
0 || 42;       // 42  (0 è falsy)
0 ?? 42;       // 0   (0 non è null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Assegnazione nullish coalescing (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Trucchi Moderni per gli Oggetti

```javascript
// Proprietà abbreviate
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Nomi di proprietà calcolati
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Metodo abbreviato
const api = {
  getUsers() { /* ... */ },      // invece di getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — inverso di Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Clonazione strutturata (copia profonda, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // ancora 42
```

---

## Tabella di Riferimento Rapido

| Funzionalità | Sintassi | Caso d'uso |
|---|---|---|
| `const` / `let` | `const x = 1` | Dichiarazioni con scope a blocco |
| Arrow function | `(a, b) => a + b` | Callback, componenti React |
| Template literal | `` `Hello ${name}` `` | Interpolazione di stringhe |
| Destructuring | `const { a, b } = obj` | Estrarre valori da oggetti/array |
| Spread | `{ ...obj, key: val }` | Clonare, unire, aggiornamenti immutabili |
| Rest | `(...args) => {}` | Raccogliere argomenti |
| `map` | `arr.map(fn)` | Trasformare ogni elemento |
| `filter` | `arr.filter(fn)` | Mantenere elementi che soddisfano la condizione |
| `reduce` | `arr.reduce(fn, init)` | Accumulare in un singolo valore |
| `?.` | `obj?.prop` | Accesso sicuro a proprietà annidate |
| `??` | `val ?? fallback` | Default solo per null/undefined |
| `async/await` | `const x = await fn()` | Codice asincrono leggibile |
| `Promise.all` | `await Promise.all([...])` | Operazioni asincrone in parallelo |

---

## Fine della Trasmissione

Questo cheatsheet copre il JavaScript moderno che ogni sviluppatore frontend deve conoscere — dai fondamentali di ES6 ai pattern asincroni e la Fetch API. Aggiungilo ai preferiti, consultalo durante i colloqui frontend e costruisci più velocemente con sintassi JS pulita e dichiarativa. Il web gira su JavaScript. Ora sei tu a far girare JavaScript.
