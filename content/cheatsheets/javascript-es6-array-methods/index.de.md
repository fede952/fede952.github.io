---
title: "Modernes JavaScript Cheatsheet: ES6+, Async/Await & Array-Methoden"
description: "Die vollständige ES6+-Referenz für Frontend-Entwickler. Meistern Sie Arrow Functions, Destructuring, Spread-Operator, Promises, Async/Await, Map/Filter/Reduce und die Fetch API mit kopierfertigen Beispielen."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["javascript cheatsheet", "es6 cheatsheet", "webentwicklung lernen", "js syntax", "javascript array methoden", "async await tutorial", "frontend interview", "react entwickler javascript", "map filter reduce", "destructuring javascript", "spread operator", "fetch api beispiele", "promise verkettung", "arrow functions", "template literals"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Modernes JavaScript Cheatsheet: ES6+, Async/Await & Array-Methoden",
    "description": "Vollständige ES6+-Referenz zu Arrow Functions, Destructuring, Promises, Async/Await und Array-Methoden für Frontend-Entwickler.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Runtime initialisieren

JavaScript hat sich von einer einfachen Skriptsprache zum Rückgrat der modernen Webentwicklung entwickelt. ES6 und spätere Versionen führten Features ein, die Code sauberer, vorhersehbarer und leichter wartbar machen — Arrow Functions, Destructuring, Module, Async/Await und leistungsstarke Array-Methoden, die ausführliche Schleifen durch deklarative Transformationen ersetzen. Ob Sie React-Komponenten bauen, API-Aufrufe handhaben oder sich auf ein Frontend-Interview vorbereiten — dieses Cheatsheet deckt die JS-Syntax ab, die Sie jeden Tag verwenden werden. Jedes Snippet ist produktionsbereit. Kopieren, einfügen, ausliefern.

---

## Variablendeklarationen

Vergessen Sie `var`. Modernes JavaScript verwendet `let` und `const` für vorhersehbares Scoping.

```javascript
// const für Werte, die nicht neu zugewiesen werden
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let für Werte, die sich ändern werden
let currentUser = null;
let retryCount = 0;

// const bedeutet NICHT unveränderlich — Objekte und Arrays können weiterhin mutiert werden
const config = { theme: "dark" };
config.theme = "light"; // ✅ Das funktioniert
// config = {};          // ❌ TypeError: Assignment to constant variable

// Block-Scoping — let und const sind auf ihren Block beschränkt
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Functions

Kürzere Syntax, lexikalische `this`-Bindung und das Grundelement von React-Komponenten.

```javascript
// Traditionelle Funktion
function add(a, b) {
  return a + b;
}

// Arrow Function (explizites Return)
const add = (a, b) => {
  return a + b;
};

// Arrow Function (implizites Return — einzelner Ausdruck)
const add = (a, b) => a + b;

// Einzelner Parameter — Klammern optional
const double = n => n * 2;

// Keine Parameter — leere Klammern erforderlich
const getTimestamp = () => Date.now();

// Ein Objekt-Literal zurückgeben — in Klammern einschließen
const createUser = (name, role) => ({ name, role, active: true });

// Arrow Functions haben KEIN eigenes `this`
const counter = {
  count: 0,
  // ❌ Arrow Function erbt `this` vom äußeren Scope (nicht vom Objekt)
  incrementBad: () => { this.count++; },
  // ✅ Reguläre Funktion bindet `this` an das Objekt
  increment() { this.count++; },
};
```

---

## Template Literals

String-Interpolation, mehrzeilige Strings und getaggte Templates.

```javascript
const name = "Federico";
const role = "developer";

// String-Interpolation
const greeting = `Hello, ${name}! You are a ${role}.`;

// Ausdrücke in Templates
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Mehrzeilige Strings
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Getaggte Templates (verwendet in Bibliotheken wie styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Werte aus Objekten und Arrays in einer einzigen Zeile extrahieren. Essentielle JS-Syntax für React-Props.

```javascript
// Objekt-Destructuring
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Variablen umbenennen
const { name: userName, role: userRole } = user;

// Standardwerte
const { name, country = "Unknown" } = user;

// Verschachteltes Destructuring
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Array-Destructuring
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Elemente überspringen
const [first, , third] = [1, 2, 3];

// Variablen ohne temp tauschen
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Funktionsparameter-Destructuring (React-Pattern)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest beim Destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Spread- und Rest-Operatoren

Der `...`-Operator — Spread zum Erweitern, Rest zum Sammeln.

```javascript
// Spread: ein Array erweitern
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: ein Array klonen (flache Kopie)
const clone = [...nums];

// Spread: Objekte zusammenführen (spätere Schlüssel überschreiben)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: unveränderliche State-Aktualisierung (React-Pattern)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: Array als Funktionsargumente übergeben
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: verbleibende Argumente sammeln
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: verbleibende Array-Elemente sammeln
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Array-Methoden: map, filter, reduce

Die heilige Dreifaltigkeit der Array-Transformation. Ersetzen Sie Schleifen durch deklarative, verkettbare Operationen.

### map — Jedes Element transformieren

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// In ein neues Array transformieren
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Mit Index transformieren
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Extrahieren und umformen (häufig in React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Elemente behalten, die einen Test bestehen

```javascript
// Nach Bedingung filtern
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Falsy-Werte entfernen
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Duplikate entfernen (mit Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// map + filter verketten
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Zu einem einzelnen Wert akkumulieren

```javascript
// Ein Array summieren
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Vorkommen zählen
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Nach Eigenschaft gruppieren
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Verschachtelte Arrays abflachen (oder verwenden Sie einfach .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline: map + filter + reduce verketten
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Weitere essentielle Array-Methoden

```javascript
const items = [1, 2, 3, 4, 5];

// find — erstes Element, das übereinstimmt
items.find(n => n > 3); // 4

// findIndex — Index der ersten Übereinstimmung
items.findIndex(n => n > 3); // 3

// some — besteht IRGENDEIN Element den Test?
items.some(n => n > 4); // true

// every — bestehen ALLE Elemente den Test?
items.every(n => n > 0); // true

// includes — enthält das Array den Wert?
items.includes(3); // true

// flat — verschachtelte Arrays abflachen
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten in einem Durchgang
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — negative Indizierung
items.at(-1); // 5 (letztes Element)
items.at(-2); // 4

// Array.from — Arrays aus Iterables erstellen
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (Objekte wie Arrays iterieren)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promises

Promises repräsentieren einen Wert, der in der Zukunft verfügbar sein wird. Das Fundament von asynchronem JavaScript.

```javascript
// Ein Promise erstellen
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

// Mit .then/.catch konsumieren
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — parallel ausführen, schlägt fehl wenn EINES abgelehnt wird
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — parallel ausführen, lehnt nie ab
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — der Erste gewinnt
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Syntaktischer Zucker über Promises. Schreiben Sie asynchronen Code, der sich wie synchroner Code liest.

```javascript
// Einfache async-Funktion
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Arrow-Function-Version
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Fehlerbehandlung mit try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Versuch ${i + 1} fehlgeschlagen, erneuter Versuch...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Sequentielle vs parallele Ausführung
// ❌ Sequentiell — jedes await wartet auf das vorherige (langsam)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Parallel — beide gleichzeitig starten (schnell)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Asynchrone Iteration
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // sequentiell, eines nach dem anderen
  }
}

// Top-level await (ES2022, unterstützt in Modulen)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

Der moderne Ersatz für XMLHttpRequest. Nativ in jedem Browser und Node 18+.

```javascript
// GET-Anfrage
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// POST-Anfrage mit JSON-Body
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// PUT-Anfrage
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// DELETE-Anfrage
await fetch(`/api/users/${id}`, { method: "DELETE" });

// HTTP-Fehler behandeln (fetch lehnt NICHT bei 4xx/5xx ab)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Datei mit FormData hochladen
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Anfrage mit AbortController abbrechen
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // 5s Timeout

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("Anfrage abgelaufen");
}

// Fetch mit Autorisierungs-Header
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Module (import / export)

Code in wiederverwendbare, isolierte Dateien organisieren.

```javascript
// Benannte Exports (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Standard-Export (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Benannte Imports
import { API_URL, formatDate } from "./utils.js";

// Beim Import umbenennen
import { formatDate as fmt } from "./utils.js";

// Standard-Import
import UserService from "./UserService.js";

// Alles als Namespace importieren
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Dynamischer Import (Code-Splitting / Lazy Loading)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-Export (Barrel-File-Pattern — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining und Nullish Coalescing

Sicher durch verschachtelte Objekte navigieren und null/undefined ohne umständliche Prüfungen behandeln.

```javascript
const user = {
  name: "Ada",
  address: {
    city: "London",
  },
  getFullName() { return this.name; },
};

// Optional Chaining (?.)
user.address?.city;      // "London"
user.address?.zipCode;   // undefined (kein Fehler)
user.social?.twitter;    // undefined (kein Fehler)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (kein Fehler)

// Array-Zugriff
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish Coalescing (??) — nur null/undefined lösen den Fallback aus
const port = config.port ?? 3000;        // 3000 wenn port null/undefined ist
const debug = config.debug ?? false;     // false wenn debug null/undefined ist

// Vergleich mit || (logisches ODER) — 0, "", false lösen den Fallback aus
0 || 42;       // 42  (0 ist falsy)
0 ?? 42;       // 0   (0 ist nicht null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Nullish-Coalescing-Zuweisung (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Moderne Objekt-Tricks

```javascript
// Kurzschreibweise für Eigenschaften
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Berechnete Eigenschaftsnamen
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Methoden-Kurzschreibweise
const api = {
  getUsers() { /* ... */ },      // anstatt getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — Umkehrung von Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Strukturiertes Klonen (tiefe Kopie, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // immer noch 42
```

---

## Schnellreferenz-Tabelle

| Feature | Syntax | Anwendungsfall |
|---|---|---|
| `const` / `let` | `const x = 1` | Block-gescopte Deklarationen |
| Arrow Function | `(a, b) => a + b` | Callbacks, React-Komponenten |
| Template Literal | `` `Hello ${name}` `` | String-Interpolation |
| Destructuring | `const { a, b } = obj` | Werte aus Objekten/Arrays extrahieren |
| Spread | `{ ...obj, key: val }` | Klonen, Zusammenführen, unveränderliche Updates |
| Rest | `(...args) => {}` | Argumente sammeln |
| `map` | `arr.map(fn)` | Jedes Element transformieren |
| `filter` | `arr.filter(fn)` | Elemente behalten, die die Bedingung erfüllen |
| `reduce` | `arr.reduce(fn, init)` | Zu einem einzelnen Wert akkumulieren |
| `?.` | `obj?.prop` | Sicherer verschachtelter Zugriff |
| `??` | `val ?? fallback` | Standard nur für null/undefined |
| `async/await` | `const x = await fn()` | Lesbarer asynchroner Code |
| `Promise.all` | `await Promise.all([...])` | Parallele asynchrone Operationen |

---

## Ende der Übertragung

Dieses Cheatsheet deckt das moderne JavaScript ab, das jeder Frontend-Entwickler kennen muss — von den ES6-Grundlagen über asynchrone Patterns bis zur Fetch API. Setzen Sie ein Lesezeichen, nutzen Sie es als Referenz bei Frontend-Interviews und entwickeln Sie schneller mit sauberer, deklarativer JS-Syntax. Das Web läuft auf JavaScript. Jetzt beherrschen Sie JavaScript.
