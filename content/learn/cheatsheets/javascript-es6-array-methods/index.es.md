---
title: "Cheatsheet de JavaScript Moderno: ES6+, Async/Await y Métodos de Array"
description: "La referencia completa de ES6+ para desarrolladores frontend. Domina arrow functions, destructuring, spread operator, promesas, async/await, map/filter/reduce y la Fetch API con ejemplos listos para copiar y pegar."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["cheatsheet javascript", "cheatsheet es6", "aprender desarrollo web", "sintaxis js", "métodos array javascript", "tutorial async await", "entrevista frontend", "javascript desarrollador react", "map filter reduce", "destructuring javascript", "spread operator", "ejemplos fetch api", "encadenamiento de promesas", "arrow functions", "template literals"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet de JavaScript Moderno: ES6+, Async/Await y Métodos de Array",
    "description": "Referencia completa de ES6+ que cubre arrow functions, destructuring, promesas, async/await y métodos de array para desarrolladores frontend.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicializando el Runtime

JavaScript ha evolucionado de un simple lenguaje de scripting a la columna vertebral del desarrollo web moderno. ES6 y versiones posteriores introdujeron características que hacen el código más limpio, predecible y fácil de mantener — arrow functions, destructuring, módulos, async/await y poderosos métodos de array que reemplazan bucles verbosos con transformaciones declarativas. Ya sea que estés construyendo componentes React, manejando llamadas a API o preparándote para una entrevista frontend, este cheatsheet cubre la sintaxis JS que usarás todos los días. Cada fragmento está listo para producción. Copia, pega, despliega.

---

## Declaraciones de Variables

Olvida `var`. El JavaScript moderno usa `let` y `const` para un alcance predecible.

```javascript
// const para valores que no serán reasignados
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let para valores que cambiarán
let currentUser = null;
let retryCount = 0;

// const NO significa inmutable — los objetos y arrays aún pueden ser mutados
const config = { theme: "dark" };
config.theme = "light"; // ✅ Esto funciona
// config = {};          // ❌ TypeError: Assignment to constant variable

// Alcance de bloque — let y const están confinados a su bloque
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Functions

Sintaxis más corta, enlace léxico de `this` y la base de los componentes React.

```javascript
// Función tradicional
function add(a, b) {
  return a + b;
}

// Arrow function (return explícito)
const add = (a, b) => {
  return a + b;
};

// Arrow function (return implícito — expresión única)
const add = (a, b) => a + b;

// Parámetro único — paréntesis opcionales
const double = n => n * 2;

// Sin parámetros — paréntesis vacíos obligatorios
const getTimestamp = () => Date.now();

// Devolver un objeto literal — envolver en paréntesis
const createUser = (name, role) => ({ name, role, active: true });

// Las arrow functions NO tienen su propio `this`
const counter = {
  count: 0,
  // ❌ La arrow function hereda `this` del ámbito exterior (no del objeto)
  incrementBad: () => { this.count++; },
  // ✅ La función regular enlaza `this` al objeto
  increment() { this.count++; },
};
```

---

## Template Literals

Interpolación de cadenas, cadenas multilínea y templates etiquetados.

```javascript
const name = "Federico";
const role = "developer";

// Interpolación de cadenas
const greeting = `Hello, ${name}! You are a ${role}.`;

// Expresiones dentro de templates
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Cadenas multilínea
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Templates etiquetados (usados en librerías como styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Extrae valores de objetos y arrays en una sola línea. Sintaxis JS esencial para las props de React.

```javascript
// Destructuring de objetos
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Renombrar variables
const { name: userName, role: userRole } = user;

// Valores por defecto
const { name, country = "Unknown" } = user;

// Destructuring anidado
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Destructuring de arrays
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Saltar elementos
const [first, , third] = [1, 2, 3];

// Intercambiar variables sin temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Destructuring de parámetros de función (patrón React)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest en destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Operadores Spread y Rest

El operador `...` — spread para expandir, rest para recopilar.

```javascript
// Spread: expandir un array
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: clonar un array (copia superficial)
const clone = [...nums];

// Spread: fusionar objetos (las claves posteriores sobrescriben)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: actualización inmutable del estado (patrón React)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: pasar un array como argumentos de función
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: recopilar argumentos restantes
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: recopilar elementos restantes del array
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Métodos de Array: map, filter, reduce

La sagrada trinidad de la transformación de arrays. Reemplaza bucles con operaciones declarativas y encadenables.

### map — Transformar cada elemento

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Transformar a un nuevo array
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Transformar con índice
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Extraer y remodelar (común en React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Mantener elementos que pasan una prueba

```javascript
// Filtrar por condición
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Eliminar valores falsy
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Eliminar duplicados (con Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Encadenar map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Acumular en un solo valor

```javascript
// Sumar un array
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Contar ocurrencias
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Agrupar por propiedad
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Aplanar arrays anidados (o simplemente usa .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline: encadenar map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Otros Métodos de Array Esenciales

```javascript
const items = [1, 2, 3, 4, 5];

// find — primer elemento que coincide
items.find(n => n > 3); // 4

// findIndex — índice de la primera coincidencia
items.findIndex(n => n > 3); // 3

// some — ¿ALGÚN elemento pasa la prueba?
items.some(n => n > 4); // true

// every — ¿TODOS los elementos pasan la prueba?
items.every(n => n > 0); // true

// includes — ¿el array contiene el valor?
items.includes(3); // true

// flat — aplanar arrays anidados
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten en una sola pasada
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — indexación negativa
items.at(-1); // 5 (último elemento)
items.at(-2); // 4

// Array.from — crear arrays desde iterables
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (iterar objetos como arrays)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promesas

Las promesas representan un valor que estará disponible en el futuro. La base del JavaScript asíncrono.

```javascript
// Crear una promesa
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

// Consumir con .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — ejecutar en paralelo, falla si ALGUNA es rechazada
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — ejecutar en paralelo, nunca rechaza
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — el primero en resolverse gana
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Azúcar sintáctico sobre promesas. Escribe código asíncrono que se lee como código síncrono.

```javascript
// Función async básica
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Versión arrow function
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Manejo de errores con try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Intento ${i + 1} fallido, reintentando...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Ejecución secuencial vs paralela
// ❌ Secuencial — cada await espera al anterior (lento)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Paralelo — lanza ambos a la vez (rápido)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Iteración asíncrona
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // secuencial, uno a la vez
  }
}

// Top-level await (ES2022, soportado en módulos)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

El reemplazo moderno de XMLHttpRequest. Nativo en todos los navegadores y Node 18+.

```javascript
// Petición GET
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// Petición POST con cuerpo JSON
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// Petición PUT
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// Petición DELETE
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Manejar errores HTTP (fetch NO rechaza en 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Subir un archivo con FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Cancelar una petición con AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // timeout de 5s

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("La petición expiró");
}

// Fetch con encabezado de autorización
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Módulos (import / export)

Organiza el código en archivos reutilizables y aislados.

```javascript
// Exports con nombre (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Export por defecto (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Imports con nombre
import { API_URL, formatDate } from "./utils.js";

// Renombrar al importar
import { formatDate as fmt } from "./utils.js";

// Import por defecto
import UserService from "./UserService.js";

// Importar todo como namespace
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Import dinámico (code splitting / carga lazy)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-export (patrón barrel file — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining y Nullish Coalescing

Navega de forma segura por objetos anidados y maneja null/undefined sin verificaciones verbosas.

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
user.address?.zipCode;   // undefined (sin error)
user.social?.twitter;    // undefined (sin error)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (sin error)

// Acceso a arrays
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — solo null/undefined activan el fallback
const port = config.port ?? 3000;        // 3000 si port es null/undefined
const debug = config.debug ?? false;     // false si debug es null/undefined

// Comparar con || (OR lógico) — 0, "", false activan el fallback
0 || 42;       // 42  (0 es falsy)
0 ?? 42;       // 0   (0 no es null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Asignación nullish coalescing (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Trucos Modernos de Objetos

```javascript
// Propiedades abreviadas
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Nombres de propiedades computados
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Método abreviado
const api = {
  getUsers() { /* ... */ },      // en lugar de getUsers: function() {}
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

// Clonación estructurada (copia profunda, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // sigue siendo 42
```

---

## Tabla de Referencia Rápida

| Característica | Sintaxis | Caso de uso |
|---|---|---|
| `const` / `let` | `const x = 1` | Declaraciones con alcance de bloque |
| Arrow function | `(a, b) => a + b` | Callbacks, componentes React |
| Template literal | `` `Hello ${name}` `` | Interpolación de cadenas |
| Destructuring | `const { a, b } = obj` | Extraer valores de objetos/arrays |
| Spread | `{ ...obj, key: val }` | Clonar, fusionar, actualizaciones inmutables |
| Rest | `(...args) => {}` | Recopilar argumentos |
| `map` | `arr.map(fn)` | Transformar cada elemento |
| `filter` | `arr.filter(fn)` | Mantener elementos que cumplen la condición |
| `reduce` | `arr.reduce(fn, init)` | Acumular en un solo valor |
| `?.` | `obj?.prop` | Acceso seguro a propiedades anidadas |
| `??` | `val ?? fallback` | Default solo para null/undefined |
| `async/await` | `const x = await fn()` | Código asíncrono legible |
| `Promise.all` | `await Promise.all([...])` | Operaciones asíncronas en paralelo |

---

## Fin de la Transmisión

Este cheatsheet cubre el JavaScript moderno que todo desarrollador frontend necesita conocer — desde los fundamentos de ES6 hasta patrones asíncronos y la Fetch API. Guárdalo en marcadores, consúltalo durante entrevistas frontend y construye más rápido con sintaxis JS limpia y declarativa. La web funciona con JavaScript. Ahora tú dominas JavaScript.
