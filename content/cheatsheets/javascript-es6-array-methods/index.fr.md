---
title: "Cheatsheet JavaScript Moderne : ES6+, Async/Await et Méthodes de Tableaux"
description: "La référence complète ES6+ pour les développeurs frontend. Maîtrisez les arrow functions, le destructuring, l'opérateur spread, les promesses, async/await, map/filter/reduce et l'API Fetch avec des exemples prêts à copier-coller."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["cheatsheet javascript", "cheatsheet es6", "apprendre le dev web", "syntaxe js", "méthodes de tableaux javascript", "tutoriel async await", "entretien frontend", "javascript développeur react", "map filter reduce", "destructuring javascript", "opérateur spread", "exemples fetch api", "chaînage de promesses", "arrow functions", "template literals"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet JavaScript Moderne : ES6+, Async/Await et Méthodes de Tableaux",
    "description": "Référence complète ES6+ couvrant les arrow functions, le destructuring, les promesses, async/await et les méthodes de tableaux pour les développeurs frontend.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Runtime

JavaScript a évolué d'un simple langage de script en l'épine dorsale du développement web moderne. ES6 et les versions suivantes ont introduit des fonctionnalités qui rendent le code plus propre, plus prévisible et plus facile à maintenir — arrow functions, destructuring, modules, async/await et de puissantes méthodes de tableaux qui remplacent les boucles verbeuses par des transformations déclaratives. Que vous construisiez des composants React, gériez des appels API ou prépariez un entretien frontend, ce cheatsheet couvre la syntaxe JS que vous utiliserez chaque jour. Chaque extrait est prêt pour la production. Copiez, collez, déployez.

---

## Déclarations de Variables

Oubliez `var`. Le JavaScript moderne utilise `let` et `const` pour une portée prévisible.

```javascript
// const pour les valeurs qui ne seront pas réassignées
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let pour les valeurs qui changeront
let currentUser = null;
let retryCount = 0;

// const ne signifie PAS immuable — les objets et tableaux peuvent encore être mutés
const config = { theme: "dark" };
config.theme = "light"; // ✅ Ça fonctionne
// config = {};          // ❌ TypeError: Assignment to constant variable

// Portée de bloc — let et const sont confinés à leur bloc
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Functions

Syntaxe plus courte, liaison lexicale du `this` et l'élément fondamental des composants React.

```javascript
// Fonction traditionnelle
function add(a, b) {
  return a + b;
}

// Arrow function (return explicite)
const add = (a, b) => {
  return a + b;
};

// Arrow function (return implicite — expression unique)
const add = (a, b) => a + b;

// Paramètre unique — parenthèses optionnelles
const double = n => n * 2;

// Aucun paramètre — parenthèses vides obligatoires
const getTimestamp = () => Date.now();

// Retourner un objet littéral — entourer de parenthèses
const createUser = (name, role) => ({ name, role, active: true });

// Les arrow functions n'ont PAS leur propre `this`
const counter = {
  count: 0,
  // ❌ L'arrow function hérite du `this` de la portée extérieure (pas de l'objet)
  incrementBad: () => { this.count++; },
  // ✅ La fonction classique lie `this` à l'objet
  increment() { this.count++; },
};
```

---

## Template Literals

Interpolation de chaînes, chaînes multilignes et templates étiquetés.

```javascript
const name = "Federico";
const role = "developer";

// Interpolation de chaînes
const greeting = `Hello, ${name}! You are a ${role}.`;

// Expressions dans les templates
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Chaînes multilignes
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Templates étiquetés (utilisés dans des bibliothèques comme styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Extraire des valeurs d'objets et de tableaux en une seule ligne. Syntaxe JS essentielle pour les props React.

```javascript
// Destructuring d'objets
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Renommer les variables
const { name: userName, role: userRole } = user;

// Valeurs par défaut
const { name, country = "Unknown" } = user;

// Destructuring imbriqué
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Destructuring de tableaux
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Sauter des éléments
const [first, , third] = [1, 2, 3];

// Échanger des variables sans temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Destructuring des paramètres de fonction (pattern React)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest dans le destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Opérateurs Spread et Rest

L'opérateur `...` — spread pour étendre, rest pour collecter.

```javascript
// Spread : étendre un tableau
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread : cloner un tableau (copie superficielle)
const clone = [...nums];

// Spread : fusionner des objets (les clés ultérieures écrasent)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread : mise à jour immuable de l'état (pattern React)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread : passer un tableau comme arguments de fonction
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest : collecter les arguments restants
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest : collecter les éléments restants du tableau
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Méthodes de Tableaux : map, filter, reduce

La sainte trinité de la transformation de tableaux. Remplacez les boucles par des opérations déclaratives et chaînables.

### map — Transformer chaque élément

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Transformer en un nouveau tableau
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Transformer avec index
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Extraire et remodeler (courant en React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Garder les éléments qui passent un test

```javascript
// Filtrer par condition
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Supprimer les valeurs falsy
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Supprimer les doublons (avec Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Chaîner map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Accumuler en une seule valeur

```javascript
// Sommer un tableau
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Compter les occurrences
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Grouper par propriété
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Aplatir des tableaux imbriqués (ou utilisez simplement .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline : chaîner map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Autres Méthodes de Tableaux Essentielles

```javascript
const items = [1, 2, 3, 4, 5];

// find — premier élément qui correspond
items.find(n => n > 3); // 4

// findIndex — index de la première correspondance
items.findIndex(n => n > 3); // 3

// some — est-ce qu'UN élément passe le test ?
items.some(n => n > 4); // true

// every — est-ce que TOUS les éléments passent le test ?
items.every(n => n > 0); // true

// includes — le tableau contient-il la valeur ?
items.includes(3); // true

// flat — aplatir des tableaux imbriqués
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten en une seule passe
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — indexation négative
items.at(-1); // 5 (dernier élément)
items.at(-2); // 4

// Array.from — créer des tableaux à partir d'itérables
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (itérer sur les objets comme des tableaux)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promesses

Les promesses représentent une valeur qui sera disponible dans le futur. La base du JavaScript asynchrone.

```javascript
// Créer une promesse
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

// Consommer avec .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — exécuter en parallèle, échoue si UNE est rejetée
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — exécuter en parallèle, ne rejette jamais
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — le premier à se résoudre gagne
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Sucre syntaxique sur les promesses. Écrivez du code asynchrone qui se lit comme du code synchrone.

```javascript
// Fonction async de base
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Version arrow function
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Gestion des erreurs avec try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Tentative ${i + 1} échouée, nouvelle tentative...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Exécution séquentielle vs parallèle
// ❌ Séquentielle — chaque await attend le précédent (lent)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Parallèle — lance les deux en même temps (rapide)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Itération asynchrone
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // séquentiel, un à la fois
  }
}

// Top-level await (ES2022, supporté dans les modules)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

Le remplacement moderne de XMLHttpRequest. Natif dans tous les navigateurs et Node 18+.

```javascript
// Requête GET
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// Requête POST avec corps JSON
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// Requête PUT
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// Requête DELETE
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Gérer les erreurs HTTP (fetch NE rejette PAS sur 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Télécharger un fichier avec FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Annuler une requête avec AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // timeout de 5s

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("La requête a expiré");
}

// Fetch avec en-tête d'autorisation
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Modules (import / export)

Organisez le code en fichiers réutilisables et isolés.

```javascript
// Exports nommés (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Export par défaut (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Imports nommés
import { API_URL, formatDate } from "./utils.js";

// Renommer à l'import
import { formatDate as fmt } from "./utils.js";

// Import par défaut
import UserService from "./UserService.js";

// Tout importer comme namespace
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Import dynamique (code splitting / chargement lazy)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-export (pattern barrel file — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining et Nullish Coalescing

Naviguez en toute sécurité dans les objets imbriqués et gérez null/undefined sans vérifications verbeuses.

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
user.address?.zipCode;   // undefined (pas d'erreur)
user.social?.twitter;    // undefined (pas d'erreur)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (pas d'erreur)

// Accès aux tableaux
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — seuls null/undefined déclenchent le fallback
const port = config.port ?? 3000;        // 3000 si port est null/undefined
const debug = config.debug ?? false;     // false si debug est null/undefined

// Comparer avec || (OU logique) — 0, "", false déclenchent le fallback
0 || 42;       // 42  (0 est falsy)
0 ?? 42;       // 0   (0 n'est pas null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Affectation nullish coalescing (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Astuces Modernes pour les Objets

```javascript
// Propriétés abrégées
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Noms de propriétés calculés
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Méthode abrégée
const api = {
  getUsers() { /* ... */ },      // au lieu de getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — l'inverse de Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Clonage structuré (copie profonde, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // toujours 42
```

---

## Tableau de Référence Rapide

| Fonctionnalité | Syntaxe | Cas d'utilisation |
|---|---|---|
| `const` / `let` | `const x = 1` | Déclarations à portée de bloc |
| Arrow function | `(a, b) => a + b` | Callbacks, composants React |
| Template literal | `` `Hello ${name}` `` | Interpolation de chaînes |
| Destructuring | `const { a, b } = obj` | Extraire des valeurs d'objets/tableaux |
| Spread | `{ ...obj, key: val }` | Cloner, fusionner, mises à jour immuables |
| Rest | `(...args) => {}` | Collecter les arguments |
| `map` | `arr.map(fn)` | Transformer chaque élément |
| `filter` | `arr.filter(fn)` | Garder les éléments correspondant à la condition |
| `reduce` | `arr.reduce(fn, init)` | Accumuler en une seule valeur |
| `?.` | `obj?.prop` | Accès sécurisé aux propriétés imbriquées |
| `??` | `val ?? fallback` | Valeur par défaut uniquement pour null/undefined |
| `async/await` | `const x = await fn()` | Code asynchrone lisible |
| `Promise.all` | `await Promise.all([...])` | Opérations asynchrones en parallèle |

---

## Fin de Transmission

Ce cheatsheet couvre le JavaScript moderne que tout développeur frontend doit connaître — des fondamentaux d'ES6 aux patterns asynchrones et l'API Fetch. Ajoutez-le à vos favoris, consultez-le lors des entretiens frontend et développez plus vite avec une syntaxe JS propre et déclarative. Le web tourne sur JavaScript. Maintenant, c'est vous qui faites tourner JavaScript.
