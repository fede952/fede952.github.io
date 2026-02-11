---
title: "Modern JavaScript Cheatsheet: ES6+, Async/Await & Array Methods"
description: "The complete ES6+ reference for frontend developers. Master arrow functions, destructuring, spread operator, promises, async/await, map/filter/reduce, and the Fetch API with copy-paste examples."
date: 2026-02-11
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["javascript cheatsheet", "es6 cheatsheet", "learn web dev", "js syntax", "javascript array methods", "async await tutorial", "frontend interview", "react developer javascript", "map filter reduce", "destructuring javascript", "spread operator", "fetch api examples", "promise chaining", "arrow functions", "template literals"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Modern JavaScript Cheatsheet: ES6+, Async/Await & Array Methods",
    "description": "Complete ES6+ reference covering arrow functions, destructuring, promises, async/await, and array methods for frontend developers.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## Initializing Runtime

JavaScript has evolved from a simple scripting language into the backbone of modern web development. ES6 and beyond introduced features that make code cleaner, more predictable, and easier to maintain — arrow functions, destructuring, modules, async/await, and powerful array methods that replace verbose loops with declarative transformations. Whether you are building React components, handling API calls, or preparing for a frontend interview, this cheatsheet covers the JS syntax you will use every single day. Every snippet is production-ready. Copy, paste, ship.

---

## Variable Declarations

Forget `var`. Modern JavaScript uses `let` and `const` for predictable scoping.

```javascript
// const for values that won't be reassigned
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let for values that will change
let currentUser = null;
let retryCount = 0;

// const does NOT mean immutable — objects and arrays can still be mutated
const config = { theme: "dark" };
config.theme = "light"; // ✅ This works
// config = {};          // ❌ TypeError: Assignment to constant variable

// Block scoping — let and const are confined to their block
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Arrow Functions

Shorter syntax, lexical `this` binding, and the bread and butter of React components.

```javascript
// Traditional function
function add(a, b) {
  return a + b;
}

// Arrow function (explicit return)
const add = (a, b) => {
  return a + b;
};

// Arrow function (implicit return — single expression)
const add = (a, b) => a + b;

// Single parameter — parentheses optional
const double = n => n * 2;

// No parameters — empty parentheses required
const getTimestamp = () => Date.now();

// Returning an object literal — wrap in parentheses
const createUser = (name, role) => ({ name, role, active: true });

// Arrow functions do NOT have their own `this`
const counter = {
  count: 0,
  // ❌ Arrow function inherits `this` from outer scope (not the object)
  incrementBad: () => { this.count++; },
  // ✅ Regular function binds `this` to the object
  increment() { this.count++; },
};
```

---

## Template Literals

String interpolation, multiline strings, and tagged templates.

```javascript
const name = "Federico";
const role = "developer";

// String interpolation
const greeting = `Hello, ${name}! You are a ${role}.`;

// Expressions inside templates
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Multiline strings
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Tagged templates (used in libraries like styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Destructuring

Extract values from objects and arrays in a single line. Essential JS syntax for React props.

```javascript
// Object destructuring
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Rename variables
const { name: userName, role: userRole } = user;

// Default values
const { name, country = "Unknown" } = user;

// Nested destructuring
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Array destructuring
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Skip elements
const [first, , third] = [1, 2, 3];

// Swap variables without temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Function parameter destructuring (React pattern)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest in destructuring
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Spread & Rest Operators

The `...` operator — spread to expand, rest to collect.

```javascript
// Spread: expand an array
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: clone an array (shallow copy)
const clone = [...nums];

// Spread: merge objects (later keys overwrite)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: immutable state update (React pattern)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: pass array as function arguments
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: collect remaining arguments
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: collect remaining array elements
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Array Methods: map, filter, reduce

The holy trinity of array transformation. Replace loops with declarative, chainable operations.

### map — Transform every element

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Transform to new array
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Transform with index
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Extract and reshape (common in React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Keep elements that pass a test

```javascript
// Filter by condition
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Remove falsy values
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Remove duplicates (with Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Chain map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Accumulate into a single value

```javascript
// Sum an array
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Count occurrences
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Group by property
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Flatten nested arrays (or just use .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Pipeline: chain map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Other Essential Array Methods

```javascript
const items = [1, 2, 3, 4, 5];

// find — first element that matches
items.find(n => n > 3); // 4

// findIndex — index of first match
items.findIndex(n => n > 3); // 3

// some — does ANY element pass the test?
items.some(n => n > 4); // true

// every — do ALL elements pass the test?
items.every(n => n > 0); // true

// includes — does the array contain the value?
items.includes(3); // true

// flat — flatten nested arrays
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten in one pass
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — negative indexing
items.at(-1); // 5 (last element)
items.at(-2); // 4

// Array.from — create arrays from iterables
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (iterate objects like arrays)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Promises

Promises represent a value that will be available in the future. The foundation of async JavaScript.

```javascript
// Create a promise
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

// Consume with .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — run in parallel, fail if ANY rejects
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — run in parallel, never rejects
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — first to settle wins
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Syntactic sugar over promises. Write asynchronous code that reads like synchronous code.

```javascript
// Basic async function
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Arrow function version
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Error handling with try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Attempt ${i + 1} failed, retrying...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Sequential vs Parallel execution
// ❌ Sequential — each awaits the previous (slow)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Parallel — fire both at once (fast)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Async iteration
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // sequential, one at a time
  }
}

// Top-level await (ES2022, supported in modules)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

The modern replacement for XMLHttpRequest. Native in every browser and Node 18+.

```javascript
// GET request
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// POST request with JSON body
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// PUT request
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// DELETE request
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Handle HTTP errors (fetch does NOT reject on 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Upload a file with FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Abort a request with AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // 5s timeout

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("Request timed out");
}

// Fetch with authorization header
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Modules (import / export)

Organize code into reusable, isolated files.

```javascript
// Named exports (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Default export (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Named imports
import { API_URL, formatDate } from "./utils.js";

// Rename on import
import { formatDate as fmt } from "./utils.js";

// Default import
import UserService from "./UserService.js";

// Import everything as namespace
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Dynamic import (code splitting / lazy loading)
const module = await import("./heavy-module.js");
module.doSomething();

// Re-export (barrel file pattern — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining & Nullish Coalescing

Safely navigate nested objects and handle null/undefined without verbose checks.

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
user.address?.zipCode;   // undefined (no error)
user.social?.twitter;    // undefined (no error)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (no error)

// Array access
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — only null/undefined trigger the fallback
const port = config.port ?? 3000;        // 3000 if port is null/undefined
const debug = config.debug ?? false;     // false if debug is null/undefined

// Compare with || (logical OR) — 0, "", false trigger the fallback
0 || 42;       // 42  (0 is falsy)
0 ?? 42;       // 0   (0 is not null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Nullish coalescing assignment (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Modern Object Tricks

```javascript
// Shorthand properties
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Computed property names
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Method shorthand
const api = {
  getUsers() { /* ... */ },      // instead of getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — reverse of Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Structured clone (deep copy, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // still 42
```

---

## Quick Reference Table

| Feature | Syntax | Use Case |
|---|---|---|
| `const` / `let` | `const x = 1` | Block-scoped declarations |
| Arrow function | `(a, b) => a + b` | Callbacks, React components |
| Template literal | `` `Hello ${name}` `` | String interpolation |
| Destructuring | `const { a, b } = obj` | Extract values from objects/arrays |
| Spread | `{ ...obj, key: val }` | Clone, merge, immutable updates |
| Rest | `(...args) => {}` | Collect arguments |
| `map` | `arr.map(fn)` | Transform every element |
| `filter` | `arr.filter(fn)` | Keep elements matching condition |
| `reduce` | `arr.reduce(fn, init)` | Accumulate into single value |
| `?.` | `obj?.prop` | Safe nested access |
| `??` | `val ?? fallback` | Default for null/undefined only |
| `async/await` | `const x = await fn()` | Readable async code |
| `Promise.all` | `await Promise.all([...])` | Parallel async operations |

---

## End of Transmission

This cheatsheet covers the modern JavaScript every frontend developer needs to know — from ES6 fundamentals to async patterns and the Fetch API. Bookmark it, reference it during frontend interviews, and build faster with clean, declarative JS syntax. The web runs on JavaScript. Now you run JavaScript.
