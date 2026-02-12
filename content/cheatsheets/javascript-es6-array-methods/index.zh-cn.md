---
title: "现代 JavaScript 速查表：ES6+、Async/Await 与数组方法"
description: "面向前端开发者的完整 ES6+ 参考手册。掌握箭头函数、解构赋值、展开运算符、Promise、async/await、map/filter/reduce 以及 Fetch API，附带可直接复制粘贴的示例。"
date: 2026-02-11
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["javascript 速查表", "es6 速查表", "学习前端开发", "js 语法", "javascript 数组方法", "async await 教程", "前端面试", "react 开发者 javascript", "map filter reduce", "解构赋值 javascript", "展开运算符", "fetch api 示例", "promise 链式调用", "箭头函数", "模板字符串"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "现代 JavaScript 速查表：ES6+、Async/Await 与数组方法",
    "description": "涵盖箭头函数、解构赋值、Promise、async/await 和数组方法的完整 ES6+ 前端开发参考手册。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-cn"
  }
---

## 初始化运行时

JavaScript 已从一种简单的脚本语言发展为现代 Web 开发的支柱。ES6 及后续版本引入的特性使代码更简洁、更可预测、更易维护——箭头函数、解构赋值、模块、async/await，以及用声明式转换替代冗长循环的强大数组方法。无论你是在构建 React 组件、处理 API 调用，还是准备前端面试，这份速查表都涵盖了你每天都会使用的 JS 语法。每个代码片段都已生产就绪。复制、粘贴、发布。

---

## 变量声明

忘掉 `var`。现代 JavaScript 使用 `let` 和 `const` 来实现可预测的作用域。

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

## 箭头函数

更简短的语法、词法 `this` 绑定，是 React 组件的核心工具。

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

## 模板字符串

字符串插值、多行字符串和标签模板。

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

## 解构赋值

在一行代码中从对象和数组中提取值。React props 必备的 JS 语法。

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

## 展开与剩余运算符

`...` 运算符——展开用于扩展，剩余用于收集。

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

## 数组方法：map、filter、reduce

数组转换的三大法宝。用声明式、可链式调用的操作替代循环。

### map — 转换每个元素

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

### filter — 保留通过测试的元素

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

### reduce — 累积为单一值

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

## 其他必备数组方法

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

## Promise

Promise 表示一个将来可用的值，是异步 JavaScript 的基础。

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

Promise 的语法糖。以同步代码的方式编写异步代码。

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

XMLHttpRequest 的现代替代品。所有浏览器和 Node 18+ 原生支持。

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

## 模块（import / export）

将代码组织成可复用的独立文件。

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

## 可选链与空值合并

安全地访问嵌套对象，无需冗长的检查即可处理 null/undefined。

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

## 现代对象技巧

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

## 快速参考表

| 特性 | 语法 | 用途 |
|---|---|---|
| `const` / `let` | `const x = 1` | 块级作用域声明 |
| 箭头函数 | `(a, b) => a + b` | 回调函数、React 组件 |
| 模板字符串 | `` `Hello ${name}` `` | 字符串插值 |
| 解构赋值 | `const { a, b } = obj` | 从对象/数组中提取值 |
| 展开运算符 | `{ ...obj, key: val }` | 克隆、合并、不可变更新 |
| 剩余参数 | `(...args) => {}` | 收集参数 |
| `map` | `arr.map(fn)` | 转换每个元素 |
| `filter` | `arr.filter(fn)` | 保留符合条件的元素 |
| `reduce` | `arr.reduce(fn, init)` | 累积为单一值 |
| `?.` | `obj?.prop` | 安全的嵌套访问 |
| `??` | `val ?? fallback` | 仅对 null/undefined 使用默认值 |
| `async/await` | `const x = await fn()` | 可读的异步代码 |
| `Promise.all` | `await Promise.all([...])` | 并行异步操作 |

---

## 传输结束

这份速查表涵盖了每个前端开发者都需要掌握的现代 JavaScript——从 ES6 基础到异步模式和 Fetch API。收藏它，在前端面试中参考它，用简洁、声明式的 JS 语法更快地构建应用。Web 运行在 JavaScript 上，现在你掌控了 JavaScript。
