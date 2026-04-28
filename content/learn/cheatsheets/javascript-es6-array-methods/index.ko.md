---
title: "모던 JavaScript 치트시트: ES6+, Async/Await & 배열 메서드"
description: "프론트엔드 개발자를 위한 완벽한 ES6+ 레퍼런스. 화살표 함수, 구조 분해 할당, 스프레드 연산자, Promise, async/await, map/filter/reduce, Fetch API를 복사-붙여넣기 가능한 예제로 마스터하세요."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["javascript 치트시트", "es6 치트시트", "웹 개발 배우기", "js 문법", "javascript 배열 메서드", "async await 튜토리얼", "프론트엔드 면접", "react 개발자 javascript", "map filter reduce", "구조 분해 할당 javascript", "스프레드 연산자", "fetch api 예제", "promise 체이닝", "화살표 함수", "템플릿 리터럴"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "모던 JavaScript 치트시트: ES6+, Async/Await & 배열 메서드",
    "description": "화살표 함수, 구조 분해 할당, Promise, async/await, 배열 메서드를 다루는 프론트엔드 개발자를 위한 완벽한 ES6+ 레퍼런스.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 런타임 초기화

JavaScript는 단순한 스크립팅 언어에서 모던 웹 개발의 핵심으로 발전했습니다. ES6 이후로 코드를 더 깔끔하고 예측 가능하며 유지보수하기 쉽게 만드는 기능들이 도입되었습니다 — 화살표 함수, 구조 분해 할당, 모듈, async/await, 그리고 장황한 루프를 선언적 변환으로 대체하는 강력한 배열 메서드입니다. React 컴포넌트를 구축하든, API 호출을 처리하든, 프론트엔드 면접을 준비하든, 이 치트시트는 매일 사용하게 될 JS 문법을 다룹니다. 모든 스니펫은 프로덕션에 바로 사용할 수 있습니다. 복사, 붙여넣기, 배포.

---

## 변수 선언

`var`는 잊으세요. 모던 JavaScript는 예측 가능한 스코핑을 위해 `let`과 `const`를 사용합니다.

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

## 화살표 함수

더 짧은 문법, 렉시컬 `this` 바인딩, React 컴포넌트의 핵심 도구.

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

## 템플릿 리터럴

문자열 보간, 여러 줄 문자열, 태그 템플릿.

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

## 구조 분해 할당

한 줄로 객체와 배열에서 값을 추출합니다. React props에 필수적인 JS 문법.

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

## 스프레드 & 나머지 연산자

`...` 연산자 — 스프레드로 확장, 나머지로 수집.

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

## 배열 메서드: map, filter, reduce

배열 변환의 삼위일체. 루프를 선언적이고 체이닝 가능한 연산으로 대체합니다.

### map — 모든 요소 변환

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

### filter — 테스트를 통과한 요소 유지

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

### reduce — 단일 값으로 누적

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

## 기타 필수 배열 메서드

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

Promise는 미래에 사용 가능해질 값을 나타냅니다. 비동기 JavaScript의 기초입니다.

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

Promise의 문법적 설탕. 동기 코드처럼 읽히는 비동기 코드를 작성합니다.

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

XMLHttpRequest의 현대적 대체. 모든 브라우저와 Node 18+에서 네이티브 지원.

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

## 모듈 (import / export)

코드를 재사용 가능하고 격리된 파일로 구성합니다.

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

## 옵셔널 체이닝과 널 병합 연산자

장황한 검사 없이 중첩된 객체를 안전하게 탐색하고 null/undefined를 처리합니다.

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

## 모던 객체 테크닉

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

## 빠른 참조 표

| 기능 | 문법 | 용도 |
|---|---|---|
| `const` / `let` | `const x = 1` | 블록 스코프 선언 |
| 화살표 함수 | `(a, b) => a + b` | 콜백, React 컴포넌트 |
| 템플릿 리터럴 | `` `Hello ${name}` `` | 문자열 보간 |
| 구조 분해 할당 | `const { a, b } = obj` | 객체/배열에서 값 추출 |
| 스프레드 | `{ ...obj, key: val }` | 복제, 병합, 불변 업데이트 |
| 나머지 | `(...args) => {}` | 인수 수집 |
| `map` | `arr.map(fn)` | 모든 요소 변환 |
| `filter` | `arr.filter(fn)` | 조건에 맞는 요소 유지 |
| `reduce` | `arr.reduce(fn, init)` | 단일 값으로 누적 |
| `?.` | `obj?.prop` | 안전한 중첩 접근 |
| `??` | `val ?? fallback` | null/undefined만 기본값 적용 |
| `async/await` | `const x = await fn()` | 읽기 쉬운 비동기 코드 |
| `Promise.all` | `await Promise.all([...])` | 병렬 비동기 작업 |

---

## 전송 완료

이 치트시트는 모든 프론트엔드 개발자가 알아야 할 모던 JavaScript를 다룹니다 — ES6 기초부터 비동기 패턴과 Fetch API까지. 북마크하고, 프론트엔드 면접에서 참고하고, 깔끔하고 선언적인 JS 문법으로 더 빠르게 개발하세요. 웹은 JavaScript로 작동합니다. 이제 당신이 JavaScript를 다룹니다.
