---
title: "Шпаргалка по современному JavaScript: ES6+, Async/Await и методы массивов"
description: "Полный справочник по ES6+ для фронтенд-разработчиков. Освойте стрелочные функции, деструктуризацию, spread-оператор, промисы, async/await, map/filter/reduce и Fetch API с готовыми примерами для копирования."
date: 2026-02-10
tags: ["javascript", "cheatsheet", "frontend", "es6", "web-dev"]
keywords: ["шпаргалка javascript", "шпаргалка es6", "изучить веб-разработку", "синтаксис js", "методы массивов javascript", "руководство async await", "собеседование фронтенд", "javascript react разработчик", "map filter reduce", "деструктуризация javascript", "spread оператор", "примеры fetch api", "цепочка промисов", "стрелочные функции", "шаблонные литералы"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Шпаргалка по современному JavaScript: ES6+, Async/Await и методы массивов",
    "description": "Полный справочник по ES6+, охватывающий стрелочные функции, деструктуризацию, промисы, async/await и методы массивов для фронтенд-разработчиков.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация среды выполнения

JavaScript эволюционировал из простого скриптового языка в основу современной веб-разработки. ES6 и последующие версии привнесли возможности, которые делают код чище, предсказуемее и проще в поддержке — стрелочные функции, деструктуризацию, модули, async/await и мощные методы массивов, заменяющие громоздкие циклы декларативными трансформациями. Будь то создание компонентов React, обработка API-запросов или подготовка к собеседованию по фронтенду — эта шпаргалка охватывает синтаксис JS, который вы будете использовать каждый день. Каждый фрагмент готов к продакшену. Копируйте, вставляйте, деплойте.

---

## Объявления переменных

Забудьте о `var`. Современный JavaScript использует `let` и `const` для предсказуемой области видимости.

```javascript
// const для значений, которые не будут переназначены
const API_URL = "https://api.example.com";
const MAX_RETRIES = 3;

// let для значений, которые будут меняться
let currentUser = null;
let retryCount = 0;

// const НЕ означает неизменяемость — объекты и массивы всё ещё можно мутировать
const config = { theme: "dark" };
config.theme = "light"; // ✅ Это работает
// config = {};          // ❌ TypeError: Assignment to constant variable

// Блочная область видимости — let и const ограничены своим блоком
if (true) {
  let blockScoped = "only here";
  var functionScoped = "leaks out";
}
// console.log(blockScoped);    // ❌ ReferenceError
// console.log(functionScoped); // ✅ "leaks out"
```

---

## Стрелочные функции

Более короткий синтаксис, лексическое связывание `this` и основной инструмент компонентов React.

```javascript
// Традиционная функция
function add(a, b) {
  return a + b;
}

// Стрелочная функция (явный return)
const add = (a, b) => {
  return a + b;
};

// Стрелочная функция (неявный return — одно выражение)
const add = (a, b) => a + b;

// Один параметр — скобки необязательны
const double = n => n * 2;

// Нет параметров — пустые скобки обязательны
const getTimestamp = () => Date.now();

// Возврат объектного литерала — обернуть в скобки
const createUser = (name, role) => ({ name, role, active: true });

// Стрелочные функции НЕ имеют своего `this`
const counter = {
  count: 0,
  // ❌ Стрелочная функция наследует `this` из внешней области (не от объекта)
  incrementBad: () => { this.count++; },
  // ✅ Обычная функция привязывает `this` к объекту
  increment() { this.count++; },
};
```

---

## Шаблонные литералы

Интерполяция строк, многострочные строки и тегированные шаблоны.

```javascript
const name = "Federico";
const role = "developer";

// Интерполяция строк
const greeting = `Hello, ${name}! You are a ${role}.`;

// Выражения внутри шаблонов
const price = 29.99;
const tax = 0.21;
const total = `Total: $${(price * (1 + tax)).toFixed(2)}`;

// Многострочные строки
const html = `
  <div class="card">
    <h2>${name}</h2>
    <p>Role: ${role}</p>
  </div>
`;

// Тегированные шаблоны (используются в библиотеках вроде styled-components)
function highlight(strings, ...values) {
  return strings.reduce((result, str, i) => {
    return `${result}${str}<mark>${values[i] || ""}</mark>`;
  }, "");
}
const message = highlight`Welcome ${name}, your role is ${role}`;
```

---

## Деструктуризация

Извлекайте значения из объектов и массивов в одну строку. Необходимый синтаксис JS для пропсов React.

```javascript
// Деструктуризация объектов
const user = { name: "Ada", age: 36, role: "engineer" };
const { name, age, role } = user;

// Переименование переменных
const { name: userName, role: userRole } = user;

// Значения по умолчанию
const { name, country = "Unknown" } = user;

// Вложенная деструктуризация
const response = { data: { users: [{ id: 1, name: "Ada" }] } };
const { data: { users: [firstUser] } } = response;

// Деструктуризация массивов
const rgb = [255, 128, 0];
const [red, green, blue] = rgb;

// Пропуск элементов
const [first, , third] = [1, 2, 3];

// Обмен переменных без temp
let a = 1, b = 2;
[a, b] = [b, a]; // a=2, b=1

// Деструктуризация параметров функции (паттерн React)
function UserCard({ name, role, avatar = "/default.png" }) {
  return `${name} (${role})`;
}

// Rest в деструктуризации
const { name, ...rest } = { name: "Ada", age: 36, role: "engineer" };
// rest = { age: 36, role: "engineer" }
```

---

## Операторы Spread и Rest

Оператор `...` — spread для расширения, rest для сбора.

```javascript
// Spread: расширить массив
const nums = [1, 2, 3];
const more = [...nums, 4, 5]; // [1, 2, 3, 4, 5]

// Spread: клонировать массив (поверхностная копия)
const clone = [...nums];

// Spread: объединить объекты (поздние ключи перезаписывают)
const defaults = { theme: "dark", lang: "en" };
const userPrefs = { lang: "it" };
const config = { ...defaults, ...userPrefs };
// { theme: "dark", lang: "it" }

// Spread: иммутабельное обновление состояния (паттерн React)
const state = { count: 0, loading: false };
const newState = { ...state, count: state.count + 1 };

// Spread: передать массив как аргументы функции
const scores = [90, 85, 92, 88];
const highest = Math.max(...scores); // 92

// Rest: собрать оставшиеся аргументы
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0);
}
sum(1, 2, 3, 4); // 10

// Rest: собрать оставшиеся элементы массива
const [head, ...tail] = [1, 2, 3, 4];
// head = 1, tail = [2, 3, 4]
```

---

## Методы массивов: map, filter, reduce

Святая троица трансформации массивов. Замените циклы декларативными цепочечными операциями.

### map — Преобразовать каждый элемент

```javascript
const users = [
  { name: "Ada", age: 36 },
  { name: "Bob", age: 25 },
  { name: "Cat", age: 30 },
];

// Преобразовать в новый массив
const names = users.map(user => user.name);
// ["Ada", "Bob", "Cat"]

// Преобразовать с индексом
const numbered = users.map((user, i) => `${i + 1}. ${user.name}`);
// ["1. Ada", "2. Bob", "3. Cat"]

// Извлечь и переформатировать (часто в React)
const options = users.map(({ name, age }) => ({
  label: `${name} (${age})`,
  value: name.toLowerCase(),
}));
```

### filter — Оставить элементы, прошедшие проверку

```javascript
// Фильтрация по условию
const adults = users.filter(user => user.age >= 30);
// [{ name: "Ada", age: 36 }, { name: "Cat", age: 30 }]

// Удалить ложные значения
const mixed = [0, "hello", null, 42, undefined, "world", false];
const clean = mixed.filter(Boolean);
// ["hello", 42, "world"]

// Удалить дубликаты (с помощью Set)
const dupes = [1, 2, 2, 3, 3, 3];
const unique = [...new Set(dupes)]; // [1, 2, 3]

// Цепочка map + filter
const activeEmails = users
  .filter(u => u.age >= 30)
  .map(u => `${u.name.toLowerCase()}@example.com`);
// ["ada@example.com", "cat@example.com"]
```

### reduce — Накопить в одно значение

```javascript
// Суммировать массив
const numbers = [10, 20, 30, 40];
const total = numbers.reduce((acc, n) => acc + n, 0); // 100

// Подсчитать вхождения
const fruits = ["apple", "banana", "apple", "cherry", "banana", "apple"];
const count = fruits.reduce((acc, fruit) => {
  acc[fruit] = (acc[fruit] || 0) + 1;
  return acc;
}, {});
// { apple: 3, banana: 2, cherry: 1 }

// Группировка по свойству
const grouped = users.reduce((acc, user) => {
  const key = user.age >= 30 ? "senior" : "junior";
  acc[key] = acc[key] || [];
  acc[key].push(user);
  return acc;
}, {});

// Сплющить вложенные массивы (или просто используйте .flat())
const nested = [[1, 2], [3, 4], [5]];
const flat = nested.reduce((acc, arr) => [...acc, ...arr], []);
// [1, 2, 3, 4, 5]

// Конвейер: цепочка map + filter + reduce
const totalSeniorAge = users
  .filter(u => u.age >= 30)
  .map(u => u.age)
  .reduce((sum, age) => sum + age, 0); // 66
```

---

## Другие важные методы массивов

```javascript
const items = [1, 2, 3, 4, 5];

// find — первый элемент, который соответствует
items.find(n => n > 3); // 4

// findIndex — индекс первого совпадения
items.findIndex(n => n > 3); // 3

// some — проходит ли ХОТЯ БЫ ОДИН элемент тест?
items.some(n => n > 4); // true

// every — проходят ли ВСЕ элементы тест?
items.every(n => n > 0); // true

// includes — содержит ли массив значение?
items.includes(3); // true

// flat — сплющить вложенные массивы
[[1, 2], [3, [4, 5]]].flat(Infinity); // [1, 2, 3, 4, 5]

// flatMap — map + flatten за один проход
const sentences = ["hello world", "foo bar"];
sentences.flatMap(s => s.split(" "));
// ["hello", "world", "foo", "bar"]

// at — отрицательная индексация
items.at(-1); // 5 (последний элемент)
items.at(-2); // 4

// Array.from — создать массивы из итерируемых объектов
Array.from({ length: 5 }, (_, i) => i + 1); // [1, 2, 3, 4, 5]
Array.from("hello"); // ["h", "e", "l", "l", "o"]

// Object.entries + map (итерировать объекты как массивы)
const scores = { math: 90, science: 85, english: 92 };
Object.entries(scores).map(([subject, score]) => `${subject}: ${score}`);
// ["math: 90", "science: 85", "english: 92"]
```

---

## Промисы

Промисы представляют значение, которое будет доступно в будущем. Основа асинхронного JavaScript.

```javascript
// Создать промис
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

// Использовать с .then/.catch
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error(err))
  .finally(() => console.log("Done"));

// Promise.all — выполнить параллельно, провал если ЛЮБОЙ отклонён
const [users, posts, comments] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json()),
  fetch("/api/comments").then(r => r.json()),
]);

// Promise.allSettled — выполнить параллельно, никогда не отклоняется
const results = await Promise.allSettled([
  fetch("/api/fast"),
  fetch("/api/slow"),
  fetch("/api/broken"),
]);
// results[2].status === "rejected"

// Promise.race — побеждает первый завершившийся
const fastest = await Promise.race([
  fetch("/api/server-a"),
  fetch("/api/server-b"),
]);
```

---

## Async / Await

Синтаксический сахар поверх промисов. Пишите асинхронный код, который читается как синхронный.

```javascript
// Базовая async-функция
async function getUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const user = await response.json();
  return user;
}

// Версия со стрелочной функцией
const getUser = async (id) => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

// Обработка ошибок с try/catch
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      console.warn(`Попытка ${i + 1} не удалась, повтор...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

// Последовательное vs параллельное выполнение
// ❌ Последовательное — каждый await ждёт предыдущий (медленно)
const user = await getUser(1);
const posts = await getPosts(user.id);

// ✅ Параллельное — запускает оба сразу (быстро)
const [user, posts] = await Promise.all([
  getUser(1),
  getPosts(1),
]);

// Асинхронная итерация
async function processItems(items) {
  for (const item of items) {
    await processItem(item); // последовательно, по одному
  }
}

// Top-level await (ES2022, поддерживается в модулях)
const config = await fetch("/config.json").then(r => r.json());
```

---

## Fetch API

Современная замена XMLHttpRequest. Нативно в каждом браузере и Node 18+.

```javascript
// GET-запрос
const response = await fetch("https://api.example.com/users");
const users = await response.json();

// POST-запрос с JSON-телом
const newUser = await fetch("https://api.example.com/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "Ada", role: "engineer" }),
});

// PUT-запрос
await fetch(`/api/users/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(updatedUser),
});

// DELETE-запрос
await fetch(`/api/users/${id}`, { method: "DELETE" });

// Обработка HTTP-ошибок (fetch НЕ отклоняется при 4xx/5xx)
async function safeFetch(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Загрузка файла с FormData
const form = new FormData();
form.append("avatar", fileInput.files[0]);
await fetch("/api/upload", { method: "POST", body: form });

// Отмена запроса с AbortController
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // таймаут 5с

try {
  const data = await fetch("/api/slow", { signal: controller.signal });
} catch (err) {
  if (err.name === "AbortError") console.log("Запрос отменён по таймауту");
}

// Fetch с заголовком авторизации
const data = await fetch("/api/protected", {
  headers: { Authorization: `Bearer ${token}` },
}).then(r => r.json());
```

---

## Модули (import / export)

Организуйте код в переиспользуемые изолированные файлы.

```javascript
// Именованные экспорты (utils.js)
export const API_URL = "https://api.example.com";
export function formatDate(date) {
  return new Intl.DateTimeFormat("en").format(date);
}
export const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// Экспорт по умолчанию (UserService.js)
export default class UserService {
  async getAll() { /* ... */ }
  async getById(id) { /* ... */ }
}

// Именованные импорты
import { API_URL, formatDate } from "./utils.js";

// Переименование при импорте
import { formatDate as fmt } from "./utils.js";

// Импорт по умолчанию
import UserService from "./UserService.js";

// Импортировать всё как пространство имён
import * as utils from "./utils.js";
utils.formatDate(new Date());

// Динамический импорт (разделение кода / ленивая загрузка)
const module = await import("./heavy-module.js");
module.doSomething();

// Реэкспорт (паттерн barrel file — index.js)
export { formatDate, capitalize } from "./utils.js";
export { default as UserService } from "./UserService.js";
```

---

## Optional Chaining и Nullish Coalescing

Безопасная навигация по вложенным объектам и обработка null/undefined без громоздких проверок.

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
user.address?.zipCode;   // undefined (без ошибки)
user.social?.twitter;    // undefined (без ошибки)
user.getFullName?.();    // "Ada"
user.nonExistent?.();    // undefined (без ошибки)

// Доступ к массивам
const users = [{ name: "Ada" }];
users?.[0]?.name;  // "Ada"
users?.[5]?.name;  // undefined

// Nullish coalescing (??) — только null/undefined запускают fallback
const port = config.port ?? 3000;        // 3000 если port равен null/undefined
const debug = config.debug ?? false;     // false если debug равен null/undefined

// Сравнение с || (логическое ИЛИ) — 0, "", false запускают fallback
0 || 42;       // 42  (0 — falsy)
0 ?? 42;       // 0   (0 — не null/undefined)
"" || "default"; // "default"
"" ?? "default"; // ""

// Присваивание nullish coalescing (??=)
let username;
username ??= "Anonymous"; // "Anonymous"
```

---

## Современные приёмы работы с объектами

```javascript
// Сокращённые свойства
const name = "Ada";
const age = 36;
const user = { name, age }; // { name: "Ada", age: 36 }

// Вычисляемые имена свойств
const field = "email";
const obj = { [field]: "ada@example.com" }; // { email: "ada@example.com" }

// Сокращённые методы
const api = {
  getUsers() { /* ... */ },      // вместо getUsers: function() {}
  async fetchData() { /* ... */ },
};

// Object.keys / values / entries
const config = { host: "localhost", port: 3000, debug: true };
Object.keys(config);    // ["host", "port", "debug"]
Object.values(config);  // ["localhost", 3000, true]
Object.entries(config);
// [["host", "localhost"], ["port", 3000], ["debug", true]]

// Object.fromEntries — обратная операция к Object.entries
const params = new URLSearchParams("name=Ada&role=dev");
const obj = Object.fromEntries(params);
// { name: "Ada", role: "dev" }

// Структурированное клонирование (глубокая копия, ES2022)
const original = { nested: { value: 42 } };
const deep = structuredClone(original);
deep.nested.value = 99;
original.nested.value; // по-прежнему 42
```

---

## Таблица быстрого справочника

| Возможность | Синтаксис | Применение |
|---|---|---|
| `const` / `let` | `const x = 1` | Объявления с блочной областью видимости |
| Стрелочная функция | `(a, b) => a + b` | Колбэки, компоненты React |
| Шаблонный литерал | `` `Hello ${name}` `` | Интерполяция строк |
| Деструктуризация | `const { a, b } = obj` | Извлечение значений из объектов/массивов |
| Spread | `{ ...obj, key: val }` | Клонирование, объединение, иммутабельные обновления |
| Rest | `(...args) => {}` | Сбор аргументов |
| `map` | `arr.map(fn)` | Преобразование каждого элемента |
| `filter` | `arr.filter(fn)` | Сохранение элементов по условию |
| `reduce` | `arr.reduce(fn, init)` | Накопление в одно значение |
| `?.` | `obj?.prop` | Безопасный доступ к вложенным свойствам |
| `??` | `val ?? fallback` | Значение по умолчанию только для null/undefined |
| `async/await` | `const x = await fn()` | Читаемый асинхронный код |
| `Promise.all` | `await Promise.all([...])` | Параллельные асинхронные операции |

---

## Конец передачи

Эта шпаргалка охватывает современный JavaScript, который должен знать каждый фронтенд-разработчик — от основ ES6 до асинхронных паттернов и Fetch API. Сохраните в закладки, используйте как справочник на собеседованиях и создавайте быстрее с чистым декларативным синтаксисом JS. Веб работает на JavaScript. Теперь вы управляете JavaScript.
