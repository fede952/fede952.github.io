---
title: "Полное Руководство по React Hooks (2026)"
description: "Каждый React Hook объяснён с готовыми фрагментами кода. Освойте useState, useEffect, useContext, useRef, useMemo, пользовательские хуки и паттерны производительности, используемые в продакшн-приложениях React."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks руководство", "usestate useeffect", "react hooks туториал", "изучение веб-разработки", "собеседование фронтенд", "custom hooks react", "react производительность", "usememo usecallback", "react context туториал", "useref react", "react паттерны 2026", "react hooks примеры"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Полное Руководство по React Hooks (2026)",
    "description": "Полный справочник по React Hooks с готовыми сниппетами для useState, useEffect, useContext, пользовательских хуков и оптимизации производительности.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Компонент Онлайн

React Hooks заменили классовые компоненты как стандартный способ управления состоянием и побочными эффектами. С версии React 16.8 каждое продакшн-приложение строится на хуках — и интервьюеры ожидают, что вы знаете их в совершенстве. Это руководство предоставляет готовые фрагменты кода для каждого хука и реальные паттерны, с которыми вы столкнётесь на собеседованиях по фронтенду и в повседневной разработке. Никаких теоретических лекций. Только рабочий код, который можно вставить в любой компонент.

---

## useState — Управление Состоянием

Самый базовый хук. Объявляет переменную состояния и функцию-сеттер.

```jsx
import { useState } from "react";

// Базовое состояние
function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(count + 1)}>Increment</button>
      <button onClick={() => setCount(0)}>Reset</button>
    </div>
  );
}

// Функциональный апдейтер (когда новое состояние зависит от предыдущего)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Всегда используйте функциональную форму при зависимости от предыдущего состояния
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Состояние-объект
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Распространяем предыдущее состояние, перезаписываем одно поле
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// Состояние-массив
function TodoList() {
  const [todos, setTodos] = useState([]);

  const addTodo = (text) => {
    setTodos(prev => [...prev, { id: Date.now(), text, done: false }]);
  };

  const removeTodo = (id) => {
    setTodos(prev => prev.filter(t => t.id !== id));
  };

  const toggleTodo = (id) => {
    setTodos(prev =>
      prev.map(t => (t.id === id ? { ...t, done: !t.done } : t))
    );
  };

  return (
    <ul>
      {todos.map(t => (
        <li key={t.id} onClick={() => toggleTodo(t.id)}>
          {t.done ? "✅" : "⬜"} {t.text}
        </li>
      ))}
    </ul>
  );
}

// Ленивая инициализация (дорогое начальное значение)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Побочные Эффекты

Выполняет код после рендера. Обрабатывает API-вызовы, подписки, таймеры и манипуляцию DOM.

```jsx
import { useState, useEffect } from "react";

// Выполнять при КАЖДОМ рендере (нет массива зависимостей)
useEffect(() => {
  console.log("Rendered");
});

// Выполнить ОДИН РАЗ при монтировании (пустой массив зависимостей)
useEffect(() => {
  console.log("Компонент смонтирован");
}, []);

// Выполнять при изменении конкретных значений
useEffect(() => {
  console.log(`Пользователь изменён на: ${userId}`);
}, [userId]);

// Функция очистки (размонтирование или перед повторным запуском)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // очистка
}, []);

// Загрузка данных при монтировании
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // предотвращаем обновление состояния размонтированного компонента

    async function fetchUser() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/users/${userId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!cancelled) setUser(data);
      } catch (err) {
        if (!cancelled) setError(err.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchUser();
    return () => { cancelled = true; };
  }, [userId]);

  if (loading) return <p>Загрузка...</p>;
  if (error) return <p>Ошибка: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Обработчик событий с очисткой
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Поле поиска с debounce
function Search() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);

  useEffect(() => {
    if (!query) return setResults([]);

    const timeout = setTimeout(async () => {
      const res = await fetch(`/api/search?q=${query}`);
      setResults(await res.json());
    }, 300);

    return () => clearTimeout(timeout);
  }, [query]);

  return <input value={query} onChange={e => setQuery(e.target.value)} />;
}
```

---

## useContext — Глобальное Состояние Без Props

Передавайте значения по дереву компонентов без prop drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Создаём контекст
const ThemeContext = createContext();

// 2. Создаём компонент-провайдер
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Потребляем через useContext (любой дочерний компонент)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Текущая тема: {theme}
    </button>
  );
}

// 4. Оборачиваем приложение
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Паттерн Auth Context (Продакшн)

```jsx
const AuthContext = createContext(null);

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/me")
      .then(r => r.ok ? r.json() : null)
      .then(setUser)
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    setUser(data.user);
  };

  const logout = () => {
    fetch("/api/logout", { method: "POST" });
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// Пользовательский хук для более чистого использования
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth должен быть внутри AuthProvider");
  return context;
}

// Использование в любом компоненте
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Изменяемые Ссылки

Хранит изменяемое значение, которое сохраняется между рендерами, не вызывая повторных рендеров.

```jsx
import { useRef, useEffect } from "react";

// Доступ к DOM-элементу
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Автофокус при монтировании" />;
}

// Хранение изменяемого значения (НЕ вызывает повторный рендер)
function StopWatch() {
  const [time, setTime] = useState(0);
  const intervalRef = useRef(null);

  const start = () => {
    intervalRef.current = setInterval(() => {
      setTime(prev => prev + 1);
    }, 1000);
  };

  const stop = () => clearInterval(intervalRef.current);

  return (
    <div>
      <p>{time}s</p>
      <button onClick={start}>Start</button>
      <button onClick={stop}>Stop</button>
    </div>
  );
}

// Отслеживание предыдущего значения
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Прокрутка к элементу
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Цель</div>;
}
```

---

## useMemo & useCallback — Производительность

Мемоизируйте дорогие вычисления и стабилизируйте ссылки на функции.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — кэширование вычисленного значения
function FilteredList({ items, query }) {
  // Пересчитывает только при изменении items или query
  const filtered = useMemo(() => {
    return items.filter(item =>
      item.name.toLowerCase().includes(query.toLowerCase())
    );
  }, [items, query]);

  return (
    <ul>
      {filtered.map(item => <li key={item.id}>{item.name}</li>)}
    </ul>
  );
}

// useMemo — дорогое вычисление
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Итого: ${stats.total} ({stats.count} транзакций)</p>;
}

// useCallback — стабилизация ссылки на функцию
function Parent() {
  const [count, setCount] = useState(0);

  // Без useCallback handleClick пересоздаётся при каждом рендере,
  // вызывая повторный рендер Child, даже если он использует React.memo
  const handleClick = useCallback((id) => {
    console.log(`Нажат элемент ${id}`);
  }, []); // стабильная ссылка

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child отрендерен");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Когда использовать (и когда НЕТ)

```jsx
// ✅ Используйте useMemo когда:
// - Фильтрация/сортировка больших списков
// - Сложные вычисления (агрегации, форматирование)
// - Создание объектов, передаваемых мемоизированным дочерним компонентам

// ✅ Используйте useCallback когда:
// - Передаёте колбэки в компоненты React.memo
// - Передаёте колбэки как зависимости useEffect

// ❌ НЕ используйте для:
// - Простых выражений (a + b, конкатенация строк)
// - Функций, которые не передаются дочерним компонентам
// - Преждевременной оптимизации — сначала измерьте
```

---

## useReducer — Сложная Логика Состояния

Как useState, но для переходов состояния, зависящих от действий. Знакомо, если вы знаете Redux.

```jsx
import { useReducer } from "react";

// Определяем функцию-редюсер
function todoReducer(state, action) {
  switch (action.type) {
    case "ADD":
      return [...state, { id: Date.now(), text: action.text, done: false }];
    case "TOGGLE":
      return state.map(t =>
        t.id === action.id ? { ...t, done: !t.done } : t
      );
    case "DELETE":
      return state.filter(t => t.id !== action.id);
    case "CLEAR_DONE":
      return state.filter(t => !t.done);
    default:
      throw new Error(`Неизвестное действие: ${action.type}`);
  }
}

function TodoApp() {
  const [todos, dispatch] = useReducer(todoReducer, []);
  const [text, setText] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    dispatch({ type: "ADD", text });
    setText("");
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input value={text} onChange={e => setText(e.target.value)} />
        <button type="submit">Добавить</button>
      </form>
      <ul>
        {todos.map(t => (
          <li key={t.id}>
            <span
              onClick={() => dispatch({ type: "TOGGLE", id: t.id })}
              style={{ textDecoration: t.done ? "line-through" : "none" }}
            >
              {t.text}
            </span>
            <button onClick={() => dispatch({ type: "DELETE", id: t.id })}>
              ×
            </button>
          </li>
        ))}
      </ul>
      <button onClick={() => dispatch({ type: "CLEAR_DONE" })}>
        Очистить Выполненные
      </button>
    </div>
  );
}
```

---

## Пользовательские Хуки — Переиспользуемая Логика

Извлекайте логику компонентов в переиспользуемые функции. Самый мощный паттерн в React.

### useLocalStorage

```jsx
function useLocalStorage(key, initialValue) {
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored ? JSON.parse(stored) : initialValue;
    } catch {
      return initialValue;
    }
  });

  useEffect(() => {
    localStorage.setItem(key, JSON.stringify(value));
  }, [key, value]);

  return [value, setValue];
}

// Использование
const [theme, setTheme] = useLocalStorage("theme", "dark");
```

### useFetch

```jsx
function useFetch(url) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    fetch(url)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => { if (!cancelled) setData(data); })
      .catch(err => { if (!cancelled) setError(err.message); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [url]);

  return { data, loading, error };
}

// Использование
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Загрузка...</p>;
  if (error) return <p>Ошибка: {error}</p>;
  return <ul>{users.map(u => <li key={u.id}>{u.name}</li>)}</ul>;
}
```

### useDebounce

```jsx
function useDebounce(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debounced;
}

// Использование
function Search() {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounce(query, 500);

  useEffect(() => {
    if (debouncedQuery) {
      fetch(`/api/search?q=${debouncedQuery}`)
        .then(r => r.json())
        .then(setResults);
    }
  }, [debouncedQuery]);

  return <input value={query} onChange={e => setQuery(e.target.value)} />;
}
```

### useToggle

```jsx
function useToggle(initial = false) {
  const [value, setValue] = useState(initial);
  const toggle = useCallback(() => setValue(v => !v), []);
  return [value, toggle];
}

// Использование
const [isOpen, toggleOpen] = useToggle();
const [isDark, toggleTheme] = useToggle(true);
```

### useWindowSize

```jsx
function useWindowSize() {
  const [size, setSize] = useState({
    width: window.innerWidth,
    height: window.innerHeight,
  });

  useEffect(() => {
    const handleResize = () => setSize({
      width: window.innerWidth,
      height: window.innerHeight,
    });
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  return size;
}

// Использование
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Правила Хуков

React хуки следуют двум строгим правилам. Нарушьте их — и получите баги, которые практически невозможно отладить.

```jsx
// ✅ Правило 1: Вызывайте хуки только на ВЕРХНЕМ УРОВНЕ
// Никогда внутри условий, циклов или вложенных функций
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Всегда вызывается
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Условный хук
  // }
  const [extra, setExtra] = useState("");     // ✅ Всегда вызывается
  // Затем условно рендерим вместо этого

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Правило 2: Вызывайте хуки только из React-функций
// React-компоненты или пользовательские хуки — никогда из обычных функций
function useMyHook() {        // ✅ Пользовательский хук (начинается с "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Не хук, не компонент
//   const [val, setVal] = useState(0);
// }
```

---

## Таблица Быстрого Справочника

| Хук | Назначение | Вызывает ре-рендер? |
|---|---|---|
| `useState` | Управление состоянием компонента | Да |
| `useEffect` | Побочные эффекты (fetch, таймеры, DOM) | Нет (выполняется после рендера) |
| `useContext` | Чтение контекста без prop drilling | Да (при изменении контекста) |
| `useRef` | Изменяемая ссылка / доступ к DOM | Нет |
| `useMemo` | Кэширование дорогих вычислений | Нет (возвращает кэшированное значение) |
| `useCallback` | Стабилизация ссылок на функции | Нет (возвращает кэшированную функцию) |
| `useReducer` | Сложное состояние с действиями | Да |

---

## Конец Передачи

Это руководство охватывает каждый паттерн React Hooks, с которым вы столкнётесь в продакшн-кодовых базах и на собеседованиях по фронтенду. От базового управления состоянием до пользовательских хуков, инкапсулирующих переиспользуемую логику — это строительные блоки современного React. Добавьте в закладки, копируйте паттерны и создавайте.
