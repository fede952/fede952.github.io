---
title: "궁극의 React Hooks 치트시트 (2026)"
description: "모든 React Hook을 복사-붙여넣기 가능한 코드 스니펫으로 설명합니다. useState, useEffect, useContext, useRef, useMemo, 커스텀 훅, 프로덕션 React 애플리케이션에서 사용되는 성능 패턴을 마스터하세요."
date: 2026-02-11
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks 치트시트", "usestate useeffect", "react hooks 튜토리얼", "웹 개발 배우기", "프론트엔드 면접", "커스텀 hooks react", "react 성능", "usememo usecallback", "react context 튜토리얼", "useref react", "react 패턴 2026", "react hooks 예제"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "궁극의 React Hooks 치트시트 (2026)",
    "description": "useState, useEffect, useContext, 커스텀 훅, 성능 최적화를 위한 복사-붙여넣기 스니펫이 포함된 완벽한 React Hooks 레퍼런스.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 컴포넌트 온라인

React Hooks는 상태와 사이드 이펙트를 관리하는 표준 방법으로 클래스 컴포넌트를 대체했습니다. React 16.8 이후로 모든 프로덕션 애플리케이션은 훅으로 구축되며, 면접관은 여러분이 이를 완벽하게 알고 있기를 기대합니다. 이 치트시트는 모든 훅의 복사-붙여넣기 가능한 스니펫과 프론트엔드 면접 및 일상 개발에서 만나게 될 실전 패턴을 제공합니다. 이론 강의는 없습니다. 어떤 컴포넌트에든 넣을 수 있는 작동하는 코드만 있습니다.

---

## useState — 상태 관리

가장 기본적인 훅. 상태 변수와 세터 함수를 선언합니다.

```jsx
import { useState } from "react";

// Basic state
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

// Functional updater (when new state depends on previous state)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Always use functional form when depending on previous state
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Object state
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Spread previous state, override one field
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// Array state
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

// Lazy initialization (expensive initial value)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — 사이드 이펙트

렌더링 후 코드를 실행합니다. API 호출, 구독, 타이머, DOM 조작을 처리합니다.

```jsx
import { useState, useEffect } from "react";

// Run on EVERY render (no dependency array)
useEffect(() => {
  console.log("Rendered");
});

// Run ONCE on mount (empty dependency array)
useEffect(() => {
  console.log("Component mounted");
}, []);

// Run when specific values change
useEffect(() => {
  console.log(`User changed to: ${userId}`);
}, [userId]);

// Cleanup function (unmount or before re-run)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // cleanup
}, []);

// Fetch data on mount
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // prevent state update on unmounted component

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

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Event listener with cleanup
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Debounced search input
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

## useContext — Props 없는 전역 상태

prop 드릴링 없이 컴포넌트 트리 전체에서 값을 공유합니다.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Create the context
const ThemeContext = createContext();

// 2. Create a provider component
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Consume with useContext (any child component)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Current theme: {theme}
    </button>
  );
}

// 4. Wrap your app
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### 인증 Context 패턴 (프로덕션)

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

// Custom hook for cleaner usage
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be inside AuthProvider");
  return context;
}

// Usage in any component
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — 변경 가능한 참조

리렌더링을 발생시키지 않으면서 렌더링 간에 유지되는 변경 가능한 값을 보유합니다.

```jsx
import { useRef, useEffect } from "react";

// Access a DOM element
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="I auto-focus on mount" />;
}

// Store a mutable value (does NOT trigger re-render)
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

// Track previous value
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Scroll to element
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Target</div>;
}
```

---

## useMemo & useCallback — 성능

비용이 큰 계산을 메모이제이션하고 함수 참조를 안정화합니다.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — cache a computed value
function FilteredList({ items, query }) {
  // Only recomputes when items or query change
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

// useMemo — expensive calculation
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Total: ${stats.total} ({stats.count} transactions)</p>;
}

// useCallback — stabilize a function reference
function Parent() {
  const [count, setCount] = useState(0);

  // Without useCallback, handleClick is recreated every render
  // causing Child to re-render even if it uses React.memo
  const handleClick = useCallback((id) => {
    console.log(`Clicked item ${id}`);
  }, []); // stable reference

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child rendered");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### 사용 시점 (그리고 사용하지 말아야 할 때)

```jsx
// ✅ Use useMemo when:
// - Filtering/sorting large lists
// - Complex calculations (aggregations, formatting)
// - Creating objects passed to memoized children

// ✅ Use useCallback when:
// - Passing callbacks to React.memo components
// - Passing callbacks as useEffect dependencies

// ❌ Do NOT use for:
// - Simple expressions (a + b, string concatenation)
// - Functions that are not passed to children
// - Premature optimization — measure first
```

---

## useReducer — 복잡한 상태 로직

useState와 비슷하지만 액션에 의존하는 상태 전환을 위한 것. Redux를 알고 있다면 익숙할 것입니다.

```jsx
import { useReducer } from "react";

// Define reducer function
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
      throw new Error(`Unknown action: ${action.type}`);
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
        <button type="submit">Add</button>
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
        Clear Completed
      </button>
    </div>
  );
}
```

---

## 커스텀 Hooks — 재사용 가능한 로직

컴포넌트 로직을 재사용 가능한 함수로 추출합니다. React에서 가장 강력한 패턴.

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

// Usage
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

// Usage
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;
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

// Usage
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

// Usage
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

// Usage
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Hook 규칙

React 훅은 두 가지 엄격한 규칙을 따릅니다. 이를 어기면 디버깅이 거의 불가능한 버그가 발생합니다.

```jsx
// ✅ Rule 1: Only call hooks at the TOP LEVEL
// Never inside conditions, loops, or nested functions
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Always called
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Conditional hook
  // }
  const [extra, setExtra] = useState("");     // ✅ Always called
  // Then conditionally render instead

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Rule 2: Only call hooks from React functions
// React components or custom hooks — never from plain functions
function useMyHook() {        // ✅ Custom hook (starts with "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Not a hook, not a component
//   const [val, setVal] = useState(0);
// }
```

---

## 빠른 참조 표

| Hook | 목적 | 리렌더링 발생? |
|---|---|---|
| `useState` | 컴포넌트 상태 관리 | 예 |
| `useEffect` | 사이드 이펙트 (fetch, 타이머, DOM) | 아니오 (렌더 후 실행) |
| `useContext` | prop 드릴링 없이 context 읽기 | 예 (context 변경 시) |
| `useRef` | 변경 가능한 ref / DOM 접근 | 아니오 |
| `useMemo` | 비용 큰 계산 캐시 | 아니오 (캐시된 값 반환) |
| `useCallback` | 함수 참조 안정화 | 아니오 (캐시된 함수 반환) |
| `useReducer` | 액션 기반 복잡한 상태 | 예 |

---

## 전송 완료

이 치트시트는 프로덕션 코드베이스와 프론트엔드 면접에서 만나게 될 모든 React Hook 패턴을 다룹니다. 기본적인 상태 관리부터 재사용 가능한 로직을 캡슐화하는 커스텀 훅까지 — 이것들이 모던 React의 기본 구성 요소입니다. 북마크하고, 패턴을 복사하고, 구축하세요.
