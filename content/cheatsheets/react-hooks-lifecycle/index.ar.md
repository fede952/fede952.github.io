---
title: "الورقة المرجعية الشاملة لـ React Hooks (2026)"
description: "كل React Hook مشروح مع مقتطفات كود جاهزة للنسخ واللصق. أتقن useState، useEffect، useContext، useRef، useMemo، الهوكات المخصصة وأنماط الأداء المستخدمة في تطبيقات React الإنتاجية."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["ورقة مرجعية react hooks", "usestate useeffect", "شرح react hooks", "تعلم تطوير الويب", "مقابلة الواجهة الأمامية", "هوكات مخصصة react", "أداء react", "usememo usecallback", "شرح react context", "useref react", "أنماط react 2026", "أمثلة react hooks"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "الورقة المرجعية الشاملة لـ React Hooks (2026)",
    "description": "مرجع شامل لـ React Hooks مع مقتطفات جاهزة للنسخ لـ useState، useEffect، useContext، الهوكات المخصصة وتحسين الأداء.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## المكوّن متصل

حلّت React Hooks محل مكونات الكلاس كطريقة معيارية لإدارة الحالة والتأثيرات الجانبية. منذ React 16.8، كل تطبيق إنتاجي يُبنى بالهوكات — ويتوقع المحاورون أن تعرفها تماماً. تمنحك هذه الورقة المرجعية مقتطفات جاهزة للنسخ لكل هوك والأنماط الواقعية التي ستواجهها في مقابلات الواجهة الأمامية والتطوير اليومي. لا محاضرات نظرية. فقط كود يعمل يمكنك وضعه في أي مكوّن.

---

## useState — إدارة الحالة

الهوك الأساسي. أعلن عن متغير حالة ودالة ضبط.

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

## useEffect — التأثيرات الجانبية

تشغيل الكود بعد العرض. يتعامل مع استدعاءات API، الاشتراكات، المؤقتات ومعالجة DOM.

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
    let cancelled = false;

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

## useContext — حالة عامة بدون Props

مشاركة القيم عبر شجرة المكونات بدون تمرير الخصائص.

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

### نمط سياق المصادقة (إنتاج)

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

## useRef — المراجع القابلة للتغيير

الاحتفاظ بقيمة قابلة للتغيير تستمر عبر العروض بدون التسبب في إعادة العرض.

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

## useMemo و useCallback — الأداء

تخزين الحسابات المكلفة مؤقتاً وتثبيت مراجع الدوال.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — cache a computed value
function FilteredList({ items, query }) {
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

  const handleClick = useCallback((id) => {
    console.log(`Clicked item ${id}`);
  }, []);

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child rendered");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### متى تستخدم (ومتى لا تستخدم)

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

## useReducer — منطق الحالة المعقد

مثل useState لكن لانتقالات الحالة التي تعتمد على الإجراءات. مألوف إذا كنت تعرف Redux.

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

## الهوكات المخصصة — المنطق القابل لإعادة الاستخدام

استخراج منطق المكونات في دوال قابلة لإعادة الاستخدام. أقوى نمط في React.

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

## قواعد الهوكات

تتبع React hooks قاعدتين صارمتين. كسرهما يسبب أخطاء يكاد يكون من المستحيل تتبعها.

```jsx
// ✅ Rule 1: Only call hooks at the TOP LEVEL
// Never inside conditions, loops, or nested functions
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Always called
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Conditional hook
  // }
  const [extra, setExtra] = useState("");     // ✅ Always called

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

## جدول المرجع السريع

| الهوك | الغرض | يسبب إعادة عرض؟ |
|---|---|---|
| `useState` | إدارة حالة المكوّن | نعم |
| `useEffect` | التأثيرات الجانبية (fetch، المؤقتات، DOM) | لا (يعمل بعد العرض) |
| `useContext` | قراءة السياق بدون تمرير الخصائص | نعم (عند تغيّر السياق) |
| `useRef` | مرجع قابل للتغيير / وصول DOM | لا |
| `useMemo` | تخزين الحسابات المكلفة مؤقتاً | لا (يعيد القيمة المخزنة) |
| `useCallback` | تثبيت مراجع الدوال | لا (يعيد الدالة المخزنة) |
| `useReducer` | حالة معقدة مع إجراءات | نعم |

---

## انتهى الإرسال

تغطي هذه الورقة المرجعية كل نمط React Hook ستواجهه في قواعد الأكواد الإنتاجية ومقابلات الواجهة الأمامية. من إدارة الحالة الأساسية إلى الهوكات المخصصة التي تغلف المنطق القابل لإعادة الاستخدام — هذه هي لبنات بناء React الحديث. احفظها، انسخ الأنماط، وابدأ البناء.
