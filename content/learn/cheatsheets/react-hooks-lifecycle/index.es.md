---
title: "La Guía Definitiva de React Hooks (2026)"
description: "Cada React Hook explicado con fragmentos de código listos para copiar y pegar. Domina useState, useEffect, useContext, useRef, useMemo, hooks personalizados y patrones de rendimiento utilizados en aplicaciones React en producción."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks guía", "usestate useeffect", "react hooks tutorial", "aprender desarrollo web", "entrevista frontend", "custom hooks react", "react rendimiento", "usememo usecallback", "react context tutorial", "useref react", "react patrones 2026", "react hooks ejemplos"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "La Guía Definitiva de React Hooks (2026)",
    "description": "Referencia completa de React Hooks con fragmentos listos para copiar y pegar para useState, useEffect, useContext, hooks personalizados y optimización del rendimiento.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Componente en Línea

Los React Hooks reemplazaron a los componentes de clase como la forma estándar de gestionar estado y efectos secundarios. Desde React 16.8, toda aplicación en producción se construye con hooks — y los entrevistadores esperan que los domines a la perfección. Esta guía te ofrece fragmentos de código listos para copiar y pegar para cada hook y los patrones del mundo real que encontrarás en entrevistas frontend y en el desarrollo diario. Sin clases teóricas. Solo código funcional que puedes insertar en cualquier componente.

---

## useState — Gestión de Estado

El hook más fundamental. Declara una variable de estado y una función setter.

```jsx
import { useState } from "react";

// Estado básico
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

// Actualizador funcional (cuando el nuevo estado depende del estado anterior)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Siempre usa la forma funcional cuando dependas del estado anterior
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Estado objeto
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Expande el estado anterior, sobrescribe un campo
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// Estado array
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

// Inicialización perezosa (valor inicial costoso)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Efectos Secundarios

Ejecuta código después del render. Gestiona llamadas API, suscripciones, temporizadores y manipulación del DOM.

```jsx
import { useState, useEffect } from "react";

// Ejecutar en CADA render (sin array de dependencias)
useEffect(() => {
  console.log("Rendered");
});

// Ejecutar UNA VEZ al montar (array de dependencias vacío)
useEffect(() => {
  console.log("Componente montado");
}, []);

// Ejecutar cuando valores específicos cambian
useEffect(() => {
  console.log(`Usuario cambió a: ${userId}`);
}, [userId]);

// Función de limpieza (desmontaje o antes de re-ejecutar)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // limpieza
}, []);

// Obtener datos al montar
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // evitar actualización de estado en componente desmontado

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

  if (loading) return <p>Cargando...</p>;
  if (error) return <p>Error: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Event listener con limpieza
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Input de búsqueda con debounce
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

## useContext — Estado Global Sin Props

Comparte valores a través del árbol de componentes sin prop drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Crear el contexto
const ThemeContext = createContext();

// 2. Crear un componente provider
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Consumir con useContext (cualquier componente hijo)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Tema actual: {theme}
    </button>
  );
}

// 4. Envolver tu app
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Patrón Auth Context (Producción)

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

// Hook personalizado para un uso más limpio
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth debe estar dentro de AuthProvider");
  return context;
}

// Uso en cualquier componente
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Referencias Mutables

Mantiene un valor mutable que persiste entre renders sin causar re-renders.

```jsx
import { useRef, useEffect } from "react";

// Acceder a un elemento DOM
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Auto-enfoco al montar" />;
}

// Almacenar un valor mutable (NO activa re-render)
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

// Rastrear valor anterior
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Desplazar hacia un elemento
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Destino</div>;
}
```

---

## useMemo & useCallback — Rendimiento

Memoiza cálculos costosos y estabiliza las referencias a funciones.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — cachear un valor calculado
function FilteredList({ items, query }) {
  // Solo recalcula cuando items o query cambian
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

// useMemo — cálculo costoso
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Total: ${stats.total} ({stats.count} transacciones)</p>;
}

// useCallback — estabilizar una referencia a función
function Parent() {
  const [count, setCount] = useState(0);

  // Sin useCallback, handleClick se recrea en cada render
  // causando que Child se re-renderice incluso si usa React.memo
  const handleClick = useCallback((id) => {
    console.log(`Elemento clicado ${id}`);
  }, []); // referencia estable

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child renderizado");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Cuándo usarlos (y cuándo NO)

```jsx
// ✅ Usa useMemo cuando:
// - Filtras/ordenas listas grandes
// - Cálculos complejos (agregaciones, formateo)
// - Creas objetos pasados a hijos memoizados

// ✅ Usa useCallback cuando:
// - Pasas callbacks a componentes React.memo
// - Pasas callbacks como dependencias de useEffect

// ❌ NO usar para:
// - Expresiones simples (a + b, concatenación de strings)
// - Funciones que no se pasan a hijos
// - Optimización prematura — mide primero
```

---

## useReducer — Lógica de Estado Compleja

Como useState pero para transiciones de estado que dependen de acciones. Familiar si conoces Redux.

```jsx
import { useReducer } from "react";

// Definir función reducer
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
      throw new Error(`Acción desconocida: ${action.type}`);
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
        <button type="submit">Agregar</button>
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
        Limpiar Completados
      </button>
    </div>
  );
}
```

---

## Hooks Personalizados — Lógica Reutilizable

Extrae la lógica de los componentes en funciones reutilizables. El patrón más poderoso en React.

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

// Uso
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

// Uso
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Cargando...</p>;
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

// Uso
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

// Uso
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

// Uso
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Reglas de los Hooks

Los React hooks siguen dos reglas estrictas. Rómpelas y obtendrás bugs casi imposibles de depurar.

```jsx
// ✅ Regla 1: Solo llama hooks en el NIVEL SUPERIOR
// Nunca dentro de condiciones, bucles o funciones anidadas
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Siempre se llama
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Hook condicional
  // }
  const [extra, setExtra] = useState("");     // ✅ Siempre se llama
  // Luego renderiza condicionalmente en su lugar

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Regla 2: Solo llama hooks desde funciones React
// Componentes React o hooks personalizados — nunca desde funciones normales
function useMyHook() {        // ✅ Hook personalizado (empieza con "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ No es un hook, no es un componente
//   const [val, setVal] = useState(0);
// }
```

---

## Tabla de Referencia Rápida

| Hook | Propósito | ¿Causa re-render? |
|---|---|---|
| `useState` | Gestionar estado del componente | Sí |
| `useEffect` | Efectos secundarios (fetch, timers, DOM) | No (se ejecuta después del render) |
| `useContext` | Leer contexto sin prop drilling | Sí (cuando el contexto cambia) |
| `useRef` | Ref mutable / acceso DOM | No |
| `useMemo` | Cachear cálculos costosos | No (devuelve valor cacheado) |
| `useCallback` | Estabilizar referencias a funciones | No (devuelve función cacheada) |
| `useReducer` | Estado complejo con acciones | Sí |

---

## Fin de la Transmisión

Esta guía cubre cada patrón de React Hooks que encontrarás en codebases de producción y entrevistas frontend. Desde la gestión básica de estado hasta hooks personalizados que encapsulan lógica reutilizable — estos son los bloques de construcción del React moderno. Guárdala en marcadores, copia los patrones y construye.
