---
title: "Das Ultimative React Hooks Cheatsheet (2026)"
description: "Jeder React Hook erklärt mit Copy-Paste-Codebeispielen. Meistere useState, useEffect, useContext, useRef, useMemo, benutzerdefinierte Hooks und Performance-Muster, die in produktiven React-Anwendungen verwendet werden."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks cheatsheet", "usestate useeffect", "react hooks tutorial", "webentwicklung lernen", "frontend interview", "custom hooks react", "react performance", "usememo usecallback", "react context tutorial", "useref react", "react muster 2026", "react hooks beispiele"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Das Ultimative React Hooks Cheatsheet (2026)",
    "description": "Vollständige React Hooks Referenz mit Copy-Paste-Snippets für useState, useEffect, useContext, benutzerdefinierte Hooks und Performance-Optimierung.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Komponente Online

React Hooks haben Klassenkomponenten als Standardmethode zur Verwaltung von State und Seiteneffekten abgelöst. Seit React 16.8 wird jede Produktionsanwendung mit Hooks gebaut — und Interviewer erwarten, dass du sie perfekt beherrschst. Dieses Cheatsheet bietet dir Copy-Paste-Snippets für jeden Hook und die praxisnahen Muster, die dir in Frontend-Interviews und im täglichen Entwicklungsalltag begegnen werden. Keine Theorie-Vorlesungen. Nur funktionierender Code, den du in jede Komponente einfügen kannst.

---

## useState — State-Verwaltung

Der grundlegendste Hook. Deklariert eine State-Variable und eine Setter-Funktion.

```jsx
import { useState } from "react";

// Grundlegender State
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

// Funktionaler Updater (wenn der neue State vom vorherigen abhängt)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Verwende immer die funktionale Form, wenn du vom vorherigen State abhängst
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Objekt-State
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Vorherigen State spreaden, ein Feld überschreiben
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// Array-State
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

// Verzögerte Initialisierung (teurer Anfangswert)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Seiteneffekte

Führe Code nach dem Rendern aus. Verwaltet API-Aufrufe, Abonnements, Timer und DOM-Manipulation.

```jsx
import { useState, useEffect } from "react";

// Bei JEDEM Render ausführen (kein Dependency-Array)
useEffect(() => {
  console.log("Rendered");
});

// EINMAL beim Mounten ausführen (leeres Dependency-Array)
useEffect(() => {
  console.log("Komponente gemountet");
}, []);

// Ausführen wenn sich bestimmte Werte ändern
useEffect(() => {
  console.log(`Benutzer geändert zu: ${userId}`);
}, [userId]);

// Cleanup-Funktion (Unmount oder vor erneutem Ausführen)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // Cleanup
}, []);

// Daten beim Mounten laden
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // State-Update auf unmounted Komponente verhindern

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

  if (loading) return <p>Laden...</p>;
  if (error) return <p>Fehler: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Event-Listener mit Cleanup
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Sucheingabe mit Debounce
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

## useContext — Globaler State Ohne Props

Teile Werte im Komponentenbaum ohne Prop Drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Context erstellen
const ThemeContext = createContext();

// 2. Provider-Komponente erstellen
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Mit useContext konsumieren (jede Kind-Komponente)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Aktuelles Theme: {theme}
    </button>
  );
}

// 4. App umwickeln
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Auth Context Muster (Produktion)

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

// Benutzerdefinierter Hook für sauberere Verwendung
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth muss innerhalb von AuthProvider sein");
  return context;
}

// Verwendung in jeder Komponente
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Veränderbare Referenzen

Halte einen veränderbaren Wert, der über Renders hinweg bestehen bleibt, ohne Re-Renders auszulösen.

```jsx
import { useRef, useEffect } from "react";

// Auf ein DOM-Element zugreifen
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Auto-Fokus beim Mounten" />;
}

// Veränderbaren Wert speichern (löst KEIN Re-Render aus)
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

// Vorherigen Wert verfolgen
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Zu einem Element scrollen
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Ziel</div>;
}
```

---

## useMemo & useCallback — Performance

Memoize teure Berechnungen und stabilisiere Funktionsreferenzen.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — berechneten Wert zwischenspeichern
function FilteredList({ items, query }) {
  // Berechnet nur neu, wenn items oder query sich ändern
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

// useMemo — teure Berechnung
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Gesamt: ${stats.total} ({stats.count} Transaktionen)</p>;
}

// useCallback — Funktionsreferenz stabilisieren
function Parent() {
  const [count, setCount] = useState(0);

  // Ohne useCallback wird handleClick bei jedem Render neu erstellt
  // was dazu führt, dass Child re-rendert, selbst wenn es React.memo verwendet
  const handleClick = useCallback((id) => {
    console.log(`Element geklickt ${id}`);
  }, []); // stabile Referenz

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child gerendert");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Wann verwenden (und wann NICHT)

```jsx
// ✅ Verwende useMemo wenn:
// - Filtern/Sortieren großer Listen
// - Komplexe Berechnungen (Aggregationen, Formatierung)
// - Objekte erstellt werden, die an memoized Kinder übergeben werden

// ✅ Verwende useCallback wenn:
// - Callbacks an React.memo-Komponenten übergeben werden
// - Callbacks als useEffect-Dependencies übergeben werden

// ❌ NICHT verwenden für:
// - Einfache Ausdrücke (a + b, String-Verkettung)
// - Funktionen, die nicht an Kinder übergeben werden
// - Vorzeitige Optimierung — erst messen
```

---

## useReducer — Komplexe State-Logik

Wie useState, aber für State-Übergänge, die von Aktionen abhängen. Vertraut, wenn du Redux kennst.

```jsx
import { useReducer } from "react";

// Reducer-Funktion definieren
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
      throw new Error(`Unbekannte Aktion: ${action.type}`);
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
        <button type="submit">Hinzufügen</button>
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
        Erledigte Löschen
      </button>
    </div>
  );
}
```

---

## Benutzerdefinierte Hooks — Wiederverwendbare Logik

Extrahiere Komponentenlogik in wiederverwendbare Funktionen. Das mächtigste Muster in React.

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

// Verwendung
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

// Verwendung
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Laden...</p>;
  if (error) return <p>Fehler: {error}</p>;
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

// Verwendung
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

// Verwendung
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

// Verwendung
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Hook-Regeln

React Hooks folgen zwei strikten Regeln. Brich sie und du bekommst Bugs, die nahezu unmöglich zu debuggen sind.

```jsx
// ✅ Regel 1: Rufe Hooks nur auf der OBERSTEN EBENE auf
// Niemals innerhalb von Bedingungen, Schleifen oder verschachtelten Funktionen
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Wird immer aufgerufen
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Bedingter Hook
  // }
  const [extra, setExtra] = useState("");     // ✅ Wird immer aufgerufen
  // Dann stattdessen bedingt rendern

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Regel 2: Rufe Hooks nur aus React-Funktionen auf
// React-Komponenten oder benutzerdefinierte Hooks — niemals aus normalen Funktionen
function useMyHook() {        // ✅ Benutzerdefinierter Hook (beginnt mit "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Kein Hook, keine Komponente
//   const [val, setVal] = useState(0);
// }
```

---

## Schnellreferenz-Tabelle

| Hook | Zweck | Löst Re-Render aus? |
|---|---|---|
| `useState` | Komponenten-State verwalten | Ja |
| `useEffect` | Seiteneffekte (Fetch, Timer, DOM) | Nein (läuft nach dem Render) |
| `useContext` | Context ohne Prop Drilling lesen | Ja (wenn sich der Context ändert) |
| `useRef` | Veränderbare Ref / DOM-Zugriff | Nein |
| `useMemo` | Teure Berechnungen zwischenspeichern | Nein (gibt gecachten Wert zurück) |
| `useCallback` | Funktionsreferenzen stabilisieren | Nein (gibt gecachte Funktion zurück) |
| `useReducer` | Komplexer State mit Aktionen | Ja |

---

## Ende der Übertragung

Dieses Cheatsheet deckt jedes React Hook Muster ab, das dir in Produktions-Codebasen und Frontend-Interviews begegnen wird. Von der grundlegenden State-Verwaltung bis zu benutzerdefinierten Hooks, die wiederverwendbare Logik kapseln — das sind die Bausteine des modernen React. Speichere es als Lesezeichen, kopiere die Muster und baue.
