---
title: "La Guida Definitiva ai React Hooks (2026)"
description: "Ogni React Hook spiegato con snippet di codice pronti all'uso. Padroneggia useState, useEffect, useContext, useRef, useMemo, hook personalizzati e pattern di performance utilizzati nelle applicazioni React in produzione."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks guida", "usestate useeffect", "react hooks tutorial", "imparare sviluppo web", "colloquio frontend", "custom hooks react", "react performance", "usememo usecallback", "react context tutorial", "useref react", "react pattern 2026", "react hooks esempi"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "La Guida Definitiva ai React Hooks (2026)",
    "description": "Riferimento completo ai React Hooks con snippet pronti all'uso per useState, useEffect, useContext, hook personalizzati e ottimizzazione delle performance.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Componente Online

I React Hooks hanno sostituito i componenti a classe come metodo standard per gestire stato ed effetti collaterali. Da React 16.8, ogni applicazione in produzione è costruita con gli hooks — e gli intervistatori si aspettano che tu li conosca perfettamente. Questa guida ti offre snippet pronti all'uso per ogni hook e i pattern reali che incontrerai nei colloqui frontend e nello sviluppo quotidiano. Niente lezioni teoriche. Solo codice funzionante che puoi inserire in qualsiasi componente.

---

## useState — Gestione dello Stato

L'hook più fondamentale. Dichiara una variabile di stato e una funzione setter.

```jsx
import { useState } from "react";

// Stato base
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

// Updater funzionale (quando il nuovo stato dipende dallo stato precedente)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Usa sempre la forma funzionale quando dipendi dallo stato precedente
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Stato oggetto
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Espandi lo stato precedente, sovrascrivi un campo
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// Stato array
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

// Inizializzazione lazy (valore iniziale costoso)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Effetti Collaterali

Esegui codice dopo il render. Gestisce chiamate API, sottoscrizioni, timer e manipolazione del DOM.

```jsx
import { useState, useEffect } from "react";

// Esegui ad OGNI render (nessun array di dipendenze)
useEffect(() => {
  console.log("Rendered");
});

// Esegui UNA VOLTA al mount (array di dipendenze vuoto)
useEffect(() => {
  console.log("Componente montato");
}, []);

// Esegui quando valori specifici cambiano
useEffect(() => {
  console.log(`Utente cambiato in: ${userId}`);
}, [userId]);

// Funzione di cleanup (unmount o prima della riesecuzione)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // cleanup
}, []);

// Fetch dati al mount
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // impedisci aggiornamento stato su componente smontato

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

  if (loading) return <p>Caricamento...</p>;
  if (error) return <p>Errore: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Event listener con cleanup
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Input di ricerca con debounce
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

## useContext — Stato Globale Senza Props

Condividi valori nell'albero dei componenti senza il prop drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Crea il contesto
const ThemeContext = createContext();

// 2. Crea un componente provider
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Consuma con useContext (qualsiasi componente figlio)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Tema corrente: {theme}
    </button>
  );
}

// 4. Avvolgi la tua app
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Pattern Auth Context (Produzione)

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

// Hook personalizzato per un utilizzo più pulito
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth deve essere dentro AuthProvider");
  return context;
}

// Utilizzo in qualsiasi componente
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Riferimenti Mutabili

Mantieni un valore mutabile che persiste tra i render senza causare re-render.

```jsx
import { useRef, useEffect } from "react";

// Accedi a un elemento DOM
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Focus automatico al mount" />;
}

// Memorizza un valore mutabile (NON attiva re-render)
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

// Traccia il valore precedente
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Scroll verso un elemento
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Destinazione</div>;
}
```

---

## useMemo & useCallback — Performance

Memoizza calcoli costosi e stabilizza i riferimenti alle funzioni.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — memorizza un valore calcolato
function FilteredList({ items, query }) {
  // Ricalcola solo quando items o query cambiano
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

// useMemo — calcolo costoso
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Totale: ${stats.total} ({stats.count} transazioni)</p>;
}

// useCallback — stabilizza un riferimento a funzione
function Parent() {
  const [count, setCount] = useState(0);

  // Senza useCallback, handleClick viene ricreato ad ogni render
  // causando il re-render di Child anche se usa React.memo
  const handleClick = useCallback((id) => {
    console.log(`Elemento cliccato ${id}`);
  }, []); // riferimento stabile

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child renderizzato");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Quando usarli (e quando NO)

```jsx
// ✅ Usa useMemo quando:
// - Filtri/ordini liste grandi
// - Calcoli complessi (aggregazioni, formattazione)
// - Crei oggetti passati a figli memoizzati

// ✅ Usa useCallback quando:
// - Passi callback a componenti React.memo
// - Passi callback come dipendenze di useEffect

// ❌ NON usare per:
// - Espressioni semplici (a + b, concatenazione di stringhe)
// - Funzioni che non vengono passate ai figli
// - Ottimizzazione prematura — misura prima
```

---

## useReducer — Logica di Stato Complessa

Come useState ma per transizioni di stato che dipendono da azioni. Familiare se conosci Redux.

```jsx
import { useReducer } from "react";

// Definisci la funzione reducer
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
      throw new Error(`Azione sconosciuta: ${action.type}`);
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
        <button type="submit">Aggiungi</button>
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
        Cancella Completati
      </button>
    </div>
  );
}
```

---

## Hook Personalizzati — Logica Riutilizzabile

Estrai la logica dei componenti in funzioni riutilizzabili. Il pattern più potente in React.

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

// Utilizzo
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

// Utilizzo
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Caricamento...</p>;
  if (error) return <p>Errore: {error}</p>;
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

// Utilizzo
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

// Utilizzo
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

// Utilizzo
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Regole degli Hook

I React hooks seguono due regole rigide. Violale e otterrai bug quasi impossibili da debuggare.

```jsx
// ✅ Regola 1: Chiama gli hook solo al LIVELLO PIÙ ALTO
// Mai dentro condizioni, cicli o funzioni annidate
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Sempre chiamato
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Hook condizionale
  // }
  const [extra, setExtra] = useState("");     // ✅ Sempre chiamato
  // Poi renderizza condizionalmente invece

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Regola 2: Chiama gli hook solo da funzioni React
// Componenti React o hook personalizzati — mai da funzioni normali
function useMyHook() {        // ✅ Hook personalizzato (inizia con "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Non è un hook, non è un componente
//   const [val, setVal] = useState(0);
// }
```

---

## Tabella di Riferimento Rapido

| Hook | Scopo | Causa re-render? |
|---|---|---|
| `useState` | Gestire lo stato del componente | Sì |
| `useEffect` | Effetti collaterali (fetch, timer, DOM) | No (eseguito dopo il render) |
| `useContext` | Leggere il contesto senza prop drilling | Sì (quando il contesto cambia) |
| `useRef` | Ref mutabile / accesso DOM | No |
| `useMemo` | Cache per calcoli costosi | No (restituisce valore in cache) |
| `useCallback` | Stabilizzare riferimenti a funzioni | No (restituisce funzione in cache) |
| `useReducer` | Stato complesso con azioni | Sì |

---

## Fine della Trasmissione

Questa guida copre ogni pattern dei React Hooks che incontrerai nei codebase di produzione e nei colloqui frontend. Dalla gestione base dello stato agli hook personalizzati che incapsulano logica riutilizzabile — questi sono i mattoni del React moderno. Salvala nei preferiti, copia i pattern e costruisci.
