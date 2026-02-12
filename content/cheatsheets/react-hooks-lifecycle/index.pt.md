---
title: "O Guia Definitivo de React Hooks (2026)"
description: "Cada React Hook explicado com trechos de código prontos para copiar e colar. Domine useState, useEffect, useContext, useRef, useMemo, hooks personalizados e padrões de performance usados em aplicações React em produção."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks guia", "usestate useeffect", "react hooks tutorial", "aprender desenvolvimento web", "entrevista frontend", "custom hooks react", "react performance", "usememo usecallback", "react context tutorial", "useref react", "react padrões 2026", "react hooks exemplos"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "O Guia Definitivo de React Hooks (2026)",
    "description": "Referência completa de React Hooks com snippets prontos para copiar e colar para useState, useEffect, useContext, hooks personalizados e otimização de performance.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Componente Online

Os React Hooks substituíram os componentes de classe como a forma padrão de gerenciar estado e efeitos colaterais. Desde o React 16.8, toda aplicação em produção é construída com hooks — e os entrevistadores esperam que você os domine perfeitamente. Este guia oferece snippets prontos para copiar e colar para cada hook e os padrões do mundo real que você encontrará em entrevistas frontend e no desenvolvimento diário. Sem aulas teóricas. Apenas código funcional que você pode inserir em qualquer componente.

---

## useState — Gerenciamento de Estado

O hook mais fundamental. Declara uma variável de estado e uma função setter.

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

// Atualizador funcional (quando o novo estado depende do estado anterior)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Sempre use a forma funcional quando depender do estado anterior
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// Estado objeto
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Espalhe o estado anterior, sobrescreva um campo
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

// Inicialização preguiçosa (valor inicial custoso)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Efeitos Colaterais

Execute código após o render. Gerencia chamadas de API, assinaturas, timers e manipulação do DOM.

```jsx
import { useState, useEffect } from "react";

// Executar em CADA render (sem array de dependências)
useEffect(() => {
  console.log("Rendered");
});

// Executar UMA VEZ na montagem (array de dependências vazio)
useEffect(() => {
  console.log("Componente montado");
}, []);

// Executar quando valores específicos mudam
useEffect(() => {
  console.log(`Usuário mudou para: ${userId}`);
}, [userId]);

// Função de limpeza (desmontagem ou antes de re-executar)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // limpeza
}, []);

// Buscar dados na montagem
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // prevenir atualização de estado em componente desmontado

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

  if (loading) return <p>Carregando...</p>;
  if (error) return <p>Erro: {error}</p>;
  return <h1>{user.name}</h1>;
}

// Event listener com limpeza
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Campo de busca com debounce
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

## useContext — Estado Global Sem Props

Compartilhe valores pela árvore de componentes sem prop drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Criar o contexto
const ThemeContext = createContext();

// 2. Criar um componente provider
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Consumir com useContext (qualquer componente filho)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Tema atual: {theme}
    </button>
  );
}

// 4. Envolver sua app
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Padrão Auth Context (Produção)

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

// Hook personalizado para uso mais limpo
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth deve estar dentro de AuthProvider");
  return context;
}

// Uso em qualquer componente
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Referências Mutáveis

Mantém um valor mutável que persiste entre renders sem causar re-renders.

```jsx
import { useRef, useEffect } from "react";

// Acessar um elemento DOM
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Foco automático na montagem" />;
}

// Armazenar um valor mutável (NÃO dispara re-render)
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

// Rolar até um elemento
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Destino</div>;
}
```

---

## useMemo & useCallback — Performance

Memoize cálculos custosos e estabilize referências de funções.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — cachear um valor calculado
function FilteredList({ items, query }) {
  // Só recalcula quando items ou query mudam
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

// useMemo — cálculo custoso
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Total: ${stats.total} ({stats.count} transações)</p>;
}

// useCallback — estabilizar uma referência de função
function Parent() {
  const [count, setCount] = useState(0);

  // Sem useCallback, handleClick é recriado a cada render
  // fazendo Child re-renderizar mesmo usando React.memo
  const handleClick = useCallback((id) => {
    console.log(`Item clicado ${id}`);
  }, []); // referência estável

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child renderizado");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Quando usar (e quando NÃO)

```jsx
// ✅ Use useMemo quando:
// - Filtrar/ordenar listas grandes
// - Cálculos complexos (agregações, formatação)
// - Criar objetos passados para filhos memoizados

// ✅ Use useCallback quando:
// - Passar callbacks para componentes React.memo
// - Passar callbacks como dependências de useEffect

// ❌ NÃO use para:
// - Expressões simples (a + b, concatenação de strings)
// - Funções que não são passadas para filhos
// - Otimização prematura — meça primeiro
```

---

## useReducer — Lógica de Estado Complexa

Como useState mas para transições de estado que dependem de ações. Familiar se você conhece Redux.

```jsx
import { useReducer } from "react";

// Definir função reducer
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
      throw new Error(`Ação desconhecida: ${action.type}`);
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
        <button type="submit">Adicionar</button>
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
        Limpar Concluídos
      </button>
    </div>
  );
}
```

---

## Hooks Personalizados — Lógica Reutilizável

Extraia a lógica dos componentes em funções reutilizáveis. O padrão mais poderoso em React.

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

  if (loading) return <p>Carregando...</p>;
  if (error) return <p>Erro: {error}</p>;
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

## Regras dos Hooks

Os React hooks seguem duas regras rigorosas. Quebre-as e você terá bugs quase impossíveis de depurar.

```jsx
// ✅ Regra 1: Só chame hooks no NÍVEL SUPERIOR
// Nunca dentro de condições, loops ou funções aninhadas
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Sempre chamado
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Hook condicional
  // }
  const [extra, setExtra] = useState("");     // ✅ Sempre chamado
  // Então renderize condicionalmente em vez disso

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Regra 2: Só chame hooks de funções React
// Componentes React ou hooks personalizados — nunca de funções comuns
function useMyHook() {        // ✅ Hook personalizado (começa com "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Não é um hook, não é um componente
//   const [val, setVal] = useState(0);
// }
```

---

## Tabela de Referência Rápida

| Hook | Propósito | Causa re-render? |
|---|---|---|
| `useState` | Gerenciar estado do componente | Sim |
| `useEffect` | Efeitos colaterais (fetch, timers, DOM) | Não (executa após o render) |
| `useContext` | Ler contexto sem prop drilling | Sim (quando o contexto muda) |
| `useRef` | Ref mutável / acesso DOM | Não |
| `useMemo` | Cache para cálculos custosos | Não (retorna valor em cache) |
| `useCallback` | Estabilizar referências de funções | Não (retorna função em cache) |
| `useReducer` | Estado complexo com ações | Sim |

---

## Fim da Transmissão

Este guia cobre cada padrão de React Hooks que você encontrará em codebases de produção e entrevistas frontend. Do gerenciamento básico de estado aos hooks personalizados que encapsulam lógica reutilizável — estes são os blocos de construção do React moderno. Salve nos favoritos, copie os padrões e construa.
