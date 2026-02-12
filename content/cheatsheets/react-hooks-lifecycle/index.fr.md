---
title: "Le Guide Ultime des React Hooks (2026)"
description: "Chaque React Hook expliqué avec des extraits de code prêts à copier-coller. Maîtrisez useState, useEffect, useContext, useRef, useMemo, les hooks personnalisés et les patterns de performance utilisés dans les applications React en production."
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks guide", "usestate useeffect", "react hooks tutoriel", "apprendre développement web", "entretien frontend", "custom hooks react", "react performance", "usememo usecallback", "react context tutoriel", "useref react", "react patterns 2026", "react hooks exemples"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Le Guide Ultime des React Hooks (2026)",
    "description": "Référence complète des React Hooks avec des extraits prêts à copier-coller pour useState, useEffect, useContext, les hooks personnalisés et l'optimisation des performances.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Composant en Ligne

Les React Hooks ont remplacé les composants de classe comme méthode standard pour gérer l'état et les effets de bord. Depuis React 16.8, toute application en production est construite avec des hooks — et les recruteurs s'attendent à ce que vous les maîtrisiez parfaitement. Ce guide vous offre des extraits de code prêts à copier-coller pour chaque hook et les patterns réels que vous rencontrerez lors des entretiens frontend et du développement quotidien. Pas de cours théoriques. Juste du code fonctionnel que vous pouvez insérer dans n'importe quel composant.

---

## useState — Gestion de l'État

Le hook le plus fondamental. Déclare une variable d'état et une fonction setter.

```jsx
import { useState } from "react";

// État de base
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

// Mise à jour fonctionnelle (quand le nouvel état dépend de l'état précédent)
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ Utilisez toujours la forme fonctionnelle quand vous dépendez de l'état précédent
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// État objet
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ Étendez l'état précédent, écrasez un champ
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// État tableau
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

// Initialisation paresseuse (valeur initiale coûteuse)
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — Effets de Bord

Exécutez du code après le rendu. Gère les appels API, les abonnements, les minuteries et la manipulation du DOM.

```jsx
import { useState, useEffect } from "react";

// Exécuter à CHAQUE rendu (pas de tableau de dépendances)
useEffect(() => {
  console.log("Rendered");
});

// Exécuter UNE FOIS au montage (tableau de dépendances vide)
useEffect(() => {
  console.log("Composant monté");
}, []);

// Exécuter quand des valeurs spécifiques changent
useEffect(() => {
  console.log(`Utilisateur changé en : ${userId}`);
}, [userId]);

// Fonction de nettoyage (démontage ou avant ré-exécution)
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // nettoyage
}, []);

// Récupérer des données au montage
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // empêcher la mise à jour d'état sur un composant démonté

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

  if (loading) return <p>Chargement...</p>;
  if (error) return <p>Erreur : {error}</p>;
  return <h1>{user.name}</h1>;
}

// Écouteur d'événement avec nettoyage
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// Champ de recherche avec debounce
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

## useContext — État Global Sans Props

Partagez des valeurs dans l'arbre de composants sans prop drilling.

```jsx
import { createContext, useContext, useState } from "react";

// 1. Créer le contexte
const ThemeContext = createContext();

// 2. Créer un composant provider
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. Consommer avec useContext (n'importe quel composant enfant)
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      Thème actuel : {theme}
    </button>
  );
}

// 4. Envelopper votre app
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Pattern Auth Context (Production)

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

// Hook personnalisé pour une utilisation plus propre
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth doit être à l'intérieur de AuthProvider");
  return context;
}

// Utilisation dans n'importe quel composant
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — Références Mutables

Conservez une valeur mutable qui persiste entre les rendus sans provoquer de re-rendus.

```jsx
import { useRef, useEffect } from "react";

// Accéder à un élément DOM
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="Focus automatique au montage" />;
}

// Stocker une valeur mutable (NE provoque PAS de re-rendu)
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

// Suivre la valeur précédente
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// Défiler vers un élément
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>Cible</div>;
}
```

---

## useMemo & useCallback — Performance

Mémorisez les calculs coûteux et stabilisez les références de fonctions.

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — mettre en cache une valeur calculée
function FilteredList({ items, query }) {
  // Recalcule uniquement quand items ou query changent
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

// useMemo — calcul coûteux
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>Total : ${stats.total} ({stats.count} transactions)</p>;
}

// useCallback — stabiliser une référence de fonction
function Parent() {
  const [count, setCount] = useState(0);

  // Sans useCallback, handleClick est recréé à chaque rendu
  // provoquant le re-rendu de Child même s'il utilise React.memo
  const handleClick = useCallback((id) => {
    console.log(`Élément cliqué ${id}`);
  }, []); // référence stable

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Child rendu");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### Quand les utiliser (et quand NE PAS)

```jsx
// ✅ Utilisez useMemo quand :
// - Vous filtrez/triez de grandes listes
// - Calculs complexes (agrégations, formatage)
// - Vous créez des objets passés à des enfants mémorisés

// ✅ Utilisez useCallback quand :
// - Vous passez des callbacks à des composants React.memo
// - Vous passez des callbacks comme dépendances de useEffect

// ❌ N'utilisez PAS pour :
// - Les expressions simples (a + b, concaténation de chaînes)
// - Les fonctions qui ne sont pas passées aux enfants
// - L'optimisation prématurée — mesurez d'abord
```

---

## useReducer — Logique d'État Complexe

Comme useState mais pour les transitions d'état qui dépendent d'actions. Familier si vous connaissez Redux.

```jsx
import { useReducer } from "react";

// Définir la fonction reducer
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
      throw new Error(`Action inconnue : ${action.type}`);
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
        <button type="submit">Ajouter</button>
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
        Effacer les Terminés
      </button>
    </div>
  );
}
```

---

## Hooks Personnalisés — Logique Réutilisable

Extrayez la logique des composants en fonctions réutilisables. Le pattern le plus puissant en React.

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

// Utilisation
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

// Utilisation
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>Chargement...</p>;
  if (error) return <p>Erreur : {error}</p>;
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

// Utilisation
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

// Utilisation
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

// Utilisation
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## Règles des Hooks

Les React hooks suivent deux règles strictes. Enfreignez-les et vous obtiendrez des bugs quasi impossibles à déboguer.

```jsx
// ✅ Règle 1 : Appelez les hooks uniquement au NIVEAU SUPÉRIEUR
// Jamais dans des conditions, boucles ou fonctions imbriquées
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ Toujours appelé
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ Hook conditionnel
  // }
  const [extra, setExtra] = useState("");     // ✅ Toujours appelé
  // Puis rendez conditionnellement à la place

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ Règle 2 : Appelez les hooks uniquement depuis des fonctions React
// Composants React ou hooks personnalisés — jamais depuis des fonctions ordinaires
function useMyHook() {        // ✅ Hook personnalisé (commence par "use")
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ Pas un hook, pas un composant
//   const [val, setVal] = useState(0);
// }
```

---

## Tableau de Référence Rapide

| Hook | Objectif | Provoque un re-rendu ? |
|---|---|---|
| `useState` | Gérer l'état du composant | Oui |
| `useEffect` | Effets de bord (fetch, minuteries, DOM) | Non (s'exécute après le rendu) |
| `useContext` | Lire le contexte sans prop drilling | Oui (quand le contexte change) |
| `useRef` | Ref mutable / accès DOM | Non |
| `useMemo` | Cache pour calculs coûteux | Non (retourne la valeur en cache) |
| `useCallback` | Stabiliser les références de fonctions | Non (retourne la fonction en cache) |
| `useReducer` | État complexe avec actions | Oui |

---

## Fin de Transmission

Ce guide couvre chaque pattern de React Hooks que vous rencontrerez dans les codebases de production et les entretiens frontend. De la gestion basique de l'état aux hooks personnalisés qui encapsulent une logique réutilisable — ce sont les briques de base du React moderne. Ajoutez-le à vos favoris, copiez les patterns et construisez.
