---
title: "究極のReact Hooksチートシート（2026年版）"
description: "すべてのReact Hookをコピペ可能なコードスニペットで解説。useState、useEffect、useContext、useRef、useMemo、カスタムフック、そしてプロダクションReactアプリケーションで使われるパフォーマンスパターンをマスターしましょう。"
date: 2026-02-10
tags: ["react", "cheatsheet", "frontend", "hooks", "web-dev"]
keywords: ["react hooks チートシート", "usestate useeffect", "react hooks チュートリアル", "ウェブ開発 学習", "フロントエンド 面接", "custom hooks react", "react パフォーマンス", "usememo usecallback", "react context チュートリアル", "useref react", "react パターン 2026", "react hooks 例"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "究極のReact Hooksチートシート（2026年版）",
    "description": "useState、useEffect、useContext、カスタムフック、パフォーマンス最適化のコピペ可能なスニペット付きReact Hooks完全リファレンス。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## コンポーネント オンライン

React Hooksは、状態管理と副作用処理の標準的な方法としてクラスコンポーネントを置き換えました。React 16.8以降、すべてのプロダクションアプリケーションはフックで構築されており、面接官はあなたがそれらを完璧に理解していることを期待しています。このチートシートは、すべてのフックのコピペ可能なスニペットと、フロントエンド面接や日常の開発で遭遇する実践的なパターンを提供します。理論の講義はありません。どんなコンポーネントにも挿入できる動作するコードだけです。

---

## useState — 状態管理

最も基本的なフック。状態変数とセッター関数を宣言します。

```jsx
import { useState } from "react";

// 基本的な状態
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

// 関数型アップデーター（新しい状態が前の状態に依存する場合）
function SafeCounter() {
  const [count, setCount] = useState(0);

  const increment = () => {
    // ✅ 前の状態に依存する場合は常に関数型を使用する
    setCount(prev => prev + 1);
  };

  return <button onClick={increment}>{count}</button>;
}

// オブジェクト状態
function Form() {
  const [form, setForm] = useState({ name: "", email: "", role: "dev" });

  const handleChange = (e) => {
    const { name, value } = e.target;
    // ✅ 前の状態をスプレッドし、1つのフィールドを上書き
    setForm(prev => ({ ...prev, [name]: value }));
  };

  return (
    <form>
      <input name="name" value={form.name} onChange={handleChange} />
      <input name="email" value={form.email} onChange={handleChange} />
    </form>
  );
}

// 配列状態
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

// 遅延初期化（コストの高い初期値）
const [data, setData] = useState(() => {
  return JSON.parse(localStorage.getItem("appData")) || {};
});
```

---

## useEffect — 副作用

レンダー後にコードを実行します。API呼び出し、サブスクリプション、タイマー、DOM操作を処理します。

```jsx
import { useState, useEffect } from "react";

// 毎回のレンダーで実行（依存配列なし）
useEffect(() => {
  console.log("Rendered");
});

// マウント時に一度だけ実行（空の依存配列）
useEffect(() => {
  console.log("コンポーネントがマウントされました");
}, []);

// 特定の値が変更されたときに実行
useEffect(() => {
  console.log(`ユーザーが変更されました: ${userId}`);
}, [userId]);

// クリーンアップ関数（アンマウント時または再実行前）
useEffect(() => {
  const timer = setInterval(() => console.log("tick"), 1000);
  return () => clearInterval(timer); // クリーンアップ
}, []);

// マウント時にデータを取得
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false; // アンマウントされたコンポーネントの状態更新を防止

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

  if (loading) return <p>読み込み中...</p>;
  if (error) return <p>エラー: {error}</p>;
  return <h1>{user.name}</h1>;
}

// クリーンアップ付きイベントリスナー
useEffect(() => {
  const handleResize = () => console.log(window.innerWidth);
  window.addEventListener("resize", handleResize);
  return () => window.removeEventListener("resize", handleResize);
}, []);

// デバウンス付き検索入力
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

## useContext — Propsなしのグローバル状態

prop drillingなしでコンポーネントツリー全体に値を共有します。

```jsx
import { createContext, useContext, useState } from "react";

// 1. コンテキストを作成
const ThemeContext = createContext();

// 2. プロバイダーコンポーネントを作成
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState("dark");
  const toggle = () => setTheme(prev => (prev === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 3. useContextで消費（任意の子コンポーネント）
function ThemeButton() {
  const { theme, toggle } = useContext(ThemeContext);

  return (
    <button onClick={toggle}>
      現在のテーマ: {theme}
    </button>
  );
}

// 4. アプリをラップ
function App() {
  return (
    <ThemeProvider>
      <ThemeButton />
    </ThemeProvider>
  );
}
```

### Auth Contextパターン（プロダクション）

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

// よりクリーンな使用のためのカスタムフック
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuthはAuthProvider内で使用する必要があります");
  return context;
}

// 任意のコンポーネントでの使用
function Dashboard() {
  const { user, logout } = useAuth();
  return <button onClick={logout}>Logout {user.name}</button>;
}
```

---

## useRef — ミュータブル参照

再レンダーを引き起こさずにレンダー間で永続するミュータブルな値を保持します。

```jsx
import { useRef, useEffect } from "react";

// DOM要素にアクセス
function AutoFocusInput() {
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current.focus();
  }, []);

  return <input ref={inputRef} placeholder="マウント時に自動フォーカス" />;
}

// ミュータブルな値を保存（再レンダーを引き起こさない）
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

// 前の値を追跡
function usePrevious(value) {
  const ref = useRef();
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

// 要素までスクロール
function ScrollDemo() {
  const sectionRef = useRef(null);
  const scrollToSection = () => {
    sectionRef.current.scrollIntoView({ behavior: "smooth" });
  };
  return <div ref={sectionRef}>ターゲット</div>;
}
```

---

## useMemo & useCallback — パフォーマンス

コストの高い計算をメモ化し、関数参照を安定させます。

```jsx
import { useMemo, useCallback, useState } from "react";

// useMemo — 計算値をキャッシュ
function FilteredList({ items, query }) {
  // itemsまたはqueryが変更されたときのみ再計算
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

// useMemo — コストの高い計算
function Dashboard({ transactions }) {
  const stats = useMemo(() => ({
    total: transactions.reduce((sum, t) => sum + t.amount, 0),
    count: transactions.length,
    average: transactions.length
      ? transactions.reduce((sum, t) => sum + t.amount, 0) / transactions.length
      : 0,
  }), [transactions]);

  return <p>合計: ${stats.total} ({stats.count} トランザクション)</p>;
}

// useCallback — 関数参照を安定させる
function Parent() {
  const [count, setCount] = useState(0);

  // useCallbackなしではhandleClickは毎回のレンダーで再生成され、
  // ChildがReact.memoを使用していても再レンダーを引き起こす
  const handleClick = useCallback((id) => {
    console.log(`アイテムがクリックされました ${id}`);
  }, []); // 安定した参照

  return <MemoizedChild onClick={handleClick} />;
}

const MemoizedChild = React.memo(function Child({ onClick }) {
  console.log("Childがレンダーされました");
  return <button onClick={() => onClick(1)}>Click</button>;
});
```

### いつ使うべきか（そしていつ使うべきでないか）

```jsx
// ✅ useMemoを使うとき：
// - 大きなリストのフィルタリング/ソート
// - 複雑な計算（集計、フォーマット）
// - メモ化された子コンポーネントに渡すオブジェクトの作成

// ✅ useCallbackを使うとき：
// - React.memoコンポーネントにコールバックを渡すとき
// - useEffectの依存配列としてコールバックを渡すとき

// ❌ 使うべきでない場合：
// - 単純な式（a + b、文字列結合）
// - 子コンポーネントに渡さない関数
// - 早すぎる最適化 — まず計測すること
```

---

## useReducer — 複雑な状態ロジック

useStateに似ていますが、アクションに依存する状態遷移用です。Reduxを知っていれば馴染みがあるでしょう。

```jsx
import { useReducer } from "react";

// reducer関数を定義
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
      throw new Error(`不明なアクション: ${action.type}`);
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
        <button type="submit">追加</button>
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
        完了済みをクリア
      </button>
    </div>
  );
}
```

---

## カスタムフック — 再利用可能なロジック

コンポーネントのロジックを再利用可能な関数に抽出します。Reactで最も強力なパターンです。

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

// 使用例
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

// 使用例
function UserList() {
  const { data: users, loading, error } = useFetch("/api/users");

  if (loading) return <p>読み込み中...</p>;
  if (error) return <p>エラー: {error}</p>;
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

// 使用例
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

// 使用例
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

// 使用例
const { width } = useWindowSize();
const isMobile = width < 768;
```

---

## フックのルール

React Hooksは2つの厳格なルールに従います。これらを破ると、デバッグがほぼ不可能なバグが発生します。

```jsx
// ✅ ルール1：フックはトップレベルでのみ呼び出す
// 条件分岐、ループ、ネストされた関数の中では呼び出さない
function Component({ showExtra }) {
  const [count, setCount] = useState(0);     // ✅ 常に呼び出される
  // if (showExtra) {
  //   const [extra, setExtra] = useState(""); // ❌ 条件付きフック
  // }
  const [extra, setExtra] = useState("");     // ✅ 常に呼び出される
  // 代わりに条件付きでレンダーする

  return showExtra ? <p>{extra}</p> : null;
}

// ✅ ルール2：フックはReact関数からのみ呼び出す
// Reactコンポーネントまたはカスタムフック — 通常の関数からは呼び出さない
function useMyHook() {        // ✅ カスタムフック（"use"で始まる）
  const [val, setVal] = useState(0);
  return val;
}
// function helperFunction() {   // ❌ フックでもコンポーネントでもない
//   const [val, setVal] = useState(0);
// }
```

---

## クイックリファレンステーブル

| フック | 目的 | 再レンダーを引き起こす？ |
|---|---|---|
| `useState` | コンポーネントの状態を管理 | はい |
| `useEffect` | 副作用（fetch、タイマー、DOM） | いいえ（レンダー後に実行） |
| `useContext` | prop drillingなしでコンテキストを読み取り | はい（コンテキスト変更時） |
| `useRef` | ミュータブルref / DOMアクセス | いいえ |
| `useMemo` | コストの高い計算をキャッシュ | いいえ（キャッシュされた値を返す） |
| `useCallback` | 関数参照を安定させる | いいえ（キャッシュされた関数を返す） |
| `useReducer` | アクション付きの複雑な状態 | はい |

---

## 送信終了

このチートシートは、プロダクションコードベースやフロントエンド面接で遭遇するすべてのReact Hookパターンをカバーしています。基本的な状態管理から再利用可能なロジックをカプセル化するカスタムフックまで — これらはモダンReactの構成要素です。ブックマークして、パターンをコピーして、構築しましょう。
