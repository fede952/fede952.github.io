---
title: "SQL & Database Design Interview Questions (Senior Level)"
description: "20 advanced SQL and database interview questions for Senior Backend and DBA roles. Covers query optimization, normalization, indexing, transactions, ACID properties, and security."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["sql query interview questions", "database normalization", "acid properties", "sql injection prevention", "database index interview", "sql join questions", "postgresql interview", "mysql interview questions", "database design patterns", "sql performance tuning"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL & Database Design Interview Questions (Senior Level)",
    "description": "20 advanced SQL and database interview questions covering optimization, normalization, indexing, transactions, and security.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "en"
  }
---

## System Init

SQL is the language of data, and databases are the backbone of every application. Senior-level interviews test your ability to write efficient queries, design normalized schemas, understand transaction isolation, optimize performance with indexes, and prevent SQL injection. Whether the role is Backend Engineer, DBA, Data Engineer, or Security Analyst, these 20 questions cover the concepts that interviewers consistently ask — with answers that demonstrate production experience.

**Need a quick SQL reference?** Keep our [SQL Injection & Database Queries Cheatsheet](/cheatsheets/sql-injection-payloads-database/) open during your prep.

---

## Query Fundamentals

<details>
<summary><strong>1. What is the order of execution of a SQL query?</strong></summary>
<br>

SQL queries are **not** executed in the order you write them. The actual execution order is:

1. **FROM** / **JOIN** — identify the tables and join them.
2. **WHERE** — filter rows before grouping.
3. **GROUP BY** — group the remaining rows.
4. **HAVING** — filter groups (after aggregation).
5. **SELECT** — choose which columns/expressions to return.
6. **DISTINCT** — remove duplicate rows.
7. **ORDER BY** — sort the results.
8. **LIMIT** / **OFFSET** — restrict the number of rows returned.

This is why you cannot use a column alias defined in SELECT inside a WHERE clause — WHERE executes before SELECT.
</details>

<details>
<summary><strong>2. Explain the difference between WHERE and HAVING.</strong></summary>
<br>

- **WHERE** filters rows **before** aggregation (GROUP BY). It operates on individual rows and cannot use aggregate functions.
- **HAVING** filters groups **after** aggregation. It operates on the results of GROUP BY and can use aggregate functions.

```sql
-- WHERE: Filter individual orders over $100
SELECT customer_id, SUM(total) as total_spent
FROM orders
WHERE total > 100
GROUP BY customer_id;

-- HAVING: Filter customers who spent over $1000 total
SELECT customer_id, SUM(total) as total_spent
FROM orders
GROUP BY customer_id
HAVING SUM(total) > 1000;
```

Performance: WHERE is always preferable when possible — it reduces the dataset before the expensive GROUP BY operation.
</details>

<details>
<summary><strong>3. What is the difference between INNER JOIN, LEFT JOIN, RIGHT JOIN, and FULL OUTER JOIN?</strong></summary>
<br>

- **INNER JOIN**: Returns only rows that have matching values in **both** tables. Non-matching rows are excluded.
- **LEFT JOIN**: Returns all rows from the left table, and matching rows from the right table. If no match, right columns are NULL.
- **RIGHT JOIN**: Returns all rows from the right table, and matching rows from the left table. If no match, left columns are NULL.
- **FULL OUTER JOIN**: Returns all rows from both tables. Where there is no match, the missing side is NULL.

In practice, LEFT JOIN is used ~90% of the time. RIGHT JOIN can always be rewritten as a LEFT JOIN by swapping the table order.
</details>

<details>
<summary><strong>4. What is the difference between UNION and UNION ALL?</strong></summary>
<br>

- **UNION**: Combines results from two queries and **removes duplicate rows**. Requires a sort/dedup operation internally.
- **UNION ALL**: Combines results **without removing duplicates**. Faster because no dedup is needed.

Always use `UNION ALL` unless you specifically need deduplication. The implicit sort operation of `UNION` can be expensive on large datasets.

Both require the same number of columns with compatible data types in each SELECT.
</details>

## Database Design

<details>
<summary><strong>5. Explain database normalization (1NF through 3NF).</strong></summary>
<br>

Normalization reduces data redundancy and prevents update anomalies:

- **1NF** (First Normal Form): Each column contains atomic (indivisible) values. No repeating groups. Each row is unique (has a primary key).
- **2NF**: Meets 1NF + every non-key column depends on the **entire** primary key (not just part of a composite key). Eliminates partial dependencies.
- **3NF**: Meets 2NF + every non-key column depends **directly** on the primary key, not on another non-key column. Eliminates transitive dependencies.

Example violation of 3NF: A table with `(order_id, customer_id, customer_name)` — `customer_name` depends on `customer_id`, not on `order_id`. Fix: Move `customer_name` to a separate `customers` table.
</details>

<details>
<summary><strong>6. When would you intentionally denormalize a database?</strong></summary>
<br>

Denormalization is justified when:

1. **Read performance is critical**: Reporting dashboards, analytics queries that join many tables. Pre-computing aggregates or flattening hierarchies avoids expensive joins at query time.
2. **Caching layers**: Materialized views or summary tables that are refreshed periodically.
3. **NoSQL/Document stores**: Data is stored as complete documents (MongoDB). Embedding related data avoids joins entirely.
4. **Event sourcing/CQRS**: Write model is normalized, read model is denormalized.

The trade-off: faster reads at the cost of more complex writes (must update multiple places) and potential data inconsistency.
</details>

<details>
<summary><strong>7. What are ACID properties?</strong></summary>
<br>

ACID guarantees reliable database transactions:

- **Atomicity**: A transaction is all-or-nothing. If any part fails, the entire transaction is rolled back. No partial updates.
- **Consistency**: A transaction moves the database from one valid state to another. All constraints (foreign keys, checks, triggers) are satisfied.
- **Isolation**: Concurrent transactions do not interfere with each other. Each transaction sees a consistent snapshot of the data.
- **Durability**: Once a transaction is committed, it survives system crashes. Data is written to non-volatile storage (WAL, redo logs).

ACID is the defining characteristic of relational databases (PostgreSQL, MySQL InnoDB). Many NoSQL databases sacrifice some ACID properties for scalability (BASE: Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. Explain transaction isolation levels.</strong></summary>
<br>

From least to most strict:

1. **Read Uncommitted**: Can read uncommitted changes from other transactions (**dirty reads**). Almost never used.
2. **Read Committed** (PostgreSQL default): Only reads committed data. But re-reading the same row may return different values if another transaction committed in between (**non-repeatable reads**).
3. **Repeatable Read** (MySQL InnoDB default): Re-reading the same row always returns the same value within a transaction. But new rows inserted by other transactions may appear (**phantom reads**).
4. **Serializable**: Full isolation. Transactions execute as if they were serial (one after another). Prevents all anomalies but has the highest performance cost (locking/MVCC overhead).

Choose based on the application: financial transactions need Serializable; web app reads typically use Read Committed.
</details>

## Indexing & Performance

<details>
<summary><strong>9. What is a database index and how does it work?</strong></summary>
<br>

An index is a separate data structure (typically a **B-tree** or **B+ tree**) that stores a sorted copy of specific columns alongside pointers to the full rows. It enables the database to find rows without scanning the entire table (full table scan).

Analogy: A book index maps keywords to page numbers. Without it, you must read every page to find a topic.

Trade-offs:
- **Faster reads**: SELECT with WHERE, JOIN, ORDER BY on indexed columns.
- **Slower writes**: Every INSERT, UPDATE, DELETE must also update the index.
- **More storage**: The index occupies disk space proportional to the indexed data.

Rule: Index columns that appear in WHERE, JOIN ON, ORDER BY, and GROUP BY clauses frequently.
</details>

<details>
<summary><strong>10. What is the difference between a clustered and non-clustered index?</strong></summary>
<br>

- **Clustered index**: Determines the **physical order** of data on disk. A table can have only one clustered index (usually the primary key). The leaf nodes of the B-tree contain the actual data rows.
- **Non-clustered index**: A separate structure with pointers to the data rows. A table can have multiple non-clustered indexes. The leaf nodes contain the indexed column values and a reference (row locator) to the actual data.

In PostgreSQL, there is no explicit clustered index concept — the `CLUSTER` command physically reorders data once, but it is not maintained automatically. InnoDB (MySQL) always clusters data by the primary key.
</details>

<details>
<summary><strong>11. How do you optimize a slow query?</strong></summary>
<br>

Step-by-step approach:

1. **EXPLAIN ANALYZE**: Read the query plan. Look for sequential scans (Seq Scan), high row estimates, and sort operations on large datasets.
2. **Add missing indexes**: If WHERE/JOIN columns lack indexes, create them.
3. **Rewrite the query**: Replace subqueries with JOINs. Use EXISTS instead of IN for large subsets. Avoid SELECT * — select only needed columns.
4. **Avoid functions on indexed columns**: `WHERE YEAR(created_at) = 2026` cannot use an index on `created_at`. Rewrite as `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`.
5. **Pagination**: Use keyset pagination (`WHERE id > last_seen_id LIMIT 20`) instead of `OFFSET` (which scans and discards rows).
6. **Statistics**: Run `ANALYZE` (PostgreSQL) to update table statistics so the planner makes better decisions.
</details>

<details>
<summary><strong>12. What is a covering index?</strong></summary>
<br>

A covering index contains all the columns needed to satisfy a query, so the database never needs to access the actual table data (no "heap fetch" or "bookmark lookup"). The query is answered entirely from the index.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL uses `INCLUDE` for non-key columns. MySQL uses composite indexes where extra columns are appended. Covering indexes can dramatically improve read performance for specific query patterns.
</details>

## Advanced Concepts

<details>
<summary><strong>13. What is a Common Table Expression (CTE) and when would you use one?</strong></summary>
<br>

A CTE is a named temporary result set defined within a single query using `WITH`:

```sql
WITH high_spenders AS (
    SELECT customer_id, SUM(total) as total_spent
    FROM orders
    GROUP BY customer_id
    HAVING SUM(total) > 10000
)
SELECT c.name, hs.total_spent
FROM customers c
JOIN high_spenders hs ON c.id = hs.customer_id;
```

Use CTEs for: readability (breaking complex queries into logical steps), recursive queries (hierarchical data like org charts), and replacing complex subqueries. Note: In PostgreSQL < 12, CTEs act as optimization fences (not inlined). In PostgreSQL 12+, non-recursive CTEs can be inlined.
</details>

<details>
<summary><strong>14. What are window functions and how do they differ from GROUP BY?</strong></summary>
<br>

Window functions compute a value across a set of rows **without collapsing them into a single row** (unlike GROUP BY).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

Common window functions: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. Essential for analytics, reporting, and pagination.
</details>

<details>
<summary><strong>15. What is a deadlock and how do you prevent it?</strong></summary>
<br>

A deadlock occurs when two transactions wait for each other to release locks, creating a circular dependency. Neither can proceed.

Example:
- Transaction A locks Row 1, wants Row 2.
- Transaction B locks Row 2, wants Row 1.
- Both wait forever.

The database detects deadlocks and kills one transaction (the "victim"), rolling it back.

Prevention:
1. **Consistent lock ordering**: Always lock resources in the same order across all transactions.
2. **Short transactions**: Hold locks for the minimum time necessary.
3. **Lock timeouts**: Set `lock_timeout` so transactions fail fast instead of waiting indefinitely.
4. **Reduce isolation level**: Lower isolation levels require fewer locks.
</details>

## Security

<details>
<summary><strong>16. What is SQL injection and how do you prevent it?</strong></summary>
<br>

SQL injection occurs when user input is concatenated directly into a SQL query, allowing an attacker to modify the query logic.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

Prevention:
1. **Parameterized queries** (prepared statements) — the #1 defense. Input is treated as data, never as SQL.
2. **ORM** (SQLAlchemy, Django ORM) — generates parameterized queries automatically.
3. **Input validation** — whitelist expected formats (numeric IDs, email patterns).
4. **Principle of least privilege** — database user should only have SELECT/INSERT/UPDATE on needed tables, never DROP or GRANT.
</details>

<details>
<summary><strong>17. What is the principle of least privilege in database security?</strong></summary>
<br>

Each database user or application should have only the minimum permissions needed to perform its job.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

Never use the database superuser (postgres, root) for application connections. If the application is compromised via SQL injection, the attacker only gets the permissions of the limited user.
</details>

## Practical Scenarios

<details>
<summary><strong>18. How do you design a schema for a many-to-many relationship?</strong></summary>
<br>

Use a **junction table** (also called bridge table or associative table):

```sql
CREATE TABLE students (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100)
);

CREATE TABLE courses (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200)
);

-- Junction table
CREATE TABLE enrollments (
    student_id INT REFERENCES students(id),
    course_id INT REFERENCES courses(id),
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    grade VARCHAR(2),
    PRIMARY KEY (student_id, course_id)
);
```

The junction table holds the foreign keys to both tables, creating the many-to-many relationship. It can also hold relationship-specific attributes (enrolled_at, grade).
</details>

<details>
<summary><strong>19. Write a query to find the second highest salary in each department.</strong></summary>
<br>

```sql
-- Using window function (cleanest approach)
WITH ranked AS (
    SELECT name, department, salary,
           DENSE_RANK() OVER (
               PARTITION BY department
               ORDER BY salary DESC
           ) as rank
    FROM employees
)
SELECT name, department, salary
FROM ranked
WHERE rank = 2;
```

Why `DENSE_RANK` over `ROW_NUMBER`: If two employees tie for the highest salary, `DENSE_RANK` correctly assigns rank 2 to the next salary. `ROW_NUMBER` would arbitrarily assign ranks 1 and 2 to the tied employees.
</details>

<details>
<summary><strong>20. How do you handle database migrations in production?</strong></summary>
<br>

1. **Use a migration tool**: Flyway, Liquibase (Java), Alembic (Python/SQLAlchemy), Django migrations, Prisma Migrate. Never run raw DDL in production.
2. **Version control migrations**: Each migration is a numbered file in the repo. Migrations are applied in order and tracked in a metadata table.
3. **Backward-compatible changes**: Add new columns as nullable first. Deploy the application code that uses the new column. Then add a NOT NULL constraint if needed. Never rename or drop columns without a deprecation period.
4. **Test migrations**: Run against a staging copy of production data before applying to production.
5. **Rollback plan**: Every migration should have a corresponding rollback script. Test rollbacks before deployment.
6. **Zero-downtime**: Use techniques like expanding/contracting patterns, ghost tables (gh-ost for MySQL), or online DDL (PostgreSQL's non-blocking ALTER TABLE).
</details>
