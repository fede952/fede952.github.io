---
title: "SQL与数据库设计面试题（高级水平）"
description: "20道高级SQL和数据库面试题，适用于高级后端和DBA岗位。涵盖查询优化、规范化、索引、事务、ACID属性和安全性。"
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["sql查询面试题", "数据库规范化", "acid属性", "sql注入防御", "数据库索引面试", "sql连接查询", "postgresql面试", "mysql面试题", "数据库设计模式", "sql性能调优"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL与数据库设计面试题（高级水平）",
    "description": "20道高级SQL和数据库面试题，涵盖优化、规范化、索引、事务和安全性。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

SQL是数据的语言，数据库是每个应用程序的基础。高级面试测试你编写高效查询、设计规范化模式、理解事务隔离、使用索引优化性能以及防止SQL注入的能力。无论岗位是后端工程师、DBA、数据工程师还是安全分析师，这20道题涵盖了面试官一致会问到的概念——附有展示生产经验的答案。

**需要快速的SQL参考？** 在准备过程中保持[SQL注入和数据库查询速查表](/cheatsheets/sql-injection-payloads-database/)处于打开状态。

---

## 查询基础

<details>
<summary><strong>1. SQL查询的执行顺序是什么？</strong></summary>
<br>

SQL查询**不是**按照你编写的顺序执行的。实际的执行顺序是：

1. **FROM** / **JOIN** — 识别表并连接它们。
2. **WHERE** — 在分组之前过滤行。
3. **GROUP BY** — 对剩余的行进行分组。
4. **HAVING** — 过滤分组（聚合之后）。
5. **SELECT** — 选择要返回的列/表达式。
6. **DISTINCT** — 去除重复行。
7. **ORDER BY** — 对结果排序。
8. **LIMIT** / **OFFSET** — 限制返回的行数。

这就是为什么你不能在WHERE子句中使用SELECT中定义的列别名——WHERE在SELECT之前执行。
</details>

<details>
<summary><strong>2. 解释WHERE和HAVING的区别。</strong></summary>
<br>

- **WHERE**在聚合（GROUP BY）**之前**过滤行。它作用于单独的行，不能使用聚合函数。
- **HAVING**在聚合**之后**过滤分组。它作用于GROUP BY的结果，可以使用聚合函数。

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

性能：在可能的情况下，WHERE总是更优选的——它在昂贵的GROUP BY操作之前减少数据集。
</details>

<details>
<summary><strong>3. INNER JOIN、LEFT JOIN、RIGHT JOIN和FULL OUTER JOIN有什么区别？</strong></summary>
<br>

- **INNER JOIN**：只返回在**两个**表中都有匹配值的行。不匹配的行被排除。
- **LEFT JOIN**：返回左表的所有行，以及右表的匹配行。如果没有匹配，右侧的列为NULL。
- **RIGHT JOIN**：返回右表的所有行，以及左表的匹配行。如果没有匹配，左侧的列为NULL。
- **FULL OUTER JOIN**：返回两个表的所有行。没有匹配的一侧为NULL。

在实践中，LEFT JOIN大约90%的时间被使用。RIGHT JOIN总是可以通过交换表的顺序重写为LEFT JOIN。
</details>

<details>
<summary><strong>4. UNION和UNION ALL有什么区别？</strong></summary>
<br>

- **UNION**：合并两个查询的结果并**去除重复行**。内部需要排序/去重操作。
- **UNION ALL**：合并结果**不去除重复**。因为不需要去重所以更快。

除非你明确需要去重，否则始终使用`UNION ALL`。`UNION`的隐式排序操作在大数据集上可能代价很高。

两者都要求每个SELECT中具有相同数量的列和兼容的数据类型。
</details>

## 数据库设计

<details>
<summary><strong>5. 解释数据库规范化（1NF到3NF）。</strong></summary>
<br>

规范化减少数据冗余并防止更新异常：

- **1NF**（第一范式）：每列包含原子（不可分割的）值。没有重复组。每行是唯一的（有主键）。
- **2NF**：满足1NF + 每个非键列依赖于**整个**主键（不仅仅是复合键的一部分）。消除部分依赖。
- **3NF**：满足2NF + 每个非键列**直接**依赖于主键，而不是依赖于另一个非键列。消除传递依赖。

3NF违规示例：一个包含`(order_id, customer_id, customer_name)`的表——`customer_name`依赖于`customer_id`，而不是`order_id`。解决方案：将`customer_name`移到单独的`customers`表中。
</details>

<details>
<summary><strong>6. 什么时候会有意对数据库进行反规范化？</strong></summary>
<br>

反规范化在以下情况下是合理的：

1. **读取性能至关重要**：报表仪表板、连接多个表的分析查询。预计算聚合或展平层次结构可以避免查询时昂贵的连接操作。
2. **缓存层**：定期刷新的物化视图或汇总表。
3. **NoSQL/文档存储**：数据存储为完整的文档（MongoDB）。嵌入相关数据完全避免了连接。
4. **事件溯源/CQRS**：写入模型是规范化的，读取模型是反规范化的。

权衡：更快的读取，代价是更复杂的写入（必须更新多个位置）和潜在的数据不一致。
</details>

<details>
<summary><strong>7. 什么是ACID属性？</strong></summary>
<br>

ACID保证可靠的数据库事务：

- **原子性（Atomicity）**：事务是全有或全无的。如果任何部分失败，整个事务将回滚。没有部分更新。
- **一致性（Consistency）**：事务将数据库从一个有效状态转移到另一个有效状态。所有约束（外键、检查、触发器）都得到满足。
- **隔离性（Isolation）**：并发事务不会相互干扰。每个事务看到数据的一致快照。
- **持久性（Durability）**：事务一旦提交，就能在系统崩溃后存活。数据写入非易失性存储（WAL、redo日志）。

ACID是关系数据库（PostgreSQL、MySQL InnoDB）的决定性特征。许多NoSQL数据库为了可扩展性而牺牲了一些ACID属性（BASE：基本可用、软状态、最终一致性）。
</details>

<details>
<summary><strong>8. 解释事务隔离级别。</strong></summary>
<br>

从最宽松到最严格：

1. **Read Uncommitted**：可以读取其他事务未提交的更改（**脏读**）。几乎从不使用。
2. **Read Committed**（PostgreSQL默认）：只读取已提交的数据。但重新读取同一行可能返回不同的值，如果另一个事务在此期间提交了（**不可重复读**）。
3. **Repeatable Read**（MySQL InnoDB默认）：在事务内重新读取同一行总是返回相同的值。但其他事务插入的新行可能会出现（**幻读**）。
4. **Serializable**：完全隔离。事务执行时就像是串行的（一个接一个）。防止所有异常，但性能开销最大（锁/MVCC开销）。

根据应用选择：金融事务需要Serializable；Web应用的读取通常使用Read Committed。
</details>

## 索引与性能

<details>
<summary><strong>9. 什么是数据库索引，它是如何工作的？</strong></summary>
<br>

索引是一个独立的数据结构（通常是**B树**或**B+树**），存储特定列的排序副本以及指向完整行的指针。它使数据库能够在不扫描整个表的情况下找到行（全表扫描）。

类比：书的索引将关键词映射到页码。没有它，你必须阅读每一页才能找到某个主题。

权衡：
- **更快的读取**：在索引列上使用WHERE、JOIN、ORDER BY的SELECT。
- **更慢的写入**：每个INSERT、UPDATE、DELETE也必须更新索引。
- **更多存储**：索引占用与索引数据成比例的磁盘空间。

规则：对频繁出现在WHERE、JOIN ON、ORDER BY和GROUP BY子句中的列建立索引。
</details>

<details>
<summary><strong>10. 聚集索引和非聚集索引有什么区别？</strong></summary>
<br>

- **聚集索引**：决定磁盘上数据的**物理顺序**。一个表只能有一个聚集索引（通常是主键）。B树的叶节点包含实际的数据行。
- **非聚集索引**：一个带有指向数据行指针的独立结构。一个表可以有多个非聚集索引。叶节点包含索引列的值和指向实际数据的引用（行定位器）。

在PostgreSQL中，没有明确的聚集索引概念——`CLUSTER`命令只对数据进行一次物理重排序，但不会自动维护。InnoDB（MySQL）总是按主键对数据进行聚集。
</details>

<details>
<summary><strong>11. 如何优化慢查询？</strong></summary>
<br>

逐步方法：

1. **EXPLAIN ANALYZE**：读取查询计划。查找顺序扫描（Seq Scan）、高行数估计和大数据集上的排序操作。
2. **添加缺失的索引**：如果WHERE/JOIN列没有索引，创建它们。
3. **重写查询**：用JOIN替换子查询。对大子集使用EXISTS而不是IN。避免SELECT *——只选择需要的列。
4. **避免在索引列上使用函数**：`WHERE YEAR(created_at) = 2026`无法使用`created_at`上的索引。重写为`WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`。
5. **分页**：使用键集分页（`WHERE id > last_seen_id LIMIT 20`）而不是`OFFSET`（它会扫描并丢弃行）。
6. **统计信息**：运行`ANALYZE`（PostgreSQL）更新表统计信息，使规划器做出更好的决策。
</details>

<details>
<summary><strong>12. 什么是覆盖索引？</strong></summary>
<br>

覆盖索引包含满足查询所需的所有列，因此数据库永远不需要访问实际的表数据（没有"堆获取"或"书签查找"）。查询完全从索引中获得答案。

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL使用`INCLUDE`来包含非键列。MySQL使用复合索引，将额外的列附加在末尾。覆盖索引可以显著提高特定查询模式的读取性能。
</details>

## 高级概念

<details>
<summary><strong>13. 什么是公共表表达式（CTE），何时使用？</strong></summary>
<br>

CTE是使用`WITH`在单个查询中定义的命名临时结果集：

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

CTE的用途：可读性（将复杂查询分解为逻辑步骤）、递归查询（如组织架构图等层次数据）以及替换复杂子查询。注意：在PostgreSQL 12以下版本中，CTE充当优化屏障（不会内联）。在PostgreSQL 12+中，非递归CTE可以被内联。
</details>

<details>
<summary><strong>14. 什么是窗口函数，它与GROUP BY有何不同？</strong></summary>
<br>

窗口函数对一组行计算值，但**不会将它们折叠为单行**（与GROUP BY不同）。

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

常见窗口函数：`ROW_NUMBER()`、`RANK()`、`DENSE_RANK()`、`LAG()`、`LEAD()`、`SUM() OVER()`、`AVG() OVER()`。对分析、报表和分页至关重要。
</details>

<details>
<summary><strong>15. 什么是死锁，如何预防？</strong></summary>
<br>

死锁发生在两个事务互相等待对方释放锁时，形成循环依赖。两者都无法继续。

示例：
- 事务A锁定行1，想要行2。
- 事务B锁定行2，想要行1。
- 两者永远等待。

数据库检测到死锁并终止一个事务（"受害者"），将其回滚。

预防：
1. **一致的锁定顺序**：在所有事务中始终以相同顺序锁定资源。
2. **短事务**：将锁持有时间减到最少。
3. **锁超时**：设置`lock_timeout`，使事务快速失败而不是无限等待。
4. **降低隔离级别**：较低的隔离级别需要更少的锁。
</details>

## 安全性

<details>
<summary><strong>16. 什么是SQL注入，如何预防？</strong></summary>
<br>

SQL注入发生在用户输入直接拼接到SQL查询中时，允许攻击者修改查询逻辑。

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

预防：
1. **参数化查询**（预编译语句）——第一防线。输入被视为数据，永远不被视为SQL。
2. **ORM**（SQLAlchemy、Django ORM）——自动生成参数化查询。
3. **输入验证**——预期格式的白名单（数字ID、电子邮件模式）。
4. **最小权限原则**——数据库用户应该只有所需表的SELECT/INSERT/UPDATE权限，永远不应有DROP或GRANT。
</details>

<details>
<summary><strong>17. 数据库安全中的最小权限原则是什么？</strong></summary>
<br>

每个数据库用户或应用程序应该只拥有执行其工作所需的最小权限。

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

永远不要使用数据库超级用户（postgres、root）进行应用程序连接。如果应用程序通过SQL注入被攻破，攻击者只能获得受限用户的权限。
</details>

## 实践场景

<details>
<summary><strong>18. 如何为多对多关系设计模式？</strong></summary>
<br>

使用**关联表**（也称为桥接表或关联实体表）：

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

关联表包含指向两个表的外键，创建多对多关系。它还可以包含关系特定的属性（enrolled_at、grade）。
</details>

<details>
<summary><strong>19. 编写查询以找出每个部门中第二高的薪资。</strong></summary>
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

为什么使用`DENSE_RANK`而不是`ROW_NUMBER`：如果两个员工并列最高薪资，`DENSE_RANK`会正确地将排名2分配给下一个薪资。`ROW_NUMBER`会任意地将排名1和2分配给并列的员工。
</details>

<details>
<summary><strong>20. 如何在生产环境中处理数据库迁移？</strong></summary>
<br>

1. **使用迁移工具**：Flyway、Liquibase（Java）、Alembic（Python/SQLAlchemy）、Django migrations、Prisma Migrate。永远不要在生产环境中运行原始DDL。
2. **版本控制迁移**：每个迁移是仓库中的编号文件。迁移按顺序应用并在元数据表中追踪。
3. **向后兼容的更改**：首先将新列添加为nullable。部署使用新列的应用程序代码。然后在需要时添加NOT NULL约束。永远不要在没有弃用期的情况下重命名或删除列。
4. **测试迁移**：在应用到生产环境之前，先在生产数据的staging副本上运行。
5. **回滚计划**：每个迁移都应该有相应的回滚脚本。在部署前测试回滚。
6. **零停机**：使用扩展/收缩模式、ghost表（MySQL的gh-ost）或在线DDL（PostgreSQL的非阻塞ALTER TABLE）等技术。
</details>
