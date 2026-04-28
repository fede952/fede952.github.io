---
title: "SQL 및 데이터베이스 설계 면접 질문 (시니어 레벨)"
description: "시니어 백엔드 및 DBA 역할을 위한 20가지 고급 SQL 및 데이터베이스 면접 질문. 쿼리 최적화, 정규화, 인덱싱, 트랜잭션, ACID 속성, 보안을 다룹니다."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["sql 쿼리 면접 질문", "데이터베이스 정규화", "acid 속성", "sql 인젝션 방지", "데이터베이스 인덱스 면접", "sql 조인 질문", "postgresql 면접", "mysql 면접 질문", "데이터베이스 설계 패턴", "sql 성능 튜닝"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL 및 데이터베이스 설계 면접 질문 (시니어 레벨)",
    "description": "최적화, 정규화, 인덱싱, 트랜잭션, 보안을 다루는 20가지 고급 SQL 및 데이터베이스 면접 질문.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

SQL은 데이터의 언어이며, 데이터베이스는 모든 애플리케이션의 근간입니다. 시니어 레벨 면접은 효율적인 쿼리 작성, 정규화된 스키마 설계, 트랜잭션 격리 이해, 인덱스를 통한 성능 최적화, SQL 인젝션 방지 능력을 테스트합니다. 백엔드 엔지니어, DBA, 데이터 엔지니어, 보안 분석가 등 어떤 역할이든, 이 20가지 질문은 면접관들이 일관되게 묻는 개념을 다루고 있습니다 — 프로덕션 경험을 보여주는 답변과 함께.

**빠른 SQL 참조가 필요하신가요?** 준비하는 동안 [SQL 인젝션 & 데이터베이스 쿼리 치트시트](/cheatsheets/sql-injection-payloads-database/)를 열어두세요.

---

## 쿼리 기초

<details>
<summary><strong>1. SQL 쿼리의 실행 순서는 무엇인가요?</strong></summary>
<br>

SQL 쿼리는 작성 순서대로 실행되지 **않습니다**. 실제 실행 순서는 다음과 같습니다:

1. **FROM** / **JOIN** — 테이블을 식별하고 조인합니다.
2. **WHERE** — 그룹화 전에 행을 필터링합니다.
3. **GROUP BY** — 나머지 행을 그룹화합니다.
4. **HAVING** — 그룹을 필터링합니다 (집계 후).
5. **SELECT** — 반환할 열/표현식을 선택합니다.
6. **DISTINCT** — 중복 행을 제거합니다.
7. **ORDER BY** — 결과를 정렬합니다.
8. **LIMIT** / **OFFSET** — 반환되는 행 수를 제한합니다.

이것이 SELECT에서 정의한 열 별칭을 WHERE 절에서 사용할 수 없는 이유입니다 — WHERE는 SELECT보다 먼저 실행됩니다.
</details>

<details>
<summary><strong>2. WHERE와 HAVING의 차이점을 설명하세요.</strong></summary>
<br>

- **WHERE**는 집계(GROUP BY) **전에** 행을 필터링합니다. 개별 행에서 작동하며 집계 함수를 사용할 수 없습니다.
- **HAVING**은 집계 **후에** 그룹을 필터링합니다. GROUP BY의 결과에서 작동하며 집계 함수를 사용할 수 있습니다.

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

성능: 가능한 경우 WHERE가 항상 선호됩니다 — 비용이 많이 드는 GROUP BY 작업 전에 데이터셋을 줄입니다.
</details>

<details>
<summary><strong>3. INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL OUTER JOIN의 차이점은 무엇인가요?</strong></summary>
<br>

- **INNER JOIN**: **양쪽** 테이블에서 일치하는 값이 있는 행만 반환합니다. 일치하지 않는 행은 제외됩니다.
- **LEFT JOIN**: 왼쪽 테이블의 모든 행과 오른쪽 테이블의 일치하는 행을 반환합니다. 일치하지 않으면 오른쪽 열은 NULL입니다.
- **RIGHT JOIN**: 오른쪽 테이블의 모든 행과 왼쪽 테이블의 일치하는 행을 반환합니다. 일치하지 않으면 왼쪽 열은 NULL입니다.
- **FULL OUTER JOIN**: 양쪽 테이블의 모든 행을 반환합니다. 일치하지 않는 경우 누락된 쪽은 NULL입니다.

실무에서 LEFT JOIN은 약 90%의 경우에 사용됩니다. RIGHT JOIN은 항상 테이블 순서를 바꿔 LEFT JOIN으로 다시 작성할 수 있습니다.
</details>

<details>
<summary><strong>4. UNION과 UNION ALL의 차이점은 무엇인가요?</strong></summary>
<br>

- **UNION**: 두 쿼리의 결과를 결합하고 **중복 행을 제거**합니다. 내부적으로 정렬/중복 제거 작업이 필요합니다.
- **UNION ALL**: **중복을 제거하지 않고** 결과를 결합합니다. 중복 제거가 필요 없으므로 더 빠릅니다.

중복 제거가 특별히 필요하지 않는 한 항상 `UNION ALL`을 사용하세요. `UNION`의 암시적 정렬 작업은 큰 데이터셋에서 비용이 많이 들 수 있습니다.

둘 다 각 SELECT에서 호환 가능한 데이터 타입의 동일한 수의 열이 필요합니다.
</details>

## 데이터베이스 설계

<details>
<summary><strong>5. 데이터베이스 정규화(1NF부터 3NF)를 설명하세요.</strong></summary>
<br>

정규화는 데이터 중복을 줄이고 갱신 이상을 방지합니다:

- **1NF** (제1정규형): 각 열은 원자적(분할 불가능한) 값을 포함합니다. 반복 그룹이 없습니다. 각 행은 고유합니다(기본키를 가집니다).
- **2NF**: 1NF를 충족 + 모든 비키 열이 기본키 **전체**에 의존합니다(복합키의 일부에만 의존하지 않음). 부분 종속성을 제거합니다.
- **3NF**: 2NF를 충족 + 모든 비키 열이 기본키에 **직접** 의존하며, 다른 비키 열에 의존하지 않습니다. 이행 종속성을 제거합니다.

3NF 위반 예시: `(order_id, customer_id, customer_name)` 테이블 — `customer_name`은 `order_id`가 아닌 `customer_id`에 의존합니다. 해결: `customer_name`을 별도의 `customers` 테이블로 이동합니다.
</details>

<details>
<summary><strong>6. 의도적으로 데이터베이스를 비정규화하는 경우는 언제인가요?</strong></summary>
<br>

비정규화가 정당화되는 경우:

1. **읽기 성능이 중요한 경우**: 보고 대시보드, 많은 테이블을 조인하는 분석 쿼리. 집계를 미리 계산하거나 계층 구조를 평탄화하면 쿼리 시 비용이 많이 드는 조인을 피할 수 있습니다.
2. **캐시 레이어**: 주기적으로 갱신되는 구체화된 뷰 또는 요약 테이블.
3. **NoSQL/문서 저장소**: 데이터가 완전한 문서로 저장됩니다(MongoDB). 관련 데이터를 포함시키면 조인이 완전히 불필요해집니다.
4. **이벤트 소싱/CQRS**: 쓰기 모델은 정규화되고, 읽기 모델은 비정규화됩니다.

트레이드오프: 더 빠른 읽기 대신 더 복잡한 쓰기(여러 곳을 업데이트해야 함)와 잠재적인 데이터 불일치.
</details>

<details>
<summary><strong>7. ACID 속성이란 무엇인가요?</strong></summary>
<br>

ACID는 신뢰할 수 있는 데이터베이스 트랜잭션을 보장합니다:

- **원자성(Atomicity)**: 트랜잭션은 전부 아니면 전무입니다. 어떤 부분이 실패하면 전체 트랜잭션이 롤백됩니다. 부분 업데이트가 없습니다.
- **일관성(Consistency)**: 트랜잭션은 데이터베이스를 하나의 유효한 상태에서 다른 유효한 상태로 전환합니다. 모든 제약 조건(외래키, 체크, 트리거)이 충족됩니다.
- **격리성(Isolation)**: 동시 트랜잭션은 서로 간섭하지 않습니다. 각 트랜잭션은 데이터의 일관된 스냅샷을 봅니다.
- **지속성(Durability)**: 트랜잭션이 커밋되면 시스템 장애에도 살아남습니다. 데이터는 비휘발성 저장소(WAL, redo 로그)에 기록됩니다.

ACID는 관계형 데이터베이스(PostgreSQL, MySQL InnoDB)의 핵심 특성입니다. 많은 NoSQL 데이터베이스는 확장성을 위해 일부 ACID 속성을 희생합니다(BASE: Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. 트랜잭션 격리 수준을 설명하세요.</strong></summary>
<br>

가장 느슨한 것부터 가장 엄격한 것까지:

1. **Read Uncommitted**: 다른 트랜잭션의 커밋되지 않은 변경을 읽을 수 있습니다(**더티 리드**). 거의 사용되지 않습니다.
2. **Read Committed** (PostgreSQL 기본값): 커밋된 데이터만 읽습니다. 하지만 같은 행을 다시 읽으면 다른 트랜잭션이 중간에 커밋한 경우 다른 값을 반환할 수 있습니다(**반복 불가능 읽기**).
3. **Repeatable Read** (MySQL InnoDB 기본값): 트랜잭션 내에서 같은 행을 다시 읽으면 항상 같은 값을 반환합니다. 하지만 다른 트랜잭션이 삽입한 새 행이 나타날 수 있습니다(**팬텀 리드**).
4. **Serializable**: 완전한 격리. 트랜잭션이 직렬(순차적)로 실행되는 것처럼 동작합니다. 모든 이상 현상을 방지하지만 가장 높은 성능 비용(잠금/MVCC 오버헤드)이 있습니다.

애플리케이션에 따라 선택하세요: 금융 트랜잭션은 Serializable이 필요합니다; 웹 앱 읽기는 일반적으로 Read Committed를 사용합니다.
</details>

## 인덱싱 및 성능

<details>
<summary><strong>9. 데이터베이스 인덱스란 무엇이며 어떻게 작동하나요?</strong></summary>
<br>

인덱스는 특정 열의 정렬된 복사본과 전체 행에 대한 포인터를 저장하는 별도의 데이터 구조(일반적으로 **B-트리** 또는 **B+ 트리**)입니다. 전체 테이블을 스캔하지 않고(풀 테이블 스캔) 데이터베이스가 행을 찾을 수 있게 합니다.

비유: 책의 색인은 키워드를 페이지 번호에 매핑합니다. 색인 없이는 주제를 찾기 위해 모든 페이지를 읽어야 합니다.

트레이드오프:
- **더 빠른 읽기**: 인덱싱된 열에서 WHERE, JOIN, ORDER BY가 있는 SELECT.
- **더 느린 쓰기**: 모든 INSERT, UPDATE, DELETE에서 인덱스도 업데이트해야 합니다.
- **더 많은 저장 공간**: 인덱스는 인덱싱된 데이터에 비례하는 디스크 공간을 차지합니다.

규칙: WHERE, JOIN ON, ORDER BY, GROUP BY 절에 자주 나타나는 열에 인덱스를 만드세요.
</details>

<details>
<summary><strong>10. 클러스터드 인덱스와 비클러스터드 인덱스의 차이점은 무엇인가요?</strong></summary>
<br>

- **클러스터드 인덱스**: 디스크에서 데이터의 **물리적 순서**를 결정합니다. 테이블은 하나의 클러스터드 인덱스만 가질 수 있습니다(보통 기본키). B-트리의 리프 노드에 실제 데이터 행이 포함됩니다.
- **비클러스터드 인덱스**: 데이터 행에 대한 포인터가 있는 별도의 구조. 테이블은 여러 비클러스터드 인덱스를 가질 수 있습니다. 리프 노드에는 인덱싱된 열 값과 실제 데이터에 대한 참조(행 로케이터)가 포함됩니다.

PostgreSQL에는 명시적인 클러스터드 인덱스 개념이 없습니다 — `CLUSTER` 명령은 데이터를 한 번 물리적으로 재정렬하지만 자동으로 유지되지는 않습니다. InnoDB(MySQL)는 항상 기본키로 데이터를 클러스터링합니다.
</details>

<details>
<summary><strong>11. 느린 쿼리를 어떻게 최적화하나요?</strong></summary>
<br>

단계별 접근법:

1. **EXPLAIN ANALYZE**: 쿼리 계획을 읽습니다. 순차 스캔(Seq Scan), 높은 행 추정치, 큰 데이터셋에서의 정렬 작업을 찾습니다.
2. **누락된 인덱스 추가**: WHERE/JOIN 열에 인덱스가 없으면 만듭니다.
3. **쿼리 재작성**: 서브쿼리를 JOIN으로 교체합니다. 큰 부분집합에는 IN 대신 EXISTS를 사용합니다. SELECT *를 피하고 필요한 열만 선택합니다.
4. **인덱싱된 열에서 함수 사용 피하기**: `WHERE YEAR(created_at) = 2026`은 `created_at`의 인덱스를 사용할 수 없습니다. `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`로 재작성합니다.
5. **페이지네이션**: `OFFSET`(행을 스캔하고 버림) 대신 키셋 페이지네이션(`WHERE id > last_seen_id LIMIT 20`)을 사용합니다.
6. **통계**: `ANALYZE`(PostgreSQL)를 실행하여 테이블 통계를 업데이트하고 플래너가 더 나은 결정을 내리도록 합니다.
</details>

<details>
<summary><strong>12. 커버링 인덱스란 무엇인가요?</strong></summary>
<br>

커버링 인덱스는 쿼리를 충족시키는 데 필요한 모든 열을 포함하므로 데이터베이스가 실제 테이블 데이터에 접근할 필요가 없습니다("힙 페치"나 "북마크 룩업" 없음). 쿼리는 전적으로 인덱스에서 응답됩니다.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL은 비키 열에 `INCLUDE`를 사용합니다. MySQL은 추가 열이 끝에 추가된 복합 인덱스를 사용합니다. 커버링 인덱스는 특정 쿼리 패턴의 읽기 성능을 극적으로 향상시킬 수 있습니다.
</details>

## 고급 개념

<details>
<summary><strong>13. Common Table Expression(CTE)이란 무엇이며 언제 사용하나요?</strong></summary>
<br>

CTE는 `WITH`를 사용하여 단일 쿼리 내에서 정의되는 이름이 있는 임시 결과 집합입니다:

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

CTE 사용 용도: 가독성(복잡한 쿼리를 논리적 단계로 분리), 재귀 쿼리(조직도와 같은 계층적 데이터), 복잡한 서브쿼리 대체. 참고: PostgreSQL 12 미만에서 CTE는 최적화 장벽으로 작동합니다(인라인되지 않음). PostgreSQL 12 이상에서는 비재귀 CTE가 인라인될 수 있습니다.
</details>

<details>
<summary><strong>14. 윈도우 함수란 무엇이며 GROUP BY와 어떻게 다른가요?</strong></summary>
<br>

윈도우 함수는 행 집합에 대해 값을 계산하지만 **행을 단일 행으로 축소하지 않습니다**(GROUP BY와 달리).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

일반적인 윈도우 함수: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. 분석, 보고, 페이지네이션에 필수적입니다.
</details>

<details>
<summary><strong>15. 데드락이란 무엇이며 어떻게 방지하나요?</strong></summary>
<br>

데드락은 두 트랜잭션이 서로 잠금 해제를 기다리며 순환 종속성을 만들 때 발생합니다. 어느 쪽도 진행할 수 없습니다.

예시:
- 트랜잭션 A가 행 1을 잠그고, 행 2를 원함.
- 트랜잭션 B가 행 2를 잠그고, 행 1을 원함.
- 둘 다 영원히 대기.

데이터베이스는 데드락을 감지하고 하나의 트랜잭션("희생자")을 종료하여 롤백합니다.

방지:
1. **일관된 잠금 순서**: 모든 트랜잭션에서 항상 같은 순서로 리소스를 잠급니다.
2. **짧은 트랜잭션**: 필요한 최소 시간 동안만 잠금을 유지합니다.
3. **잠금 타임아웃**: `lock_timeout`을 설정하여 트랜잭션이 무한히 대기하는 대신 빠르게 실패하도록 합니다.
4. **격리 수준 낮추기**: 낮은 격리 수준은 더 적은 잠금을 필요로 합니다.
</details>

## 보안

<details>
<summary><strong>16. SQL 인젝션이란 무엇이며 어떻게 방지하나요?</strong></summary>
<br>

SQL 인젝션은 사용자 입력이 SQL 쿼리에 직접 연결될 때 발생하며, 공격자가 쿼리 로직을 수정할 수 있게 합니다.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

방지:
1. **매개변수화된 쿼리**(준비된 문장) — 최우선 방어. 입력은 데이터로 처리되며 SQL로 처리되지 않습니다.
2. **ORM**(SQLAlchemy, Django ORM) — 자동으로 매개변수화된 쿼리를 생성합니다.
3. **입력 유효성 검사** — 예상 형식의 화이트리스트(숫자 ID, 이메일 패턴).
4. **최소 권한 원칙** — 데이터베이스 사용자는 필요한 테이블에 대한 SELECT/INSERT/UPDATE만 가져야 하며, DROP이나 GRANT는 절대 안 됩니다.
</details>

<details>
<summary><strong>17. 데이터베이스 보안에서 최소 권한 원칙이란 무엇인가요?</strong></summary>
<br>

각 데이터베이스 사용자 또는 애플리케이션은 자신의 업무를 수행하는 데 필요한 최소한의 권한만 가져야 합니다.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

애플리케이션 연결에 데이터베이스 슈퍼유저(postgres, root)를 절대 사용하지 마세요. 애플리케이션이 SQL 인젝션으로 침해되면, 공격자는 제한된 사용자의 권한만 얻게 됩니다.
</details>

## 실전 시나리오

<details>
<summary><strong>18. 다대다 관계의 스키마를 어떻게 설계하나요?</strong></summary>
<br>

**연결 테이블**(브리지 테이블 또는 연관 테이블이라고도 함)을 사용합니다:

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

연결 테이블은 양쪽 테이블에 대한 외래키를 보유하여 다대다 관계를 생성합니다. 관계 특정 속성(enrolled_at, grade)도 보유할 수 있습니다.
</details>

<details>
<summary><strong>19. 각 부서에서 두 번째로 높은 급여를 찾는 쿼리를 작성하세요.</strong></summary>
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

`ROW_NUMBER` 대신 `DENSE_RANK`를 사용하는 이유: 두 직원이 최고 급여에서 동점인 경우, `DENSE_RANK`는 다음 급여에 올바르게 순위 2를 할당합니다. `ROW_NUMBER`는 동점 직원에게 임의로 순위 1과 2를 할당합니다.
</details>

<details>
<summary><strong>20. 프로덕션에서 데이터베이스 마이그레이션을 어떻게 처리하나요?</strong></summary>
<br>

1. **마이그레이션 도구 사용**: Flyway, Liquibase(Java), Alembic(Python/SQLAlchemy), Django migrations, Prisma Migrate. 프로덕션에서 절대 원시 DDL을 실행하지 마세요.
2. **마이그레이션 버전 관리**: 각 마이그레이션은 리포지토리의 번호가 매겨진 파일입니다. 마이그레이션은 순서대로 적용되고 메타데이터 테이블에서 추적됩니다.
3. **하위 호환 변경**: 새 열을 먼저 nullable로 추가합니다. 새 열을 사용하는 애플리케이션 코드를 배포합니다. 필요한 경우 NOT NULL 제약 조건을 추가합니다. 지원 중단 기간 없이 열 이름을 바꾸거나 삭제하지 마세요.
4. **마이그레이션 테스트**: 프로덕션에 적용하기 전에 프로덕션 데이터의 스테이징 복사본에 대해 실행합니다.
5. **롤백 계획**: 모든 마이그레이션에는 해당 롤백 스크립트가 있어야 합니다. 배포 전에 롤백을 테스트합니다.
6. **제로 다운타임**: 확장/축소 패턴, 고스트 테이블(MySQL용 gh-ost), 온라인 DDL(PostgreSQL의 비차단 ALTER TABLE)과 같은 기법을 사용합니다.
</details>
