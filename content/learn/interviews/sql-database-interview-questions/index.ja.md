---
title: "SQL・データベース設計 面接質問集（シニアレベル）"
description: "シニアバックエンドおよびDBA向けの20の高度なSQLとデータベースの面接質問。クエリ最適化、正規化、インデックス、トランザクション、ACID特性、セキュリティをカバーします。"
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["sqlクエリ面接質問", "データベース正規化", "acid特性", "sqlインジェクション防止", "データベースインデックス面接", "sql結合質問", "postgresql面接", "mysql面接質問", "データベース設計パターン", "sqlパフォーマンスチューニング"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL・データベース設計 面接質問集（シニアレベル）",
    "description": "最適化、正規化、インデックス、トランザクション、セキュリティをカバーする20の高度なSQLとデータベースの面接質問。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ja"
  }
---

## システム初期化

SQLはデータの言語であり、データベースはすべてのアプリケーションの基盤です。シニアレベルの面接では、効率的なクエリの作成、正規化されたスキーマの設計、トランザクション分離の理解、インデックスによるパフォーマンス最適化、SQLインジェクションの防止能力がテストされます。バックエンドエンジニア、DBA、データエンジニア、セキュリティアナリストのいずれの役割であっても、これらの20の質問は面接官が一貫して質問する概念をカバーしています — 本番環境での経験を示す回答付きです。

**SQLのクイックリファレンスが必要ですか？** 準備中は[SQLインジェクション＆データベースクエリチートシート](/cheatsheets/sql-injection-payloads-database/)を開いておきましょう。

---

## クエリの基礎

<details>
<summary><strong>1. SQLクエリの実行順序は何ですか？</strong></summary>
<br>

SQLクエリは、記述した順序では実行**されません**。実際の実行順序は以下の通りです：

1. **FROM** / **JOIN** — テーブルを特定し結合する。
2. **WHERE** — グループ化前に行をフィルタリングする。
3. **GROUP BY** — 残りの行をグループ化する。
4. **HAVING** — グループをフィルタリングする（集約後）。
5. **SELECT** — 返す列/式を選択する。
6. **DISTINCT** — 重複行を削除する。
7. **ORDER BY** — 結果をソートする。
8. **LIMIT** / **OFFSET** — 返す行数を制限する。

このため、SELECTで定義した列エイリアスをWHERE句で使用できません — WHEREはSELECTの前に実行されるからです。
</details>

<details>
<summary><strong>2. WHEREとHAVINGの違いを説明してください。</strong></summary>
<br>

- **WHERE**は集約（GROUP BY）の**前に**行をフィルタリングします。個々の行に対して動作し、集約関数は使用できません。
- **HAVING**は集約の**後に**グループをフィルタリングします。GROUP BYの結果に対して動作し、集約関数を使用できます。

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

パフォーマンス：可能な場合はWHEREが常に好ましいです — コストの高いGROUP BY操作の前にデータセットを削減します。
</details>

<details>
<summary><strong>3. INNER JOIN、LEFT JOIN、RIGHT JOIN、FULL OUTER JOINの違いは何ですか？</strong></summary>
<br>

- **INNER JOIN**：**両方の**テーブルで一致する値を持つ行のみを返します。一致しない行は除外されます。
- **LEFT JOIN**：左テーブルのすべての行と、右テーブルの一致する行を返します。一致がない場合、右側の列はNULLになります。
- **RIGHT JOIN**：右テーブルのすべての行と、左テーブルの一致する行を返します。一致がない場合、左側の列はNULLになります。
- **FULL OUTER JOIN**：両方のテーブルのすべての行を返します。一致がない場合、欠落している側はNULLになります。

実務では、LEFT JOINが約90%の場面で使用されます。RIGHT JOINはテーブルの順序を入れ替えることで常にLEFT JOINに書き換えることができます。
</details>

<details>
<summary><strong>4. UNIONとUNION ALLの違いは何ですか？</strong></summary>
<br>

- **UNION**：2つのクエリの結果を結合し、**重複行を削除**します。内部的にソート/重複排除操作が必要です。
- **UNION ALL**：**重複を削除せずに**結果を結合します。重複排除が不要なため高速です。

重複排除が具体的に必要でない限り、常に`UNION ALL`を使用してください。`UNION`の暗黙的なソート操作は大規模なデータセットでコストが高くなる可能性があります。

両方とも、各SELECTで互換性のあるデータ型を持つ同じ数の列が必要です。
</details>

## データベース設計

<details>
<summary><strong>5. データベースの正規化（第1正規形から第3正規形）を説明してください。</strong></summary>
<br>

正規化はデータの冗長性を削減し、更新異常を防ぎます：

- **1NF**（第1正規形）：各列にはアトミック（不可分）な値が含まれます。繰り返しグループはありません。各行は一意です（主キーを持ちます）。
- **2NF**：1NFを満たし、すべての非キー列が主キーの**全体**に依存します（複合キーの一部だけではなく）。部分依存を排除します。
- **3NF**：2NFを満たし、すべての非キー列が主キーに**直接**依存し、他の非キー列には依存しません。推移依存を排除します。

3NF違反の例：`(order_id, customer_id, customer_name)`のテーブル — `customer_name`は`order_id`ではなく`customer_id`に依存しています。解決策：`customer_name`を別の`customers`テーブルに移動します。
</details>

<details>
<summary><strong>6. データベースを意図的に非正規化するのはどのような場合ですか？</strong></summary>
<br>

非正規化が正当化されるのは以下の場合です：

1. **読み取りパフォーマンスが重要な場合**：レポートダッシュボード、多くのテーブルを結合する分析クエリ。集約の事前計算や階層の平坦化により、クエリ時のコストの高い結合を回避します。
2. **キャッシュレイヤー**：定期的に更新されるマテリアライズドビューまたはサマリーテーブル。
3. **NoSQL/ドキュメントストア**：データが完全なドキュメントとして保存されます（MongoDB）。関連データの埋め込みにより結合が完全に不要になります。
4. **イベントソーシング/CQRS**：書き込みモデルは正規化され、読み取りモデルは非正規化されます。

トレードオフ：より高速な読み取りと引き換えに、より複雑な書き込み（複数の場所を更新する必要がある）とデータの不整合の可能性があります。
</details>

<details>
<summary><strong>7. ACID特性とは何ですか？</strong></summary>
<br>

ACIDは信頼性の高いデータベーストランザクションを保証します：

- **原子性（Atomicity）**：トランザクションは「全か無か」です。いずれかの部分が失敗した場合、トランザクション全体がロールバックされます。部分的な更新はありません。
- **一貫性（Consistency）**：トランザクションはデータベースを一つの有効な状態から別の有効な状態に移行させます。すべての制約（外部キー、チェック、トリガー）が満たされます。
- **分離性（Isolation）**：同時実行されるトランザクションは互いに干渉しません。各トランザクションはデータの一貫したスナップショットを見ます。
- **耐久性（Durability）**：トランザクションがコミットされると、システム障害に耐えます。データは不揮発性ストレージ（WAL、redoログ）に書き込まれます。

ACIDはリレーショナルデータベース（PostgreSQL、MySQL InnoDB）の決定的な特徴です。多くのNoSQLデータベースはスケーラビリティのためにいくつかのACID特性を犠牲にしています（BASE：Basically Available、Soft state、Eventually consistent）。
</details>

<details>
<summary><strong>8. トランザクション分離レベルを説明してください。</strong></summary>
<br>

最も緩いものから最も厳格なものまで：

1. **Read Uncommitted**：他のトランザクションの未コミットの変更を読み取ることができます（**ダーティリード**）。ほとんど使用されません。
2. **Read Committed**（PostgreSQLのデフォルト）：コミットされたデータのみを読み取ります。ただし、他のトランザクションがその間にコミットした場合、同じ行を再読み取りすると異なる値が返される可能性があります（**ノンリピータブルリード**）。
3. **Repeatable Read**（MySQL InnoDBのデフォルト）：トランザクション内で同じ行を再読み取りすると常に同じ値が返されます。ただし、他のトランザクションによって挿入された新しい行が表示される場合があります（**ファントムリード**）。
4. **Serializable**：完全な分離。トランザクションはシリアル（逐次的）に実行されるかのように動作します。すべての異常を防止しますが、最も高いパフォーマンスコスト（ロック/MVCCオーバーヘッド）があります。

アプリケーションに応じて選択してください：金融トランザクションにはSerializableが必要です。WebアプリケーションのリードにはRead Committedが一般的に使用されます。
</details>

## インデックスとパフォーマンス

<details>
<summary><strong>9. データベースインデックスとは何で、どのように機能しますか？</strong></summary>
<br>

インデックスは、特定の列のソートされたコピーと完全な行へのポインタを格納する別個のデータ構造（通常は**B木**または**B+木**）です。テーブル全体をスキャンすることなく（フルテーブルスキャン）、データベースが行を見つけることを可能にします。

例え：本の索引はキーワードをページ番号にマッピングします。索引がなければ、トピックを見つけるためにすべてのページを読む必要があります。

トレードオフ：
- **より高速な読み取り**：インデックス付き列でのWHERE、JOIN、ORDER BY付きSELECT。
- **より遅い書き込み**：すべてのINSERT、UPDATE、DELETEでインデックスも更新する必要があります。
- **より多いストレージ**：インデックスはインデックス付きデータに比例したディスクスペースを占有します。

ルール：WHERE、JOIN ON、ORDER BY、GROUP BY句に頻繁に現れる列にインデックスを作成してください。
</details>

<details>
<summary><strong>10. クラスター化インデックスと非クラスター化インデックスの違いは何ですか？</strong></summary>
<br>

- **クラスター化インデックス**：ディスク上のデータの**物理的な順序**を決定します。テーブルは1つのクラスター化インデックスのみ持つことができます（通常は主キー）。B木のリーフノードには実際のデータ行が含まれます。
- **非クラスター化インデックス**：データ行へのポインタを持つ別個の構造。テーブルは複数の非クラスター化インデックスを持つことができます。リーフノードにはインデックス付き列の値と実際のデータへの参照（行ロケータ）が含まれます。

PostgreSQLには明示的なクラスター化インデックスの概念はありません — `CLUSTER`コマンドは一度だけデータを物理的に並べ替えますが、自動的には維持されません。InnoDB（MySQL）は常に主キーでデータをクラスター化します。
</details>

<details>
<summary><strong>11. 遅いクエリをどのように最適化しますか？</strong></summary>
<br>

段階的なアプローチ：

1. **EXPLAIN ANALYZE**：クエリプランを読みます。シーケンシャルスキャン（Seq Scan）、高い行数の見積もり、大きなデータセットでのソート操作を探します。
2. **不足しているインデックスを追加**：WHERE/JOIN列にインデックスがない場合、作成します。
3. **クエリを書き換え**：サブクエリをJOINに置き換えます。大きなサブセットにはINの代わりにEXISTSを使用します。SELECT *を避け、必要な列のみを選択します。
4. **インデックス付き列での関数を避ける**：`WHERE YEAR(created_at) = 2026`は`created_at`のインデックスを使用できません。`WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`に書き換えます。
5. **ページネーション**：`OFFSET`（行をスキャンして破棄する）の代わりに、キーセットページネーション（`WHERE id > last_seen_id LIMIT 20`）を使用します。
6. **統計情報**：`ANALYZE`（PostgreSQL）を実行してテーブル統計を更新し、プランナーがより良い判断を行えるようにします。
</details>

<details>
<summary><strong>12. カバリングインデックスとは何ですか？</strong></summary>
<br>

カバリングインデックスは、クエリを満たすために必要なすべての列を含んでいるため、データベースが実際のテーブルデータにアクセスする必要がありません（「ヒープフェッチ」や「ブックマークルックアップ」なし）。クエリは完全にインデックスから回答されます。

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQLは非キー列に`INCLUDE`を使用します。MySQLは追加の列を末尾に追加した複合インデックスを使用します。カバリングインデックスは特定のクエリパターンの読み取りパフォーマンスを劇的に向上させることができます。
</details>

## 高度な概念

<details>
<summary><strong>13. Common Table Expression（CTE）とは何で、いつ使用しますか？</strong></summary>
<br>

CTEは`WITH`を使用して単一のクエリ内で定義される名前付きの一時的な結果セットです：

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

CTEの用途：可読性（複雑なクエリを論理的なステップに分割）、再帰クエリ（組織図のような階層データ）、複雑なサブクエリの置き換え。注意：PostgreSQL 12未満では、CTEは最適化バリアとして機能します（インライン化されません）。PostgreSQL 12以降では、非再帰CTEはインライン化できます。
</details>

<details>
<summary><strong>14. ウィンドウ関数とは何で、GROUP BYとどう違いますか？</strong></summary>
<br>

ウィンドウ関数は、行のセットに対して値を計算しますが、**行を1つの行にまとめません**（GROUP BYとは異なります）。

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

一般的なウィンドウ関数：`ROW_NUMBER()`、`RANK()`、`DENSE_RANK()`、`LAG()`、`LEAD()`、`SUM() OVER()`、`AVG() OVER()`。分析、レポート、ページネーションに不可欠です。
</details>

<details>
<summary><strong>15. デッドロックとは何で、どのように防止しますか？</strong></summary>
<br>

デッドロックは、2つのトランザクションが互いにロックの解放を待ち、循環依存が発生した場合に起こります。どちらも進行できません。

例：
- トランザクションAが行1をロックし、行2を要求。
- トランザクションBが行2をロックし、行1を要求。
- 両方が永遠に待機。

データベースはデッドロックを検出し、1つのトランザクション（「犠牲者」）を終了してロールバックします。

防止策：
1. **一貫したロック順序**：すべてのトランザクションで常に同じ順序でリソースをロックします。
2. **短いトランザクション**：必要最小限の時間だけロックを保持します。
3. **ロックタイムアウト**：`lock_timeout`を設定して、無期限に待つ代わりにトランザクションを素早く失敗させます。
4. **分離レベルを下げる**：低い分離レベルはより少ないロックを必要とします。
</details>

## セキュリティ

<details>
<summary><strong>16. SQLインジェクションとは何で、どのように防止しますか？</strong></summary>
<br>

SQLインジェクションは、ユーザー入力がSQLクエリに直接連結される場合に発生し、攻撃者がクエリロジックを変更できるようになります。

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

防止策：
1. **パラメータ化クエリ**（プリペアドステートメント）— 最重要の防御。入力はデータとして扱われ、SQLとしては扱われません。
2. **ORM**（SQLAlchemy、Django ORM）— 自動的にパラメータ化クエリを生成します。
3. **入力検証** — 期待されるフォーマットのホワイトリスト（数値ID、メールパターン）。
4. **最小権限の原則** — データベースユーザーは必要なテーブルに対するSELECT/INSERT/UPDATEのみを持ち、DROPやGRANTは決して持たないようにします。
</details>

<details>
<summary><strong>17. データベースセキュリティにおける最小権限の原則とは何ですか？</strong></summary>
<br>

各データベースユーザーまたはアプリケーションは、その職務を遂行するために必要な最小限の権限のみを持つべきです。

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

アプリケーション接続にデータベースのスーパーユーザー（postgres、root）を使用しないでください。アプリケーションがSQLインジェクションで侵害された場合、攻撃者は制限されたユーザーの権限のみを取得します。
</details>

## 実践的なシナリオ

<details>
<summary><strong>18. 多対多の関係のスキーマをどのように設計しますか？</strong></summary>
<br>

**中間テーブル**（ブリッジテーブルまたは連関テーブルとも呼ばれます）を使用します：

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

中間テーブルは両方のテーブルへの外部キーを保持し、多対多の関係を作成します。関係固有の属性（enrolled_at、grade）も保持できます。
</details>

<details>
<summary><strong>19. 各部門で2番目に高い給与を見つけるクエリを書いてください。</strong></summary>
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

`ROW_NUMBER`ではなく`DENSE_RANK`を使う理由：2人の従業員が最高給与で同点の場合、`DENSE_RANK`は次の給与に正しくランク2を割り当てます。`ROW_NUMBER`は同点の従業員にランク1と2を任意に割り当てます。
</details>

<details>
<summary><strong>20. 本番環境でのデータベースマイグレーションをどのように管理しますか？</strong></summary>
<br>

1. **マイグレーションツールを使用**：Flyway、Liquibase（Java）、Alembic（Python/SQLAlchemy）、Django migrations、Prisma Migrate。本番環境で生のDDLを実行しないでください。
2. **マイグレーションのバージョン管理**：各マイグレーションはリポジトリ内の番号付きファイルです。マイグレーションは順序通りに適用され、メタデータテーブルで追跡されます。
3. **後方互換性のある変更**：まず新しい列をnullableとして追加します。新しい列を使用するアプリケーションコードをデプロイします。必要に応じてNOT NULL制約を追加します。非推奨期間なしに列の名前変更や削除を行わないでください。
4. **マイグレーションのテスト**：本番環境に適用する前に、本番データのステージングコピーに対して実行します。
5. **ロールバック計画**：各マイグレーションには対応するロールバックスクリプトが必要です。デプロイ前にロールバックをテストします。
6. **ゼロダウンタイム**：拡張/縮小パターン、ゴーストテーブル（MySQLのgh-ost）、またはオンラインDDL（PostgreSQLのノンブロッキングALTER TABLE）などの技術を使用します。
</details>
