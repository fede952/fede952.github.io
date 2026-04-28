---
title: "Perguntas de Entrevista sobre SQL e Design de Banco de Dados (Nível Sênior)"
description: "20 perguntas avançadas de entrevista sobre SQL e banco de dados para cargos Senior Backend e DBA. Cobre otimização de consultas, normalização, indexação, transações, propriedades ACID e segurança."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["perguntas entrevista consultas sql", "normalização de banco de dados", "propriedades acid", "prevenção de sql injection", "entrevista índices de banco de dados", "perguntas join sql", "entrevista postgresql", "perguntas entrevista mysql", "padrões design de banco de dados", "otimização performance sql"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Perguntas de Entrevista sobre SQL e Design de Banco de Dados (Nível Sênior)",
    "description": "20 perguntas avançadas de entrevista sobre SQL e banco de dados cobrindo otimização, normalização, indexação, transações e segurança.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

SQL é a linguagem dos dados, e bancos de dados são a espinha dorsal de toda aplicação. Entrevistas de nível sênior testam sua capacidade de escrever consultas eficientes, projetar esquemas normalizados, entender isolamento de transações, otimizar performance com índices e prevenir SQL injection. Seja o cargo de Engenheiro Backend, DBA, Engenheiro de Dados ou Analista de Segurança, estas 20 perguntas cobrem os conceitos que entrevistadores perguntam consistentemente — com respostas que demonstram experiência em produção.

**Precisa de uma referência rápida de SQL?** Mantenha nosso [Cheatsheet de SQL Injection e Consultas de Banco de Dados](/cheatsheets/sql-injection-payloads-database/) aberto durante sua preparação.

---

## Fundamentos de Consultas

<details>
<summary><strong>1. Qual é a ordem de execução de uma consulta SQL?</strong></summary>
<br>

As consultas SQL **não** são executadas na ordem em que você as escreve. A ordem real de execução é:

1. **FROM** / **JOIN** — identifica as tabelas e as une.
2. **WHERE** — filtra linhas antes do agrupamento.
3. **GROUP BY** — agrupa as linhas restantes.
4. **HAVING** — filtra grupos (após a agregação).
5. **SELECT** — escolhe quais colunas/expressões retornar.
6. **DISTINCT** — remove linhas duplicadas.
7. **ORDER BY** — ordena os resultados.
8. **LIMIT** / **OFFSET** — restringe o número de linhas retornadas.

É por isso que você não pode usar um alias de coluna definido no SELECT dentro de uma cláusula WHERE — WHERE é executado antes do SELECT.
</details>

<details>
<summary><strong>2. Explique a diferença entre WHERE e HAVING.</strong></summary>
<br>

- **WHERE** filtra linhas **antes** da agregação (GROUP BY). Opera em linhas individuais e não pode usar funções de agregação.
- **HAVING** filtra grupos **após** a agregação. Opera nos resultados do GROUP BY e pode usar funções de agregação.

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

Performance: WHERE é sempre preferível quando possível — reduz o conjunto de dados antes da operação custosa de GROUP BY.
</details>

<details>
<summary><strong>3. Qual é a diferença entre INNER JOIN, LEFT JOIN, RIGHT JOIN e FULL OUTER JOIN?</strong></summary>
<br>

- **INNER JOIN**: Retorna apenas linhas que têm valores correspondentes em **ambas** as tabelas. Linhas sem correspondência são excluídas.
- **LEFT JOIN**: Retorna todas as linhas da tabela esquerda e linhas correspondentes da tabela direita. Se não houver correspondência, as colunas da direita são NULL.
- **RIGHT JOIN**: Retorna todas as linhas da tabela direita e linhas correspondentes da tabela esquerda. Se não houver correspondência, as colunas da esquerda são NULL.
- **FULL OUTER JOIN**: Retorna todas as linhas de ambas as tabelas. Onde não há correspondência, o lado ausente é NULL.

Na prática, LEFT JOIN é usado cerca de 90% das vezes. RIGHT JOIN sempre pode ser reescrito como LEFT JOIN trocando a ordem das tabelas.
</details>

<details>
<summary><strong>4. Qual é a diferença entre UNION e UNION ALL?</strong></summary>
<br>

- **UNION**: Combina resultados de duas consultas e **remove linhas duplicadas**. Requer uma operação interna de ordenação/deduplicação.
- **UNION ALL**: Combina resultados **sem remover duplicatas**. Mais rápido porque nenhuma deduplicação é necessária.

Sempre use `UNION ALL` a menos que você especificamente precise de deduplicação. A operação implícita de ordenação do `UNION` pode ser custosa em grandes conjuntos de dados.

Ambos requerem o mesmo número de colunas com tipos de dados compatíveis em cada SELECT.
</details>

## Design de Banco de Dados

<details>
<summary><strong>5. Explique a normalização de banco de dados (1NF até 3NF).</strong></summary>
<br>

A normalização reduz a redundância de dados e previne anomalias de atualização:

- **1NF** (Primeira Forma Normal): Cada coluna contém valores atômicos (indivisíveis). Sem grupos repetidos. Cada linha é única (tem uma chave primária).
- **2NF**: Atende a 1NF + cada coluna não-chave depende da chave primária **inteira** (não apenas de parte de uma chave composta). Elimina dependências parciais.
- **3NF**: Atende a 2NF + cada coluna não-chave depende **diretamente** da chave primária, não de outra coluna não-chave. Elimina dependências transitivas.

Exemplo de violação da 3NF: Uma tabela com `(order_id, customer_id, customer_name)` — `customer_name` depende de `customer_id`, não de `order_id`. Solução: Mover `customer_name` para uma tabela `customers` separada.
</details>

<details>
<summary><strong>6. Quando você intencionalmente desnormalizaria um banco de dados?</strong></summary>
<br>

A desnormalização é justificada quando:

1. **A performance de leitura é crítica**: Dashboards de relatórios, consultas analíticas que unem muitas tabelas. Pré-calcular agregados ou achatar hierarquias evita joins custosos no momento da consulta.
2. **Camadas de cache**: Views materializadas ou tabelas de resumo que são atualizadas periodicamente.
3. **NoSQL/Armazenamentos de documentos**: Os dados são armazenados como documentos completos (MongoDB). Incorporar dados relacionados evita joins completamente.
4. **Event sourcing/CQRS**: O modelo de escrita é normalizado, o modelo de leitura é desnormalizado.

O compromisso: leituras mais rápidas ao custo de escritas mais complexas (deve atualizar múltiplos lugares) e potencial inconsistência de dados.
</details>

<details>
<summary><strong>7. O que são as propriedades ACID?</strong></summary>
<br>

ACID garante transações de banco de dados confiáveis:

- **Atomicidade**: Uma transação é tudo-ou-nada. Se qualquer parte falhar, a transação inteira é revertida. Sem atualizações parciais.
- **Consistência**: Uma transação move o banco de dados de um estado válido para outro. Todas as restrições (chaves estrangeiras, checks, triggers) são satisfeitas.
- **Isolamento**: Transações concorrentes não interferem umas nas outras. Cada transação vê um snapshot consistente dos dados.
- **Durabilidade**: Uma vez que uma transação é confirmada, ela sobrevive a falhas do sistema. Os dados são gravados em armazenamento não volátil (WAL, redo logs).

ACID é a característica definidora de bancos de dados relacionais (PostgreSQL, MySQL InnoDB). Muitos bancos de dados NoSQL sacrificam algumas propriedades ACID pela escalabilidade (BASE: Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. Explique os níveis de isolamento de transações.</strong></summary>
<br>

Do menos ao mais rigoroso:

1. **Read Uncommitted**: Pode ler alterações não confirmadas de outras transações (**leituras sujas**). Quase nunca usado.
2. **Read Committed** (padrão do PostgreSQL): Só lê dados confirmados. Mas reler a mesma linha pode retornar valores diferentes se outra transação foi confirmada no meio tempo (**leituras não repetíveis**).
3. **Repeatable Read** (padrão do MySQL InnoDB): Reler a mesma linha sempre retorna o mesmo valor dentro de uma transação. Mas novas linhas inseridas por outras transações podem aparecer (**leituras fantasma**).
4. **Serializable**: Isolamento completo. As transações são executadas como se fossem seriais (uma após a outra). Previne todas as anomalias mas tem o maior custo de performance (overhead de locking/MVCC).

Escolha baseado na aplicação: transações financeiras precisam de Serializable; leituras de aplicações web tipicamente usam Read Committed.
</details>

## Indexação e Performance

<details>
<summary><strong>9. O que é um índice de banco de dados e como funciona?</strong></summary>
<br>

Um índice é uma estrutura de dados separada (tipicamente uma **B-tree** ou **B+ tree**) que armazena uma cópia ordenada de colunas específicas junto com ponteiros para as linhas completas. Permite que o banco de dados encontre linhas sem varrer a tabela inteira (varredura completa de tabela).

Analogia: O índice de um livro mapeia palavras-chave para números de página. Sem ele, você precisa ler cada página para encontrar um tópico.

Compromissos:
- **Leituras mais rápidas**: SELECT com WHERE, JOIN, ORDER BY em colunas indexadas.
- **Escritas mais lentas**: Cada INSERT, UPDATE, DELETE também precisa atualizar o índice.
- **Mais armazenamento**: O índice ocupa espaço em disco proporcional aos dados indexados.

Regra: Indexe colunas que aparecem frequentemente nas cláusulas WHERE, JOIN ON, ORDER BY e GROUP BY.
</details>

<details>
<summary><strong>10. Qual é a diferença entre um índice clustered e non-clustered?</strong></summary>
<br>

- **Índice clustered**: Determina a **ordem física** dos dados no disco. Uma tabela pode ter apenas um índice clustered (geralmente a chave primária). Os nós folha da B-tree contêm as linhas de dados reais.
- **Índice non-clustered**: Uma estrutura separada com ponteiros para as linhas de dados. Uma tabela pode ter múltiplos índices non-clustered. Os nós folha contêm os valores das colunas indexadas e uma referência (localizador de linha) para os dados reais.

No PostgreSQL, não existe conceito explícito de índice clustered — o comando `CLUSTER` reordena fisicamente os dados uma vez, mas não é mantido automaticamente. InnoDB (MySQL) sempre agrupa os dados pela chave primária.
</details>

<details>
<summary><strong>11. Como você otimiza uma consulta lenta?</strong></summary>
<br>

Abordagem passo a passo:

1. **EXPLAIN ANALYZE**: Leia o plano da consulta. Procure por varreduras sequenciais (Seq Scan), estimativas de linhas altas e operações de ordenação em grandes conjuntos de dados.
2. **Adicione índices ausentes**: Se as colunas WHERE/JOIN não têm índices, crie-os.
3. **Reescreva a consulta**: Substitua subconsultas por JOINs. Use EXISTS em vez de IN para grandes subconjuntos. Evite SELECT * — selecione apenas as colunas necessárias.
4. **Evite funções em colunas indexadas**: `WHERE YEAR(created_at) = 2026` não pode usar um índice em `created_at`. Reescreva como `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`.
5. **Paginação**: Use paginação por chave (`WHERE id > last_seen_id LIMIT 20`) em vez de `OFFSET` (que varre e descarta linhas).
6. **Estatísticas**: Execute `ANALYZE` (PostgreSQL) para atualizar as estatísticas da tabela para que o planejador tome melhores decisões.
</details>

<details>
<summary><strong>12. O que é um índice de cobertura?</strong></summary>
<br>

Um índice de cobertura contém todas as colunas necessárias para satisfazer uma consulta, então o banco de dados nunca precisa acessar os dados reais da tabela (sem "heap fetch" ou "bookmark lookup"). A consulta é respondida inteiramente a partir do índice.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL usa `INCLUDE` para colunas não-chave. MySQL usa índices compostos onde colunas extras são adicionadas ao final. Índices de cobertura podem melhorar drasticamente a performance de leitura para padrões de consulta específicos.
</details>

## Conceitos Avançados

<details>
<summary><strong>13. O que é uma Common Table Expression (CTE) e quando você a usaria?</strong></summary>
<br>

Uma CTE é um conjunto de resultados temporário nomeado definido dentro de uma única consulta usando `WITH`:

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

Use CTEs para: legibilidade (dividir consultas complexas em etapas lógicas), consultas recursivas (dados hierárquicos como organogramas) e substituir subconsultas complexas. Nota: No PostgreSQL < 12, CTEs atuam como barreiras de otimização (não são inline). No PostgreSQL 12+, CTEs não recursivas podem ser inline.
</details>

<details>
<summary><strong>14. O que são funções de janela e como elas diferem do GROUP BY?</strong></summary>
<br>

Funções de janela calculam um valor sobre um conjunto de linhas **sem colapsá-las em uma única linha** (ao contrário do GROUP BY).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

Funções de janela comuns: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. Essenciais para análise, relatórios e paginação.
</details>

<details>
<summary><strong>15. O que é um deadlock e como você o previne?</strong></summary>
<br>

Um deadlock ocorre quando duas transações esperam que a outra libere bloqueios, criando uma dependência circular. Nenhuma pode prosseguir.

Exemplo:
- A Transação A bloqueia a Linha 1, quer a Linha 2.
- A Transação B bloqueia a Linha 2, quer a Linha 1.
- Ambas esperam para sempre.

O banco de dados detecta deadlocks e mata uma transação (a "vítima"), revertendo-a.

Prevenção:
1. **Ordem de bloqueio consistente**: Sempre bloqueie recursos na mesma ordem em todas as transações.
2. **Transações curtas**: Mantenha os bloqueios pelo tempo mínimo necessário.
3. **Timeouts de bloqueio**: Configure `lock_timeout` para que as transações falhem rapidamente em vez de esperar indefinidamente.
4. **Reduzir o nível de isolamento**: Níveis de isolamento mais baixos requerem menos bloqueios.
</details>

## Segurança

<details>
<summary><strong>16. O que é SQL injection e como você a previne?</strong></summary>
<br>

SQL injection ocorre quando a entrada do usuário é concatenada diretamente em uma consulta SQL, permitindo que um atacante modifique a lógica da consulta.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

Prevenção:
1. **Consultas parametrizadas** (prepared statements) — a defesa número 1. A entrada é tratada como dado, nunca como SQL.
2. **ORM** (SQLAlchemy, Django ORM) — gera consultas parametrizadas automaticamente.
3. **Validação de entrada** — lista branca de formatos esperados (IDs numéricos, padrões de email).
4. **Princípio do menor privilégio** — o usuário do banco de dados deve ter apenas SELECT/INSERT/UPDATE nas tabelas necessárias, nunca DROP ou GRANT.
</details>

<details>
<summary><strong>17. O que é o princípio do menor privilégio na segurança de banco de dados?</strong></summary>
<br>

Cada usuário de banco de dados ou aplicação deve ter apenas as permissões mínimas necessárias para realizar seu trabalho.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

Nunca use o superusuário do banco de dados (postgres, root) para conexões da aplicação. Se a aplicação for comprometida via SQL injection, o atacante obtém apenas as permissões do usuário limitado.
</details>

## Cenários Práticos

<details>
<summary><strong>18. Como você projeta um esquema para um relacionamento muitos-para-muitos?</strong></summary>
<br>

Use uma **tabela de junção** (também chamada de tabela ponte ou tabela associativa):

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

A tabela de junção contém as chaves estrangeiras para ambas as tabelas, criando o relacionamento muitos-para-muitos. Ela também pode conter atributos específicos do relacionamento (enrolled_at, grade).
</details>

<details>
<summary><strong>19. Escreva uma consulta para encontrar o segundo maior salário em cada departamento.</strong></summary>
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

Por que `DENSE_RANK` em vez de `ROW_NUMBER`: Se dois funcionários empatam com o maior salário, `DENSE_RANK` atribui corretamente o rank 2 ao próximo salário. `ROW_NUMBER` atribuiria arbitrariamente os ranks 1 e 2 aos funcionários empatados.
</details>

<details>
<summary><strong>20. Como você lida com migrações de banco de dados em produção?</strong></summary>
<br>

1. **Use uma ferramenta de migração**: Flyway, Liquibase (Java), Alembic (Python/SQLAlchemy), Django migrations, Prisma Migrate. Nunca execute DDL bruto em produção.
2. **Versione as migrações**: Cada migração é um arquivo numerado no repositório. As migrações são aplicadas em ordem e rastreadas em uma tabela de metadados.
3. **Mudanças retrocompatíveis**: Adicione novas colunas como nullable primeiro. Faça deploy do código da aplicação que usa a nova coluna. Depois adicione uma restrição NOT NULL se necessário. Nunca renomeie ou remova colunas sem um período de depreciação.
4. **Teste as migrações**: Execute contra uma cópia staging dos dados de produção antes de aplicar em produção.
5. **Plano de rollback**: Cada migração deve ter um script de rollback correspondente. Teste os rollbacks antes do deploy.
6. **Zero-downtime**: Use técnicas como padrões de expansão/contração, tabelas fantasma (gh-ost para MySQL) ou DDL online (ALTER TABLE não bloqueante do PostgreSQL).
</details>
