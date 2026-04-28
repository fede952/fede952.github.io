---
title: "Questions d'Entretien SQL et Conception de Bases de Données (Niveau Senior)"
description: "20 questions avancées d'entretien sur SQL et les bases de données pour les rôles Senior Backend et DBA. Couvre l'optimisation des requêtes, la normalisation, l'indexation, les transactions, les propriétés ACID et la sécurité."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["questions entretien requêtes sql", "normalisation base de données", "propriétés acid", "prévention injection sql", "entretien index base de données", "questions jointure sql", "entretien postgresql", "questions entretien mysql", "modèles conception base de données", "optimisation performance sql"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Questions d'Entretien SQL et Conception de Bases de Données (Niveau Senior)",
    "description": "20 questions avancées d'entretien sur SQL et les bases de données couvrant l'optimisation, la normalisation, l'indexation, les transactions et la sécurité.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

SQL est le langage des données, et les bases de données sont l'épine dorsale de chaque application. Les entretiens de niveau senior testent votre capacité à écrire des requêtes efficaces, concevoir des schémas normalisés, comprendre l'isolation des transactions, optimiser les performances avec des index et prévenir les injections SQL. Que le rôle soit Ingénieur Backend, DBA, Ingénieur Data ou Analyste Sécurité, ces 20 questions couvrent les concepts que les recruteurs demandent systématiquement — avec des réponses qui démontrent une expérience en production.

**Besoin d'une référence rapide SQL ?** Gardez notre [Cheatsheet Injection SQL et Requêtes Base de Données](/cheatsheets/sql-injection-payloads-database/) ouvert pendant votre préparation.

---

## Fondamentaux des Requêtes

<details>
<summary><strong>1. Quel est l'ordre d'exécution d'une requête SQL ?</strong></summary>
<br>

Les requêtes SQL ne sont **pas** exécutées dans l'ordre dans lequel vous les écrivez. L'ordre d'exécution réel est :

1. **FROM** / **JOIN** — identifie les tables et les joint.
2. **WHERE** — filtre les lignes avant le regroupement.
3. **GROUP BY** — regroupe les lignes restantes.
4. **HAVING** — filtre les groupes (après l'agrégation).
5. **SELECT** — choisit les colonnes/expressions à retourner.
6. **DISTINCT** — supprime les lignes en double.
7. **ORDER BY** — trie les résultats.
8. **LIMIT** / **OFFSET** — restreint le nombre de lignes retournées.

C'est pourquoi vous ne pouvez pas utiliser un alias de colonne défini dans SELECT dans une clause WHERE — WHERE s'exécute avant SELECT.
</details>

<details>
<summary><strong>2. Expliquez la différence entre WHERE et HAVING.</strong></summary>
<br>

- **WHERE** filtre les lignes **avant** l'agrégation (GROUP BY). Il opère sur les lignes individuelles et ne peut pas utiliser de fonctions d'agrégation.
- **HAVING** filtre les groupes **après** l'agrégation. Il opère sur les résultats de GROUP BY et peut utiliser des fonctions d'agrégation.

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

Performance : WHERE est toujours préférable quand c'est possible — il réduit le jeu de données avant l'opération coûteuse de GROUP BY.
</details>

<details>
<summary><strong>3. Quelle est la différence entre INNER JOIN, LEFT JOIN, RIGHT JOIN et FULL OUTER JOIN ?</strong></summary>
<br>

- **INNER JOIN** : Retourne uniquement les lignes qui ont des valeurs correspondantes dans **les deux** tables. Les lignes sans correspondance sont exclues.
- **LEFT JOIN** : Retourne toutes les lignes de la table gauche, et les lignes correspondantes de la table droite. S'il n'y a pas de correspondance, les colonnes droites sont NULL.
- **RIGHT JOIN** : Retourne toutes les lignes de la table droite, et les lignes correspondantes de la table gauche. S'il n'y a pas de correspondance, les colonnes gauches sont NULL.
- **FULL OUTER JOIN** : Retourne toutes les lignes des deux tables. Là où il n'y a pas de correspondance, le côté manquant est NULL.

En pratique, LEFT JOIN est utilisé environ 90% du temps. RIGHT JOIN peut toujours être réécrit comme un LEFT JOIN en inversant l'ordre des tables.
</details>

<details>
<summary><strong>4. Quelle est la différence entre UNION et UNION ALL ?</strong></summary>
<br>

- **UNION** : Combine les résultats de deux requêtes et **supprime les lignes en double**. Nécessite une opération interne de tri/déduplication.
- **UNION ALL** : Combine les résultats **sans supprimer les doublons**. Plus rapide car aucune déduplication n'est nécessaire.

Utilisez toujours `UNION ALL` sauf si vous avez spécifiquement besoin de déduplication. L'opération de tri implicite de `UNION` peut être coûteuse sur de grands jeux de données.

Les deux nécessitent le même nombre de colonnes avec des types de données compatibles dans chaque SELECT.
</details>

## Conception de Base de Données

<details>
<summary><strong>5. Expliquez la normalisation de base de données (1NF à 3NF).</strong></summary>
<br>

La normalisation réduit la redondance des données et prévient les anomalies de mise à jour :

- **1NF** (Première Forme Normale) : Chaque colonne contient des valeurs atomiques (indivisibles). Pas de groupes répétitifs. Chaque ligne est unique (possède une clé primaire).
- **2NF** : Satisfait la 1NF + chaque colonne non-clé dépend de la clé primaire **entière** (pas seulement d'une partie d'une clé composée). Élimine les dépendances partielles.
- **3NF** : Satisfait la 2NF + chaque colonne non-clé dépend **directement** de la clé primaire, pas d'une autre colonne non-clé. Élimine les dépendances transitives.

Exemple de violation de 3NF : Une table avec `(order_id, customer_id, customer_name)` — `customer_name` dépend de `customer_id`, pas de `order_id`. Solution : Déplacer `customer_name` dans une table `customers` séparée.
</details>

<details>
<summary><strong>6. Quand dénormaliseriez-vous intentionnellement une base de données ?</strong></summary>
<br>

La dénormalisation est justifiée quand :

1. **La performance en lecture est critique** : Tableaux de bord de reporting, requêtes analytiques qui joignent de nombreuses tables. Précalculer les agrégats ou aplatir les hiérarchies évite les jointures coûteuses au moment de la requête.
2. **Couches de cache** : Vues matérialisées ou tables de résumé qui sont rafraîchies périodiquement.
3. **NoSQL/Magasins de documents** : Les données sont stockées comme des documents complets (MongoDB). L'incorporation de données liées évite complètement les jointures.
4. **Event sourcing/CQRS** : Le modèle d'écriture est normalisé, le modèle de lecture est dénormalisé.

Le compromis : des lectures plus rapides au prix d'écritures plus complexes (mise à jour à plusieurs endroits) et d'une potentielle incohérence des données.
</details>

<details>
<summary><strong>7. Quelles sont les propriétés ACID ?</strong></summary>
<br>

ACID garantit des transactions de base de données fiables :

- **Atomicité** : Une transaction est tout-ou-rien. Si une partie échoue, la transaction entière est annulée. Pas de mises à jour partielles.
- **Cohérence** : Une transaction fait passer la base de données d'un état valide à un autre. Toutes les contraintes (clés étrangères, checks, triggers) sont satisfaites.
- **Isolation** : Les transactions concurrentes n'interfèrent pas entre elles. Chaque transaction voit un instantané cohérent des données.
- **Durabilité** : Une fois qu'une transaction est validée, elle survit aux pannes système. Les données sont écrites sur un stockage non volatil (WAL, redo logs).

ACID est la caractéristique déterminante des bases de données relationnelles (PostgreSQL, MySQL InnoDB). De nombreuses bases de données NoSQL sacrifient certaines propriétés ACID pour la scalabilité (BASE : Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. Expliquez les niveaux d'isolation des transactions.</strong></summary>
<br>

Du moins au plus strict :

1. **Read Uncommitted** : Peut lire les modifications non validées d'autres transactions (**lectures sales**). Presque jamais utilisé.
2. **Read Committed** (par défaut PostgreSQL) : Ne lit que les données validées. Mais relire la même ligne peut retourner des valeurs différentes si une autre transaction a été validée entre-temps (**lectures non répétables**).
3. **Repeatable Read** (par défaut MySQL InnoDB) : Relire la même ligne retourne toujours la même valeur au sein d'une transaction. Mais de nouvelles lignes insérées par d'autres transactions peuvent apparaître (**lectures fantômes**).
4. **Serializable** : Isolation complète. Les transactions s'exécutent comme si elles étaient sérielles (l'une après l'autre). Prévient toutes les anomalies mais a le coût de performance le plus élevé (surcharge de verrouillage/MVCC).

Choisissez selon l'application : les transactions financières nécessitent Serializable ; les lectures d'applications web utilisent typiquement Read Committed.
</details>

## Indexation et Performance

<details>
<summary><strong>9. Qu'est-ce qu'un index de base de données et comment fonctionne-t-il ?</strong></summary>
<br>

Un index est une structure de données séparée (typiquement un **B-tree** ou **B+ tree**) qui stocke une copie triée de colonnes spécifiques avec des pointeurs vers les lignes complètes. Il permet à la base de données de trouver des lignes sans scanner la table entière (scan complet de table).

Analogie : L'index d'un livre associe des mots-clés à des numéros de page. Sans lui, vous devez lire chaque page pour trouver un sujet.

Compromis :
- **Lectures plus rapides** : SELECT avec WHERE, JOIN, ORDER BY sur des colonnes indexées.
- **Écritures plus lentes** : Chaque INSERT, UPDATE, DELETE doit aussi mettre à jour l'index.
- **Plus de stockage** : L'index occupe de l'espace disque proportionnel aux données indexées.

Règle : Indexez les colonnes qui apparaissent fréquemment dans les clauses WHERE, JOIN ON, ORDER BY et GROUP BY.
</details>

<details>
<summary><strong>10. Quelle est la différence entre un index clustered et non-clustered ?</strong></summary>
<br>

- **Index clustered** : Détermine l'**ordre physique** des données sur le disque. Une table ne peut avoir qu'un seul index clustered (généralement la clé primaire). Les nœuds feuilles du B-tree contiennent les lignes de données réelles.
- **Index non-clustered** : Une structure séparée avec des pointeurs vers les lignes de données. Une table peut avoir plusieurs index non-clustered. Les nœuds feuilles contiennent les valeurs des colonnes indexées et une référence (localisateur de ligne) vers les données réelles.

Dans PostgreSQL, il n'y a pas de concept explicite d'index clustered — la commande `CLUSTER` réordonne physiquement les données une fois, mais ce n'est pas maintenu automatiquement. InnoDB (MySQL) regroupe toujours les données par la clé primaire.
</details>

<details>
<summary><strong>11. Comment optimisez-vous une requête lente ?</strong></summary>
<br>

Approche étape par étape :

1. **EXPLAIN ANALYZE** : Lisez le plan de requête. Cherchez les scans séquentiels (Seq Scan), les estimations de lignes élevées et les opérations de tri sur de grands jeux de données.
2. **Ajoutez les index manquants** : Si les colonnes WHERE/JOIN n'ont pas d'index, créez-les.
3. **Réécrivez la requête** : Remplacez les sous-requêtes par des JOINs. Utilisez EXISTS au lieu de IN pour les grands sous-ensembles. Évitez SELECT * — sélectionnez uniquement les colonnes nécessaires.
4. **Évitez les fonctions sur les colonnes indexées** : `WHERE YEAR(created_at) = 2026` ne peut pas utiliser un index sur `created_at`. Réécrivez comme `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`.
5. **Pagination** : Utilisez la pagination par clé (`WHERE id > last_seen_id LIMIT 20`) au lieu de `OFFSET` (qui scanne et rejette des lignes).
6. **Statistiques** : Exécutez `ANALYZE` (PostgreSQL) pour mettre à jour les statistiques de table afin que le planificateur prenne de meilleures décisions.
</details>

<details>
<summary><strong>12. Qu'est-ce qu'un index couvrant ?</strong></summary>
<br>

Un index couvrant contient toutes les colonnes nécessaires pour satisfaire une requête, donc la base de données n'a jamais besoin d'accéder aux données réelles de la table (pas de "heap fetch" ni de "bookmark lookup"). La requête est résolue entièrement depuis l'index.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL utilise `INCLUDE` pour les colonnes non-clé. MySQL utilise des index composites où les colonnes supplémentaires sont ajoutées en fin. Les index couvrants peuvent améliorer considérablement les performances de lecture pour des modèles de requête spécifiques.
</details>

## Concepts Avancés

<details>
<summary><strong>13. Qu'est-ce qu'une Common Table Expression (CTE) et quand l'utiliseriez-vous ?</strong></summary>
<br>

Une CTE est un ensemble de résultats temporaire nommé défini dans une seule requête avec `WITH` :

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

Utilisez les CTEs pour : la lisibilité (découper des requêtes complexes en étapes logiques), les requêtes récursives (données hiérarchiques comme les organigrammes) et remplacer les sous-requêtes complexes. Note : Dans PostgreSQL < 12, les CTEs agissent comme des barrières d'optimisation (non intégrées inline). Dans PostgreSQL 12+, les CTEs non récursives peuvent être intégrées inline.
</details>

<details>
<summary><strong>14. Que sont les fonctions fenêtre et en quoi diffèrent-elles de GROUP BY ?</strong></summary>
<br>

Les fonctions fenêtre calculent une valeur sur un ensemble de lignes **sans les réduire en une seule ligne** (contrairement à GROUP BY).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

Fonctions fenêtre courantes : `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. Essentielles pour l'analyse, le reporting et la pagination.
</details>

<details>
<summary><strong>15. Qu'est-ce qu'un deadlock et comment le prévenir ?</strong></summary>
<br>

Un deadlock survient quand deux transactions attendent que l'autre libère ses verrous, créant une dépendance circulaire. Aucune ne peut progresser.

Exemple :
- La Transaction A verrouille la Ligne 1, veut la Ligne 2.
- La Transaction B verrouille la Ligne 2, veut la Ligne 1.
- Les deux attendent indéfiniment.

La base de données détecte les deadlocks et tue une transaction (la "victime"), en effectuant un rollback.

Prévention :
1. **Ordre de verrouillage cohérent** : Verrouillez toujours les ressources dans le même ordre dans toutes les transactions.
2. **Transactions courtes** : Maintenez les verrous le minimum de temps nécessaire.
3. **Timeouts de verrouillage** : Définissez `lock_timeout` pour que les transactions échouent rapidement au lieu d'attendre indéfiniment.
4. **Réduire le niveau d'isolation** : Des niveaux d'isolation plus bas nécessitent moins de verrous.
</details>

## Sécurité

<details>
<summary><strong>16. Qu'est-ce que l'injection SQL et comment la prévenir ?</strong></summary>
<br>

L'injection SQL survient quand l'entrée utilisateur est concaténée directement dans une requête SQL, permettant à un attaquant de modifier la logique de la requête.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

Prévention :
1. **Requêtes paramétrées** (instructions préparées) — la défense numéro 1. L'entrée est traitée comme des données, jamais comme du SQL.
2. **ORM** (SQLAlchemy, Django ORM) — génère automatiquement des requêtes paramétrées.
3. **Validation des entrées** — liste blanche des formats attendus (IDs numériques, modèles d'email).
4. **Principe du moindre privilège** — l'utilisateur de base de données ne devrait avoir que SELECT/INSERT/UPDATE sur les tables nécessaires, jamais DROP ou GRANT.
</details>

<details>
<summary><strong>17. Qu'est-ce que le principe du moindre privilège en sécurité des bases de données ?</strong></summary>
<br>

Chaque utilisateur de base de données ou application ne devrait avoir que les permissions minimales nécessaires pour accomplir son travail.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

N'utilisez jamais le superutilisateur de la base de données (postgres, root) pour les connexions de l'application. Si l'application est compromise via une injection SQL, l'attaquant n'obtient que les permissions de l'utilisateur limité.
</details>

## Scénarios Pratiques

<details>
<summary><strong>18. Comment concevez-vous un schéma pour une relation plusieurs-à-plusieurs ?</strong></summary>
<br>

Utilisez une **table de jonction** (aussi appelée table de liaison ou table associative) :

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

La table de jonction contient les clés étrangères vers les deux tables, créant la relation plusieurs-à-plusieurs. Elle peut aussi contenir des attributs spécifiques à la relation (enrolled_at, grade).
</details>

<details>
<summary><strong>19. Écrivez une requête pour trouver le deuxième salaire le plus élevé dans chaque département.</strong></summary>
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

Pourquoi `DENSE_RANK` plutôt que `ROW_NUMBER` : Si deux employés sont à égalité pour le salaire le plus élevé, `DENSE_RANK` attribue correctement le rang 2 au salaire suivant. `ROW_NUMBER` attribuerait arbitrairement les rangs 1 et 2 aux employés à égalité.
</details>

<details>
<summary><strong>20. Comment gérez-vous les migrations de base de données en production ?</strong></summary>
<br>

1. **Utilisez un outil de migration** : Flyway, Liquibase (Java), Alembic (Python/SQLAlchemy), Django migrations, Prisma Migrate. N'exécutez jamais de DDL brut en production.
2. **Versionnez les migrations** : Chaque migration est un fichier numéroté dans le dépôt. Les migrations sont appliquées dans l'ordre et suivies dans une table de métadonnées.
3. **Changements rétrocompatibles** : Ajoutez d'abord les nouvelles colonnes comme nullable. Déployez le code applicatif qui utilise la nouvelle colonne. Puis ajoutez une contrainte NOT NULL si nécessaire. Ne renommez ou supprimez jamais des colonnes sans période de dépréciation.
4. **Testez les migrations** : Exécutez-les sur une copie staging des données de production avant d'appliquer en production.
5. **Plan de rollback** : Chaque migration devrait avoir un script de rollback correspondant. Testez les rollbacks avant le déploiement.
6. **Zero-downtime** : Utilisez des techniques comme les patterns expansion/contraction, les tables fantômes (gh-ost pour MySQL) ou le DDL en ligne (ALTER TABLE non bloquant de PostgreSQL).
</details>
