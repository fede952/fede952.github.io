---
title: "Domande di Colloquio su SQL e Progettazione Database (Livello Senior)"
description: "20 domande avanzate di colloquio su SQL e database per ruoli Senior Backend e DBA. Copre ottimizzazione delle query, normalizzazione, indicizzazione, transazioni, proprietà ACID e sicurezza."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["domande colloquio query sql", "normalizzazione database", "proprietà acid", "prevenzione sql injection", "colloquio indici database", "domande join sql", "colloquio postgresql", "domande colloquio mysql", "pattern progettazione database", "ottimizzazione prestazioni sql"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Domande di Colloquio su SQL e Progettazione Database (Livello Senior)",
    "description": "20 domande avanzate di colloquio su SQL e database che coprono ottimizzazione, normalizzazione, indicizzazione, transazioni e sicurezza.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

SQL è il linguaggio dei dati e i database sono la spina dorsale di ogni applicazione. I colloqui di livello senior testano la tua capacità di scrivere query efficienti, progettare schemi normalizzati, comprendere l'isolamento delle transazioni, ottimizzare le prestazioni con gli indici e prevenire le SQL injection. Che il ruolo sia Backend Engineer, DBA, Data Engineer o Security Analyst, queste 20 domande coprono i concetti che gli intervistatori chiedono costantemente — con risposte che dimostrano esperienza in produzione.

**Hai bisogno di un riferimento rapido su SQL?** Tieni aperto il nostro [Cheatsheet SQL Injection e Query Database](/cheatsheets/sql-injection-payloads-database/) durante la preparazione.

---

## Fondamenti delle Query

<details>
<summary><strong>1. Qual è l'ordine di esecuzione di una query SQL?</strong></summary>
<br>

Le query SQL **non** vengono eseguite nell'ordine in cui le scrivi. L'ordine effettivo di esecuzione è:

1. **FROM** / **JOIN** — identifica le tabelle e le unisce.
2. **WHERE** — filtra le righe prima del raggruppamento.
3. **GROUP BY** — raggruppa le righe rimanenti.
4. **HAVING** — filtra i gruppi (dopo l'aggregazione).
5. **SELECT** — sceglie quali colonne/espressioni restituire.
6. **DISTINCT** — rimuove le righe duplicate.
7. **ORDER BY** — ordina i risultati.
8. **LIMIT** / **OFFSET** — limita il numero di righe restituite.

Ecco perché non puoi usare un alias di colonna definito in SELECT all'interno di una clausola WHERE — WHERE viene eseguito prima di SELECT.
</details>

<details>
<summary><strong>2. Spiega la differenza tra WHERE e HAVING.</strong></summary>
<br>

- **WHERE** filtra le righe **prima** dell'aggregazione (GROUP BY). Opera sulle singole righe e non può usare funzioni di aggregazione.
- **HAVING** filtra i gruppi **dopo** l'aggregazione. Opera sui risultati di GROUP BY e può usare funzioni di aggregazione.

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

Prestazioni: WHERE è sempre preferibile quando possibile — riduce il dataset prima dell'operazione costosa di GROUP BY.
</details>

<details>
<summary><strong>3. Qual è la differenza tra INNER JOIN, LEFT JOIN, RIGHT JOIN e FULL OUTER JOIN?</strong></summary>
<br>

- **INNER JOIN**: Restituisce solo le righe che hanno valori corrispondenti in **entrambe** le tabelle. Le righe senza corrispondenza vengono escluse.
- **LEFT JOIN**: Restituisce tutte le righe dalla tabella sinistra e le righe corrispondenti dalla tabella destra. Se non c'è corrispondenza, le colonne destre sono NULL.
- **RIGHT JOIN**: Restituisce tutte le righe dalla tabella destra e le righe corrispondenti dalla tabella sinistra. Se non c'è corrispondenza, le colonne sinistre sono NULL.
- **FULL OUTER JOIN**: Restituisce tutte le righe da entrambe le tabelle. Dove non c'è corrispondenza, il lato mancante è NULL.

In pratica, LEFT JOIN viene usato circa il 90% delle volte. RIGHT JOIN può sempre essere riscritto come LEFT JOIN invertendo l'ordine delle tabelle.
</details>

<details>
<summary><strong>4. Qual è la differenza tra UNION e UNION ALL?</strong></summary>
<br>

- **UNION**: Combina i risultati di due query e **rimuove le righe duplicate**. Richiede internamente un'operazione di ordinamento/deduplicazione.
- **UNION ALL**: Combina i risultati **senza rimuovere i duplicati**. Più veloce perché non è necessaria la deduplicazione.

Usa sempre `UNION ALL` a meno che tu non abbia specificamente bisogno della deduplicazione. L'operazione di ordinamento implicita di `UNION` può essere costosa su grandi dataset.

Entrambi richiedono lo stesso numero di colonne con tipi di dati compatibili in ogni SELECT.
</details>

## Progettazione del Database

<details>
<summary><strong>5. Spiega la normalizzazione del database (dalla 1NF alla 3NF).</strong></summary>
<br>

La normalizzazione riduce la ridondanza dei dati e previene le anomalie di aggiornamento:

- **1NF** (Prima Forma Normale): Ogni colonna contiene valori atomici (indivisibili). Nessun gruppo ripetuto. Ogni riga è unica (ha una chiave primaria).
- **2NF**: Soddisfa la 1NF + ogni colonna non chiave dipende dall'**intera** chiave primaria (non solo da parte di una chiave composta). Elimina le dipendenze parziali.
- **3NF**: Soddisfa la 2NF + ogni colonna non chiave dipende **direttamente** dalla chiave primaria, non da un'altra colonna non chiave. Elimina le dipendenze transitive.

Esempio di violazione della 3NF: Una tabella con `(order_id, customer_id, customer_name)` — `customer_name` dipende da `customer_id`, non da `order_id`. Soluzione: Spostare `customer_name` in una tabella `customers` separata.
</details>

<details>
<summary><strong>6. Quando denormalizzeresti intenzionalmente un database?</strong></summary>
<br>

La denormalizzazione è giustificata quando:

1. **Le prestazioni in lettura sono critiche**: Dashboard di reportistica, query analitiche che uniscono molte tabelle. Precalcolare aggregati o appiattire gerarchie evita join costosi al momento della query.
2. **Livelli di cache**: Viste materializzate o tabelle riepilogative che vengono aggiornate periodicamente.
3. **NoSQL/Document store**: I dati vengono archiviati come documenti completi (MongoDB). L'incorporamento di dati correlati evita completamente i join.
4. **Event sourcing/CQRS**: Il modello di scrittura è normalizzato, il modello di lettura è denormalizzato.

Il compromesso: letture più veloci a costo di scritture più complesse (è necessario aggiornare più posizioni) e potenziale inconsistenza dei dati.
</details>

<details>
<summary><strong>7. Cosa sono le proprietà ACID?</strong></summary>
<br>

ACID garantisce transazioni di database affidabili:

- **Atomicità**: Una transazione è tutto-o-niente. Se una parte fallisce, l'intera transazione viene annullata. Nessun aggiornamento parziale.
- **Consistenza**: Una transazione porta il database da uno stato valido a un altro. Tutti i vincoli (chiavi esterne, check, trigger) sono soddisfatti.
- **Isolamento**: Le transazioni concorrenti non interferiscono tra loro. Ogni transazione vede uno snapshot consistente dei dati.
- **Durabilità**: Una volta che una transazione è confermata, sopravvive ai crash di sistema. I dati vengono scritti su storage non volatile (WAL, redo log).

ACID è la caratteristica distintiva dei database relazionali (PostgreSQL, MySQL InnoDB). Molti database NoSQL sacrificano alcune proprietà ACID per la scalabilità (BASE: Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. Spiega i livelli di isolamento delle transazioni.</strong></summary>
<br>

Dal meno al più rigoroso:

1. **Read Uncommitted**: Può leggere modifiche non confermate da altre transazioni (**dirty read**). Quasi mai usato.
2. **Read Committed** (predefinito in PostgreSQL): Legge solo dati confermati. Ma rileggere la stessa riga può restituire valori diversi se un'altra transazione ha confermato nel frattempo (**letture non ripetibili**).
3. **Repeatable Read** (predefinito in MySQL InnoDB): Rileggere la stessa riga restituisce sempre lo stesso valore all'interno di una transazione. Ma nuove righe inserite da altre transazioni possono apparire (**letture fantasma**).
4. **Serializable**: Isolamento completo. Le transazioni vengono eseguite come se fossero seriali (una dopo l'altra). Previene tutte le anomalie ma ha il costo prestazionale più alto (overhead di locking/MVCC).

Scegli in base all'applicazione: le transazioni finanziarie necessitano di Serializable; le letture di app web tipicamente usano Read Committed.
</details>

## Indicizzazione e Prestazioni

<details>
<summary><strong>9. Cos'è un indice di database e come funziona?</strong></summary>
<br>

Un indice è una struttura dati separata (tipicamente un **B-tree** o **B+ tree**) che memorizza una copia ordinata di colonne specifiche insieme a puntatori alle righe complete. Permette al database di trovare le righe senza scansionare l'intera tabella (scansione completa della tabella).

Analogia: L'indice di un libro mappa le parole chiave ai numeri di pagina. Senza di esso, devi leggere ogni pagina per trovare un argomento.

Compromessi:
- **Letture più veloci**: SELECT con WHERE, JOIN, ORDER BY su colonne indicizzate.
- **Scritture più lente**: Ogni INSERT, UPDATE, DELETE deve anche aggiornare l'indice.
- **Più spazio**: L'indice occupa spazio su disco proporzionale ai dati indicizzati.

Regola: Indicizza le colonne che appaiono frequentemente nelle clausole WHERE, JOIN ON, ORDER BY e GROUP BY.
</details>

<details>
<summary><strong>10. Qual è la differenza tra un indice clustered e non-clustered?</strong></summary>
<br>

- **Indice clustered**: Determina l'**ordine fisico** dei dati su disco. Una tabella può avere un solo indice clustered (di solito la chiave primaria). I nodi foglia del B-tree contengono le righe di dati effettive.
- **Indice non-clustered**: Una struttura separata con puntatori alle righe di dati. Una tabella può avere più indici non-clustered. I nodi foglia contengono i valori delle colonne indicizzate e un riferimento (localizzatore di riga) ai dati effettivi.

In PostgreSQL, non esiste il concetto esplicito di indice clustered — il comando `CLUSTER` riordina fisicamente i dati una volta, ma non viene mantenuto automaticamente. InnoDB (MySQL) raggruppa sempre i dati per chiave primaria.
</details>

<details>
<summary><strong>11. Come ottimizzi una query lenta?</strong></summary>
<br>

Approccio passo dopo passo:

1. **EXPLAIN ANALYZE**: Leggi il piano di esecuzione della query. Cerca scansioni sequenziali (Seq Scan), stime di righe elevate e operazioni di ordinamento su grandi dataset.
2. **Aggiungi indici mancanti**: Se le colonne WHERE/JOIN non hanno indici, creali.
3. **Riscrivi la query**: Sostituisci le subquery con JOIN. Usa EXISTS invece di IN per grandi sottoinsiemi. Evita SELECT * — seleziona solo le colonne necessarie.
4. **Evita funzioni su colonne indicizzate**: `WHERE YEAR(created_at) = 2026` non può usare un indice su `created_at`. Riscrivi come `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`.
5. **Paginazione**: Usa la paginazione per chiave (`WHERE id > last_seen_id LIMIT 20`) invece di `OFFSET` (che scansiona e scarta righe).
6. **Statistiche**: Esegui `ANALYZE` (PostgreSQL) per aggiornare le statistiche della tabella in modo che il pianificatore prenda decisioni migliori.
</details>

<details>
<summary><strong>12. Cos'è un indice di copertura?</strong></summary>
<br>

Un indice di copertura contiene tutte le colonne necessarie per soddisfare una query, quindi il database non ha mai bisogno di accedere ai dati effettivi della tabella (nessun "heap fetch" o "bookmark lookup"). La query viene soddisfatta interamente dall'indice.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL usa `INCLUDE` per le colonne non chiave. MySQL usa indici compositi dove le colonne extra vengono aggiunte in coda. Gli indici di copertura possono migliorare drasticamente le prestazioni di lettura per pattern di query specifici.
</details>

## Concetti Avanzati

<details>
<summary><strong>13. Cos'è una Common Table Expression (CTE) e quando la useresti?</strong></summary>
<br>

Una CTE è un set di risultati temporaneo con nome definito all'interno di una singola query usando `WITH`:

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

Usa le CTE per: leggibilità (suddividere query complesse in passaggi logici), query ricorsive (dati gerarchici come organigrammi) e sostituire subquery complesse. Nota: In PostgreSQL < 12, le CTE agiscono come barriere di ottimizzazione (non vengono inline). In PostgreSQL 12+, le CTE non ricorsive possono essere inline.
</details>

<details>
<summary><strong>14. Cosa sono le funzioni finestra e come si differenziano da GROUP BY?</strong></summary>
<br>

Le funzioni finestra calcolano un valore su un insieme di righe **senza comprimerle in una singola riga** (a differenza di GROUP BY).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

Funzioni finestra comuni: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. Essenziali per analisi, reportistica e paginazione.
</details>

<details>
<summary><strong>15. Cos'è un deadlock e come lo previeni?</strong></summary>
<br>

Un deadlock si verifica quando due transazioni attendono che l'altra rilasci i lock, creando una dipendenza circolare. Nessuna delle due può procedere.

Esempio:
- La Transazione A blocca la Riga 1, vuole la Riga 2.
- La Transazione B blocca la Riga 2, vuole la Riga 1.
- Entrambe attendono per sempre.

Il database rileva i deadlock e termina una transazione (la "vittima"), eseguendo il rollback.

Prevenzione:
1. **Ordine di lock consistente**: Blocca sempre le risorse nello stesso ordine in tutte le transazioni.
2. **Transazioni brevi**: Mantieni i lock per il tempo minimo necessario.
3. **Timeout dei lock**: Imposta `lock_timeout` in modo che le transazioni falliscano rapidamente invece di attendere indefinitamente.
4. **Ridurre il livello di isolamento**: Livelli di isolamento inferiori richiedono meno lock.
</details>

## Sicurezza

<details>
<summary><strong>16. Cos'è la SQL injection e come la previeni?</strong></summary>
<br>

La SQL injection si verifica quando l'input dell'utente viene concatenato direttamente in una query SQL, permettendo a un attaccante di modificare la logica della query.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

Prevenzione:
1. **Query parametrizzate** (prepared statement) — la difesa numero 1. L'input viene trattato come dato, mai come SQL.
2. **ORM** (SQLAlchemy, Django ORM) — genera query parametrizzate automaticamente.
3. **Validazione dell'input** — lista bianca dei formati attesi (ID numerici, pattern email).
4. **Principio del minimo privilegio** — l'utente database dovrebbe avere solo SELECT/INSERT/UPDATE sulle tabelle necessarie, mai DROP o GRANT.
</details>

<details>
<summary><strong>17. Cos'è il principio del minimo privilegio nella sicurezza dei database?</strong></summary>
<br>

Ogni utente database o applicazione dovrebbe avere solo i permessi minimi necessari per svolgere il proprio lavoro.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

Non usare mai il superutente del database (postgres, root) per le connessioni dell'applicazione. Se l'applicazione viene compromessa tramite SQL injection, l'attaccante ottiene solo i permessi dell'utente limitato.
</details>

## Scenari Pratici

<details>
<summary><strong>18. Come progetti uno schema per una relazione molti-a-molti?</strong></summary>
<br>

Usa una **tabella di giunzione** (chiamata anche tabella ponte o tabella associativa):

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

La tabella di giunzione contiene le chiavi esterne verso entrambe le tabelle, creando la relazione molti-a-molti. Può anche contenere attributi specifici della relazione (enrolled_at, grade).
</details>

<details>
<summary><strong>19. Scrivi una query per trovare il secondo stipendio più alto in ogni dipartimento.</strong></summary>
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

Perché `DENSE_RANK` invece di `ROW_NUMBER`: Se due dipendenti sono a pari merito per lo stipendio più alto, `DENSE_RANK` assegna correttamente il rango 2 allo stipendio successivo. `ROW_NUMBER` assegnerebbe arbitrariamente i ranghi 1 e 2 ai dipendenti a pari merito.
</details>

<details>
<summary><strong>20. Come gestisci le migrazioni del database in produzione?</strong></summary>
<br>

1. **Usa uno strumento di migrazione**: Flyway, Liquibase (Java), Alembic (Python/SQLAlchemy), Django migrations, Prisma Migrate. Non eseguire mai DDL grezzo in produzione.
2. **Versiona le migrazioni**: Ogni migrazione è un file numerato nel repository. Le migrazioni vengono applicate in ordine e tracciate in una tabella di metadati.
3. **Modifiche retrocompatibili**: Aggiungi nuove colonne come nullable prima. Distribuisci il codice dell'applicazione che usa la nuova colonna. Poi aggiungi un vincolo NOT NULL se necessario. Non rinominare o eliminare colonne senza un periodo di deprecazione.
4. **Testa le migrazioni**: Esegui su una copia staging dei dati di produzione prima di applicare in produzione.
5. **Piano di rollback**: Ogni migrazione dovrebbe avere uno script di rollback corrispondente. Testa i rollback prima del deployment.
6. **Zero-downtime**: Usa tecniche come pattern espansione/contrazione, ghost table (gh-ost per MySQL) o DDL online (ALTER TABLE non bloccante di PostgreSQL).
</details>
