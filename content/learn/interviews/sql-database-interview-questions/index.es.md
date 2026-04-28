---
title: "Preguntas de Entrevista sobre SQL y Diseño de Bases de Datos (Nivel Senior)"
description: "20 preguntas avanzadas de entrevista sobre SQL y bases de datos para roles Senior Backend y DBA. Cubre optimización de consultas, normalización, indexación, transacciones, propiedades ACID y seguridad."
date: 2026-02-11
tags: ["sql", "interview", "database", "backend"]
keywords: ["preguntas entrevista consultas sql", "normalización de bases de datos", "propiedades acid", "prevención de inyección sql", "entrevista índices de bases de datos", "preguntas join sql", "entrevista postgresql", "preguntas entrevista mysql", "patrones diseño de bases de datos", "optimización rendimiento sql"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Preguntas de Entrevista sobre SQL y Diseño de Bases de Datos (Nivel Senior)",
    "description": "20 preguntas avanzadas de entrevista sobre SQL y bases de datos que cubren optimización, normalización, indexación, transacciones y seguridad.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "es"
  }
---

## Inicialización del Sistema

SQL es el lenguaje de los datos, y las bases de datos son la columna vertebral de cada aplicación. Las entrevistas de nivel senior evalúan tu capacidad para escribir consultas eficientes, diseñar esquemas normalizados, comprender el aislamiento de transacciones, optimizar el rendimiento con índices y prevenir inyecciones SQL. Ya sea que el rol sea Ingeniero Backend, DBA, Ingeniero de Datos o Analista de Seguridad, estas 20 preguntas cubren los conceptos que los entrevistadores preguntan constantemente — con respuestas que demuestran experiencia en producción.

**¿Necesitas una referencia rápida de SQL?** Mantén abierto nuestro [Cheatsheet de Inyección SQL y Consultas de Base de Datos](/cheatsheets/sql-injection-payloads-database/) durante tu preparación.

---

## Fundamentos de Consultas

<details>
<summary><strong>1. ¿Cuál es el orden de ejecución de una consulta SQL?</strong></summary>
<br>

Las consultas SQL **no** se ejecutan en el orden en que las escribes. El orden real de ejecución es:

1. **FROM** / **JOIN** — identifica las tablas y las une.
2. **WHERE** — filtra filas antes del agrupamiento.
3. **GROUP BY** — agrupa las filas restantes.
4. **HAVING** — filtra grupos (después de la agregación).
5. **SELECT** — elige qué columnas/expresiones devolver.
6. **DISTINCT** — elimina filas duplicadas.
7. **ORDER BY** — ordena los resultados.
8. **LIMIT** / **OFFSET** — restringe el número de filas devueltas.

Por esto no puedes usar un alias de columna definido en SELECT dentro de una cláusula WHERE — WHERE se ejecuta antes que SELECT.
</details>

<details>
<summary><strong>2. Explica la diferencia entre WHERE y HAVING.</strong></summary>
<br>

- **WHERE** filtra filas **antes** de la agregación (GROUP BY). Opera sobre filas individuales y no puede usar funciones de agregación.
- **HAVING** filtra grupos **después** de la agregación. Opera sobre los resultados de GROUP BY y puede usar funciones de agregación.

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

Rendimiento: WHERE siempre es preferible cuando es posible — reduce el conjunto de datos antes de la costosa operación GROUP BY.
</details>

<details>
<summary><strong>3. ¿Cuál es la diferencia entre INNER JOIN, LEFT JOIN, RIGHT JOIN y FULL OUTER JOIN?</strong></summary>
<br>

- **INNER JOIN**: Devuelve solo las filas que tienen valores coincidentes en **ambas** tablas. Las filas sin coincidencia se excluyen.
- **LEFT JOIN**: Devuelve todas las filas de la tabla izquierda y las filas coincidentes de la tabla derecha. Si no hay coincidencia, las columnas derechas son NULL.
- **RIGHT JOIN**: Devuelve todas las filas de la tabla derecha y las filas coincidentes de la tabla izquierda. Si no hay coincidencia, las columnas izquierdas son NULL.
- **FULL OUTER JOIN**: Devuelve todas las filas de ambas tablas. Donde no hay coincidencia, el lado faltante es NULL.

En la práctica, LEFT JOIN se usa aproximadamente el 90% de las veces. RIGHT JOIN siempre puede reescribirse como LEFT JOIN intercambiando el orden de las tablas.
</details>

<details>
<summary><strong>4. ¿Cuál es la diferencia entre UNION y UNION ALL?</strong></summary>
<br>

- **UNION**: Combina resultados de dos consultas y **elimina filas duplicadas**. Requiere una operación interna de ordenamiento/deduplicación.
- **UNION ALL**: Combina resultados **sin eliminar duplicados**. Más rápido porque no se necesita deduplicación.

Siempre usa `UNION ALL` a menos que específicamente necesites deduplicación. La operación de ordenamiento implícita de `UNION` puede ser costosa en conjuntos de datos grandes.

Ambos requieren el mismo número de columnas con tipos de datos compatibles en cada SELECT.
</details>

## Diseño de Base de Datos

<details>
<summary><strong>5. Explica la normalización de bases de datos (1NF a 3NF).</strong></summary>
<br>

La normalización reduce la redundancia de datos y previene anomalías de actualización:

- **1NF** (Primera Forma Normal): Cada columna contiene valores atómicos (indivisibles). Sin grupos repetidos. Cada fila es única (tiene una clave primaria).
- **2NF**: Cumple 1NF + cada columna no clave depende de la clave primaria **completa** (no solo de parte de una clave compuesta). Elimina dependencias parciales.
- **3NF**: Cumple 2NF + cada columna no clave depende **directamente** de la clave primaria, no de otra columna no clave. Elimina dependencias transitivas.

Ejemplo de violación de 3NF: Una tabla con `(order_id, customer_id, customer_name)` — `customer_name` depende de `customer_id`, no de `order_id`. Solución: Mover `customer_name` a una tabla `customers` separada.
</details>

<details>
<summary><strong>6. ¿Cuándo desnormalizarías intencionalmente una base de datos?</strong></summary>
<br>

La desnormalización se justifica cuando:

1. **El rendimiento de lectura es crítico**: Dashboards de reportes, consultas analíticas que unen muchas tablas. Precalcular agregados o aplanar jerarquías evita joins costosos en tiempo de consulta.
2. **Capas de caché**: Vistas materializadas o tablas resumen que se actualizan periódicamente.
3. **NoSQL/Almacenes de documentos**: Los datos se almacenan como documentos completos (MongoDB). Incorporar datos relacionados evita los joins por completo.
4. **Event sourcing/CQRS**: El modelo de escritura está normalizado, el modelo de lectura está desnormalizado.

El compromiso: lecturas más rápidas a costa de escrituras más complejas (debe actualizar múltiples lugares) y posible inconsistencia de datos.
</details>

<details>
<summary><strong>7. ¿Qué son las propiedades ACID?</strong></summary>
<br>

ACID garantiza transacciones de base de datos confiables:

- **Atomicidad**: Una transacción es todo-o-nada. Si alguna parte falla, toda la transacción se revierte. Sin actualizaciones parciales.
- **Consistencia**: Una transacción mueve la base de datos de un estado válido a otro. Todas las restricciones (claves foráneas, checks, triggers) se satisfacen.
- **Aislamiento**: Las transacciones concurrentes no interfieren entre sí. Cada transacción ve una instantánea consistente de los datos.
- **Durabilidad**: Una vez que una transacción se confirma, sobrevive a fallos del sistema. Los datos se escriben en almacenamiento no volátil (WAL, redo logs).

ACID es la característica definitoria de las bases de datos relacionales (PostgreSQL, MySQL InnoDB). Muchas bases de datos NoSQL sacrifican algunas propiedades ACID por escalabilidad (BASE: Basically Available, Soft state, Eventually consistent).
</details>

<details>
<summary><strong>8. Explica los niveles de aislamiento de transacciones.</strong></summary>
<br>

De menos a más estricto:

1. **Read Uncommitted**: Puede leer cambios no confirmados de otras transacciones (**lecturas sucias**). Casi nunca se usa.
2. **Read Committed** (predeterminado en PostgreSQL): Solo lee datos confirmados. Pero releer la misma fila puede devolver valores diferentes si otra transacción confirmó entre medias (**lecturas no repetibles**).
3. **Repeatable Read** (predeterminado en MySQL InnoDB): Releer la misma fila siempre devuelve el mismo valor dentro de una transacción. Pero nuevas filas insertadas por otras transacciones pueden aparecer (**lecturas fantasma**).
4. **Serializable**: Aislamiento completo. Las transacciones se ejecutan como si fueran seriales (una tras otra). Previene todas las anomalías pero tiene el mayor costo de rendimiento (overhead de bloqueo/MVCC).

Elige según la aplicación: las transacciones financieras necesitan Serializable; las lecturas de aplicaciones web típicamente usan Read Committed.
</details>

## Indexación y Rendimiento

<details>
<summary><strong>9. ¿Qué es un índice de base de datos y cómo funciona?</strong></summary>
<br>

Un índice es una estructura de datos separada (típicamente un **B-tree** o **B+ tree**) que almacena una copia ordenada de columnas específicas junto con punteros a las filas completas. Permite a la base de datos encontrar filas sin escanear toda la tabla (escaneo completo de tabla).

Analogía: El índice de un libro mapea palabras clave a números de página. Sin él, debes leer cada página para encontrar un tema.

Compensaciones:
- **Lecturas más rápidas**: SELECT con WHERE, JOIN, ORDER BY en columnas indexadas.
- **Escrituras más lentas**: Cada INSERT, UPDATE, DELETE también debe actualizar el índice.
- **Más almacenamiento**: El índice ocupa espacio en disco proporcional a los datos indexados.

Regla: Indexa las columnas que aparecen frecuentemente en las cláusulas WHERE, JOIN ON, ORDER BY y GROUP BY.
</details>

<details>
<summary><strong>10. ¿Cuál es la diferencia entre un índice clustered y non-clustered?</strong></summary>
<br>

- **Índice clustered**: Determina el **orden físico** de los datos en disco. Una tabla solo puede tener un índice clustered (generalmente la clave primaria). Los nodos hoja del B-tree contienen las filas de datos reales.
- **Índice non-clustered**: Una estructura separada con punteros a las filas de datos. Una tabla puede tener múltiples índices non-clustered. Los nodos hoja contienen los valores de las columnas indexadas y una referencia (localizador de fila) a los datos reales.

En PostgreSQL, no existe un concepto explícito de índice clustered — el comando `CLUSTER` reordena físicamente los datos una vez, pero no se mantiene automáticamente. InnoDB (MySQL) siempre agrupa los datos por la clave primaria.
</details>

<details>
<summary><strong>11. ¿Cómo optimizas una consulta lenta?</strong></summary>
<br>

Enfoque paso a paso:

1. **EXPLAIN ANALYZE**: Lee el plan de la consulta. Busca escaneos secuenciales (Seq Scan), estimaciones de filas altas y operaciones de ordenamiento en grandes conjuntos de datos.
2. **Agrega índices faltantes**: Si las columnas WHERE/JOIN carecen de índices, créalos.
3. **Reescribe la consulta**: Reemplaza subconsultas con JOINs. Usa EXISTS en lugar de IN para subconjuntos grandes. Evita SELECT * — selecciona solo las columnas necesarias.
4. **Evita funciones en columnas indexadas**: `WHERE YEAR(created_at) = 2026` no puede usar un índice en `created_at`. Reescribe como `WHERE created_at >= '2026-01-01' AND created_at < '2027-01-01'`.
5. **Paginación**: Usa paginación por clave (`WHERE id > last_seen_id LIMIT 20`) en lugar de `OFFSET` (que escanea y descarta filas).
6. **Estadísticas**: Ejecuta `ANALYZE` (PostgreSQL) para actualizar las estadísticas de la tabla para que el planificador tome mejores decisiones.
</details>

<details>
<summary><strong>12. ¿Qué es un índice de cobertura?</strong></summary>
<br>

Un índice de cobertura contiene todas las columnas necesarias para satisfacer una consulta, por lo que la base de datos nunca necesita acceder a los datos reales de la tabla (sin "heap fetch" ni "bookmark lookup"). La consulta se responde completamente desde el índice.

```sql
-- Query
SELECT email, name FROM users WHERE email = 'user@example.com';

-- Covering index (includes all needed columns)
CREATE INDEX idx_users_email_name ON users(email) INCLUDE (name);
```

PostgreSQL usa `INCLUDE` para columnas no clave. MySQL usa índices compuestos donde las columnas extra se agregan al final. Los índices de cobertura pueden mejorar drásticamente el rendimiento de lectura para patrones de consulta específicos.
</details>

## Conceptos Avanzados

<details>
<summary><strong>13. ¿Qué es una Common Table Expression (CTE) y cuándo la usarías?</strong></summary>
<br>

Una CTE es un conjunto de resultados temporal con nombre definido dentro de una sola consulta usando `WITH`:

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

Usa CTEs para: legibilidad (dividir consultas complejas en pasos lógicos), consultas recursivas (datos jerárquicos como organigramas) y reemplazar subconsultas complejas. Nota: En PostgreSQL < 12, las CTEs actúan como barreras de optimización (no se integran inline). En PostgreSQL 12+, las CTEs no recursivas pueden integrarse inline.
</details>

<details>
<summary><strong>14. ¿Qué son las funciones ventana y cómo difieren de GROUP BY?</strong></summary>
<br>

Las funciones ventana calculan un valor sobre un conjunto de filas **sin colapsar las filas en una sola** (a diferencia de GROUP BY).

```sql
-- GROUP BY: One row per department
SELECT department, AVG(salary) FROM employees GROUP BY department;

-- Window function: Every row, with department average added
SELECT name, department, salary,
       AVG(salary) OVER (PARTITION BY department) as dept_avg,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank
FROM employees;
```

Funciones ventana comunes: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`, `LAG()`, `LEAD()`, `SUM() OVER()`, `AVG() OVER()`. Esenciales para análisis, reportes y paginación.
</details>

<details>
<summary><strong>15. ¿Qué es un deadlock y cómo lo previenes?</strong></summary>
<br>

Un deadlock ocurre cuando dos transacciones esperan que la otra libere bloqueos, creando una dependencia circular. Ninguna puede proceder.

Ejemplo:
- La Transacción A bloquea la Fila 1, quiere la Fila 2.
- La Transacción B bloquea la Fila 2, quiere la Fila 1.
- Ambas esperan indefinidamente.

La base de datos detecta los deadlocks y mata una transacción (la "víctima"), revirtiéndola.

Prevención:
1. **Orden de bloqueo consistente**: Siempre bloquea recursos en el mismo orden en todas las transacciones.
2. **Transacciones cortas**: Mantén los bloqueos el tiempo mínimo necesario.
3. **Timeouts de bloqueo**: Configura `lock_timeout` para que las transacciones fallen rápido en lugar de esperar indefinidamente.
4. **Reducir el nivel de aislamiento**: Niveles de aislamiento más bajos requieren menos bloqueos.
</details>

## Seguridad

<details>
<summary><strong>16. ¿Qué es la inyección SQL y cómo la previenes?</strong></summary>
<br>

La inyección SQL ocurre cuando la entrada del usuario se concatena directamente en una consulta SQL, permitiendo a un atacante modificar la lógica de la consulta.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{user_input}'"
# If user_input = "' OR 1=1--", returns all users

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

Prevención:
1. **Consultas parametrizadas** (sentencias preparadas) — la defensa número 1. La entrada se trata como dato, nunca como SQL.
2. **ORM** (SQLAlchemy, Django ORM) — genera consultas parametrizadas automáticamente.
3. **Validación de entrada** — lista blanca de formatos esperados (IDs numéricos, patrones de email).
4. **Principio de mínimo privilegio** — el usuario de la base de datos solo debería tener SELECT/INSERT/UPDATE en las tablas necesarias, nunca DROP o GRANT.
</details>

<details>
<summary><strong>17. ¿Qué es el principio de mínimo privilegio en la seguridad de bases de datos?</strong></summary>
<br>

Cada usuario de base de datos o aplicación debería tener solo los permisos mínimos necesarios para realizar su trabajo.

```sql
-- Application user: Only needs CRUD on specific tables
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;
-- No DELETE, no DROP, no access to other tables

-- Admin user: Full access but should not be used by the application
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO admin_user;
```

Nunca uses el superusuario de la base de datos (postgres, root) para las conexiones de la aplicación. Si la aplicación se compromete a través de inyección SQL, el atacante solo obtiene los permisos del usuario limitado.
</details>

## Escenarios Prácticos

<details>
<summary><strong>18. ¿Cómo diseñas un esquema para una relación muchos-a-muchos?</strong></summary>
<br>

Usa una **tabla de unión** (también llamada tabla puente o tabla asociativa):

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

La tabla de unión contiene las claves foráneas a ambas tablas, creando la relación muchos-a-muchos. También puede contener atributos específicos de la relación (enrolled_at, grade).
</details>

<details>
<summary><strong>19. Escribe una consulta para encontrar el segundo salario más alto en cada departamento.</strong></summary>
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

Por qué `DENSE_RANK` sobre `ROW_NUMBER`: Si dos empleados empatan con el salario más alto, `DENSE_RANK` asigna correctamente el rango 2 al siguiente salario. `ROW_NUMBER` asignaría arbitrariamente los rangos 1 y 2 a los empleados empatados.
</details>

<details>
<summary><strong>20. ¿Cómo manejas las migraciones de base de datos en producción?</strong></summary>
<br>

1. **Usa una herramienta de migración**: Flyway, Liquibase (Java), Alembic (Python/SQLAlchemy), Django migrations, Prisma Migrate. Nunca ejecutes DDL crudo en producción.
2. **Versiona las migraciones**: Cada migración es un archivo numerado en el repositorio. Las migraciones se aplican en orden y se registran en una tabla de metadatos.
3. **Cambios retrocompatibles**: Agrega nuevas columnas como nullable primero. Despliega el código de la aplicación que usa la nueva columna. Luego agrega una restricción NOT NULL si es necesario. Nunca renombres o elimines columnas sin un período de deprecación.
4. **Prueba las migraciones**: Ejecútalas contra una copia staging de los datos de producción antes de aplicarlas en producción.
5. **Plan de rollback**: Cada migración debería tener un script de rollback correspondiente. Prueba los rollbacks antes del despliegue.
6. **Zero-downtime**: Usa técnicas como patrones de expansión/contracción, tablas fantasma (gh-ost para MySQL) o DDL en línea (ALTER TABLE no bloqueante de PostgreSQL).
</details>
