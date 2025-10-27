# 13 - SQL Injection

## Introduction
- SQL (Structured Query Language) is the standard language for interacting with relational databases (MySQL, PostgreSQL, SQL Server). SQL Injection is a vulnerability that occurs when untrusted input is embedded into SQL queries, allowing attackers to modify or exfiltrate data.

## Short history & impact
- Emerged in the late 1990s with dynamic web apps. Remains a high‑impact vulnerability leading to data theft, corruption or deletion, and full system compromise.

## Classification of SQL Injection
- In‑band (same channel): attacker retrieves data via the same channel (common).
	- Error‑based: force DB errors to reveal information.
	- Union‑based: append `UNION SELECT ...` to extract rows from other tables.
- Blind: no direct output; infer data via boolean or time delays.
	- Boolean‑based: observe true/false responses.
	- Time‑based: use `SLEEP()` or similar to detect true conditions.
- Out‑of‑band: extract data via a different channel (DNS/HTTP callbacks).

## Why it happens (common causes)
- Dynamic query construction with unsanitized user input.
- Insufficient input validation and verbose error messages.
- Excessive database privileges for application accounts.

## SQL basics (useful commands & examples)
- Connect to MySQL: `mysql -u root -p`.
- Show databases: `SHOW DATABASES;` — system DBs: `information_schema`, `mysql`, `performance_schema`, `sys`.
- Create DB: `CREATE DATABASE fogolo_app;` and `USE fogolo_app;`.
- Table creation example:
	- `CREATE TABLE Persons (PersonID int, LastName varchar(255), FirstName varchar(255), Address varchar(255), City varchar(255));`
- Insert/select/update/delete examples shown in source — remember `;` terminates statements.
- UNION operator combines resultsets (must match column count & types).

## Common SQL Injection examples (from source)
- Dynamic/unsafe PHP/Python example:
	- Unsafe: `$query = "SELECT * FROM users WHERE username = '$username'";`
	- Safe: use prepared statements / parameterized queries (`prepare()` / `?` placeholders).
- Login bypass payload example: `admin' --` turns `SELECT * FROM users WHERE username='admin' --' AND password=''` and bypasses password checks.

## In‑band: Union & Error based
- UNION technique: determine number of columns (ORDER BY or trial `UNION SELECT 1,2,...`) then substitute functions (e.g., `USER(), DATABASE(), VERSION()`) into a working `UNION SELECT` to extract data.
- Error‑based: craft payloads that cause DB errors revealing metadata.

## Blind techniques
- Boolean‑based: inject conditions and observe page differences for true/false results (e.g., `substring(password,1,1)='a'`).
- Time‑based: use DB sleep functions to infer truth via response latency (e.g., `IF(condition, SLEEP(10), 0)`).

## Out‑of‑band
- Trigger the database to make an outbound request (DNS/HTTP) to an attacker‑controlled host to leak data (e.g., `load_file()` or concatenated DNS exfiltration techniques described in source).

## NoSQL mention
- Non‑relational DBs (MongoDB, etc.) have different data models and can be vulnerable to NoSQL injection variants — validate inputs and use drivers' parameter APIs.

## Practical testing examples & tips
- Start by identifying injectable parameters (search, id, login fields).
- Test with simple payloads like `' OR 1=1#` to detect injection.
- For UNION: find number of columns then use `UNION SELECT 1,2,3...` and replace columns with functions to leak data (e.g., `USER(), DATABASE(), VERSION()`).

## Login bypass example (Python/SQLite)
- Unsafe pattern: `query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"` — vulnerable to `' OR 1=1--`.
- Fix: parameterized queries: `cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))`.

## Protecting against SQL Injection (core defenses)
1. Parameterized queries / prepared statements — separate code from data.
2. Input validation and whitelisting (reject unexpected formats).
3. Principle of least privilege — grant DB accounts minimal rights.
4. Limit error messages — log internals, show generic errors to users.
5. Keep DBMS and frameworks patched.
6. Use a WAF as an additional layer to block common patterns.

## DB admin & runtime notes
- Be mindful of special characters (quotes, `--`, `/* */`, `;`) and how they affect queries.
- Logical operators: `AND`, `OR`, `NOT` (or `&&`, `||`, `!` in some contexts) are useful for boolean tests.

## Quick checklist for secure development
- Use parameterized queries for all DB access.
- Validate input server‑side (whitelist when possible).
- Limit privileges for application DB users.
- Sanitize or avoid exposing raw DB errors to users.
- Monitor unusual queries and use WAF/logging for early detection.


