# 25 - Insecure Direct Object Reference (IDOR)

## Introduction

IDOR (Insecure Direct Object Reference) is a significant security vulnerability that occurs when authorization checks are not properly implemented, allowing malicious users to access data or resources that do not belong to them.

For example, if a transaction number is directly included in a transaction URL and this number can be manipulated to provide a different transaction number, it is possible to access another user's transaction information. A simple example:

https://example.com/transaction?id=1234

If the `id` parameter in this URL is changed (for instance, to `id=1235`), another user's transaction information can be viewed. This is a classic example of an IDOR vulnerability caused by the developer's failure to implement adequate authorization checks.

IDOR means that the web application gives a direct reference to an object in the system, such as a transaction number or user ID, but this reference is visible to everyone, directly accessible, and left without any validation or access control. In 2007, OWASP introduced this term in the A4 category of its "OWASP Top 10" project. Later (2017) it was merged with other access control vulnerabilities under the heading "Broken Access Control," and in 2021 it continued as "A1 Broken Access Control."

## How Do IDOR Vulnerabilities Occur?

Most web applications use simple unique identifiers to mark objects on the server side. For example, a user in a database is typically represented by a unique user ID. This same ID is used as the primary key in the database column containing user information and is often generated as an automatically incrementing integer value.

These IDs are often used in URLs or HTTP requests, making them accessible to attackers. Attackers can change IDs or try random values. If access control is lacking, they can access other users' data.

## Common IDOR Vulnerability Examples

1. Password Change Forms

If a URL parameter is used to identify the user in a password change form, attackers can change this ID to reset the password of other accounts.

```
https://example.com/change_password.php?userid=1701
```

2. File Access

URLs containing file names or directory structures can often lead to unauthorized access to filesystem resources.

```
https://example.com/display_file.php?file.txt
```

An attacker can replace `file.txt` with directory traversal characters to access a sensitive file, such as `/etc/passwd`:

```
https://example.com/display_file.php?../../../etc/passwd
```

## Detecting IDOR Vulnerabilities

Since IDOR is a logical vulnerability, it cannot always be detected by security scanning tools. Therefore, manual penetration testing and security-focused code reviews are required.

### Techniques

- Parameter manipulation (GET/POST/JSON/XML/form-data).
- Authentication and authorization testing across different roles.
- Manual code review focused on access control and direct object references.
- Use of proxy tools (Burp Suite, OWASP ZAP) to intercept and fuzz parameters.
- Review of server and database logs for suspicious enumeration attempts.

## How to Protect Against IDOR Attacks

The only reliable way to protect against IDOR is to implement strict access control checks for all sensitive objects. Modern frameworks (such as Ruby on Rails, Django) can make access control easier when used properly. Key protections include:

- Access controls: Validate every object access and ensure the requesting user has right to the object.
- Authentication: Ensure authenticated users can only access their own resources.
- Remove direct references: Use indirect references or cryptographically unguessable identifiers (UUIDs, opaque tokens) instead of sequential IDs.
- Data minimization: Return only the fields required by the client.
- Logging and monitoring: Detect mass enumeration and suspicious patterns.

## Detecting IDOR: Practical Approaches

1. Parameter Manipulation

IDOR vulnerabilities often occur through identifier parameters in URLs, POST data, or other client-server communications. Strategies:

	- Review and alter URL parameters. Look for `userId`, `orderId`, `fileId`, `invoice_id`, etc.

```
https://example.com/profile?id=1001
https://example.com/profile?id=1002
```

	- Review and manipulate POST parameters in forms and APIs (JSON, XML, form-data).

```json
{
	"transaction_id": 4321
}
```

2. Authentication and Authorization Testing

	- Authorized vs. unauthorized testing (different user accounts/roles).
	- Inter-user role testing to check for data exposure between roles.

3. Automated Tools

Automated scanners can help with coverage but may miss logical flaws.

	- Use Burp Suite or OWASP ZAP for crawling, parameter discovery, and parameter fuzzing.
	- Use Intruder-style bulk testing to mutate ID values.

4. Comprehensive Log Reviews

	- Inspect access logs and database logs for repeated ID probing patterns.

5. Security-Focused Code Reviews

	- Ensure access control checks exist for each API/function.
	- Look for direct use of primary keys in client-visible parameters.

## Mass IDOR Scanning and Enumeration

Mass IDOR Enumeration is the process of discovering IDOR vulnerabilities at scale by systematically manipulating identifiers. Attackers use manual and automated techniques to enumerate IDs and access multiple objects.

### Purpose

- Bulk data access and data leakage.
- System manipulation by enumerating many objects.

### Methods

a. Manual Testing

	- Sequential ID trials (e.g., `id=1000`, `id=1001`, ...).
	- List-based trials using previously discovered valid IDs.
	- Test both GET and POST parameters.

b. Automated Scanning

	- Fuzzing (Burp Intruder, ZAP) to systematically change parameter values.
	- Scraping pages/APIs to collect IDs then enumerating them offline or in bulk.

### Risks

- Large-scale data breaches.
- Potential to overload and crash backend systems when performed aggressively.
- Unauthorized actions on accessed resources (modification, deletion).

## Example Applications / Lab Walkthroughs

Below are example lab solutions demonstrating IDOR vulnerabilities and how they are exploited in practice.

### Invoices (Lab)

When visiting the application, the invoice list shows a View button with an `invoice_id` parameter in the URL. By changing the `invoice_id` value, we can attempt to access other users' invoices.

If changing the `invoice_id` to another value shows a different user's invoice (e.g., Jane Smith), that confirms an IDOR vulnerability for invoices.

### Ticket Sales (Lab)

In this lab, the purchase flow includes form data where `ticket_money` is sent from the client. Because the client can edit this value (via browser DevTools or a proxy), a user can reduce the ticket price and complete a purchase despite insufficient balance.

Steps commonly used in labs:

1. Open DevTools (Inspect) and locate the hidden `ticket_money` form input.
2. Edit the `value` attribute from `300` to an affordable amount (for example `10`).
3. Submit the purchase form. If the server does not validate the price or authorize the action based on server-side checks, the purchase succeeds.

This demonstrates an IDOR-style issue where client-supplied values that should be server-controlled are trusted.

## Methods of Protecting Against IDOR (Detailed)

1. Authorization Checks (Server-Side)

Authorization determines what data and resources an authenticated user can access. Always verify that the authenticated user is authorized to access the requested object.

Example (Flask):

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# Sample order data stored in the database
orders = {
		1: {"user_id": 1, "details": "Order 1 details"},
		2: {"user_id": 2, "details": "Order 2 details"}
}

# Authenticated user information (example)
logged_in_user = {"id": 1, "username": "user1"}

@app.route('/order/<int:order_id>', methods=['GET'])
def get_order(order_id):
		order = orders.get(order_id)
    
		if order and order['user_id'] == logged_in_user['id']:
				return jsonify(order), 200
		else:
				return jsonify({"error": "Unauthorized access"}), 403

if __name__ == '__main__':
		app.run(debug=True)
```

In this example, each `order_id` access is checked against the authenticated user's `user_id`.

2. Use of Indirect Object References

Using opaque or unguessable references (UUIDs, random tokens, or one-time references) makes it harder for attackers to guess valid object identifiers.

Example: UUIDs

```python
import uuid

# UUID generation
user_uuid = str(uuid.uuid4())
print(f"User UUID: {user_uuid}")

# Storing user data with UUID
users = {
		user_uuid: {"username": "user1", "email": "user1@example.com"}
}

@app.route('/user/<uuid:user_id>', methods=['GET'])
def get_user(user_id):
		user = users.get(str(user_id))
    
		if user:
				return jsonify(user), 200
		else:
				return jsonify({"error": "User not found"}), 404
```

UUIDs are much harder to enumerate than small integers.

3. Data Minimization

Return only necessary data from endpoints to limit what an attacker can learn about the system structure.

Example: Limiting JSON response

```python
@app.route('/user/info', methods=['GET'])
def get_user_info():
		# Sample user data
		user_info = {
				"username": "user1",
				"email": "user1@example.com",
				"phone": "1234567890",
				"address": "123 Main St."
		}

		# Return only the necessary information
		response_data = {
				"username": user_info["username"],
				"email": user_info["email"]
		}

		return jsonify(response_data), 200
```

4. Logging and Monitoring

Keep logs for suspicious behaviors and set alerts for patterns consistent with mass enumeration (many sequential requests, repeated 403s, or same account probing many object IDs).

5. Security Testing

	- Manual penetration testing focused on access-control checks.
	- Use automated scans (Burp, ZAP) as part of a larger manual review.

## Summary / Key Takeaways

- IDOR is a logical authorization vulnerability caused by exposing direct references to internal objects without server-side access checks.
- Protect by enforcing server-side authorization checks, using indirect/unguessable object references, minimizing returned data, and logging/monitoring for enumeration patterns.
- Automated scanners help, but manual testing and code reviews are essential to find logical IDOR issues.

---



