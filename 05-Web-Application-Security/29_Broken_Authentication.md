# 29 - Broken Authentication

## Introduction

What is Broken Authentication?

Broken Authentication is a security vulnerability that allows attackers to gain unauthorized access due to weaknesses or misconfigurations in authentication mechanisms. These vulnerabilities often stem from weak passwords, session management errors, easily guessable security questions, and ineffective implementation of multi-factor authentication (MFA).

In modern applications, authentication is a crucial component that ensures users can securely access their accounts. However, vulnerabilities or errors in authentication mechanisms can lead to attackers exploiting these systems and gaining unauthorized access. This can result in severe consequences such as account takeovers, leakage of sensitive information, and even complete system control.

### Authentication vs Authorization

Authentication is the process of verifying the identity of a user or system (e.g., username/password, biometric data). Authorization determines what resources or actions an authenticated user is permitted to access.

## Common Causes of Broken Authentication

- Weak Password Policies: Users employing weak or easily guessable passwords make accounts vulnerable to brute force and dictionary attacks.
- Session Management Errors: Insecure session handling can lead to session hijacking and credential theft.
- Default Credentials: Failing to change factory/default usernames and passwords allows attackers easy access.
- Misconfigured Authentication Mechanisms: Configuration errors can open unintended access paths.
- Lack of MFA: Not using MFA or implementing it incorrectly greatly increases risk.

## Authentication Methods

1. Password-Based Authentication

	- Advantages: Simple to implement and understand.
	- Disadvantages: Vulnerable to weak passwords, reuse, brute force, and dictionary attacks.

2. Multi-Factor Authentication (MFA)

	- Advantages: Adds extra security by requiring multiple factors (knowledge, possession, biometric).
	- Disadvantages: May complicate UX and incur additional cost.

3. Biometric Authentication

	- Advantages: Hard to replicate; unique to users.
	- Disadvantages: Privacy concerns and higher cost.

4. One-Time Passwords (OTP)

	- Advantages: Protects against phishing and MITM when used properly.
	- Disadvantages: Can add friction and require extra devices.

5. Hardware Tokens

	- Advantages: High security by requiring physical possession.
	- Disadvantages: Risk of loss and additional cost.

## Gathering Information on Usernames (Username Enumeration)

Username enumeration is the process by which attackers learn valid usernames using differences in error messages, password reset flows, registration forms, or timing differences.

### Username Enumeration via Error Messages

Different error messages for invalid username vs invalid password allow attackers to verify usernames.

Bad (vulnerable) examples:

- "The username is correct, but the password is incorrect."
- "Invalid username."
- "Account is disabled."

Good (uniform) messages:

- "Login failed; invalid username or password."

### Password Reset Functions

If password reset flows reveal whether a username/email exists (e.g., "Password reset link has been sent" vs "Username does not exist"), attackers can enumerate accounts.

## Default Credentials

Default credentials are factory-set username/password pairs that must be changed during setup. Leaving them in place is a common cause of compromise across devices, databases, admin panels, and IoT devices.

Risks:

- Easy access using public documentation.
- Automated attacks and credential stuffing.
- Widespread impact when the same defaults are used across devices.

Examples & preventive measures:

1. Network Devices / Admin Panels
	- Example: `admin` / `admin`
	- Prevent: Change defaults, restrict management interfaces.

2. Databases
	- Example: `root` / `root`
	- Prevent: Set strong passwords, limit DB access to allowed IPs.

3. IoT Devices
	- Example: `admin` / `12345`
	- Prevent: Change defaults, segment networks.

4. Web Apps and Management Panels
	- Example: `admin` / `password`
	- Prevent: Enforce password change on setup.

## Lack of Brute-Force Protection

Brute force attacks systematically try username/password combinations. They succeed more easily when weak passwords, predictable usernames, or absent protections are present.

Types:

- Username brute force: try many usernames to discover valid accounts.
- Password brute force: try many passwords once a username is known.

Protection methods:

1. Rate Limiting
	- Limit number of attempts per IP or account (e.g., block after 5 failed attempts for 10 minutes).

2. Account Lockout
	- Temporarily lock accounts after repeated failed attempts (with care to avoid account lockout abuse).

3. Use of Captcha
	- Introduce CAPTCHA after a number of failed attempts to slow automated attacks.

4. Multi-Factor Authentication
	- Require a second factor to make password-only attacks ineffective.

## Weak Cookies and Session Management

Cookies store session identifiers and other client state. Improper cookie configuration or weak session IDs lead to session hijacking or replay attacks.

Common cookie problems and mitigations:

- Unsecure Transmission: Always use HTTPS and set the Secure flag.
- Long-lived Cookies: Use short session lifetimes and invalidate on logout.
- Predictable Values: Generate session IDs using cryptographically secure RNGs.
- Missing Flags: Set HttpOnly and SameSite flags appropriately.

## Object Injection (Mass Assignment)

Object injection and mass assignment occur when user-supplied data is assigned directly to object properties without filtering. Attackers may set protected fields (e.g., `is_admin`) during account creation or profile updates.

Risks:

- Privilege escalation (set `is_admin = true`).
- Data manipulation and logic bypass.

Countermeasures:

- Secure assignment: assign only expected fields explicitly.
- Whitelisting: permit only specific fields (preferred).
- Blacklisting: block unsafe fields (less reliable).
- Use ORM safeguards (e.g., `attr_protected` or permit/require patterns).

## Example: Mass Assignment in PHP

```php
class User {
		public $username;
		public $password;
		public $is_admin = false;
}

$data = $_POST['user_data'];
$user = new User();
foreach ($data as $key => $value) {
		$user->$key = $value; // unsafe
}

// Attacker can include `is_admin` in the POST data and set it to true
```

Safer approach: only assign explicit fields from input.

## Application / Lab Walkthrough: Execution After Redirect (EAR)

Execution After Redirect (EAR) is a vulnerability where sensitive data or code is accessible or executed after a redirect, often because the redirect flow exposes information before authentication completes or post-redirect logic isn't properly controlled.

To solve the lab and analyze EAR issues, use an HTTP proxy (e.g., Burp Suite) to intercept requests and responses and inspect redirects and any data returned prior to authentication.

Typical steps:

1. Open Burp Proxy and enable interception.
2. Open the lab site in the proxied browser and observe requests and redirections.
3. Inspect responses prior to login for exposed data.

If user data (e.g., a phone number) is present in responses before authentication completes, that indicates a problem.

## Preventing Broken Authentication Vulnerabilities

1. Strong Password Policies
	- Minimum length (e.g., 12+ characters).
	- Require mix of upper/lowercase, numbers, and symbols.
	- Block common/risky passwords.

2. Multi-Factor Authentication (MFA)
	- Deploy MFA for sensitive actions and logins.

3. Session Management Improvements
	- Use secure random session IDs, set Secure/HttpOnly flags.
	- Idle and absolute timeouts; invalidate session on logout.

4. User Account Security
	- Rate limiting, account lockout, and verified password resets.

5. Error Message Security
	- Use uniform error messages: avoid revealing whether username or password is incorrect.

6. Secure Cookie Management
	- Enforce Secure, HttpOnly, and SameSite flags.

7. User Education and Awareness
	- Train users on phishing, strong password creation, and MFA usage.

## Summary / Key Takeaways

- Broken Authentication arises from weak or incorrectly implemented authentication and session controls.
- Mitigate by enforcing strong password policies, MFA, robust session management, rate limiting, and secure error messages.
- Regular testing (pen tests, code reviews, and automated scans) helps detect broken authentication before attackers exploit it.

---

Explore the labs in this repository to practice detecting and fixing broken authentication issues.


