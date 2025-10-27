# Social Engineering — Phishing (Expanded Study Notes)

Purpose: fuller study notes for students. Keep these for awareness and authorized training only.

1) What is phishing?
- Phishing is a social engineering technique that uses deceptive messages to trick people
  into revealing credentials, clicking malicious links, or running malware.

2) Why phishing works
- Attackers exploit common human traits: urgency, curiosity, trust in authority, and
  routine. Under time pressure people are more likely to miss red flags.

3) Common phishing variants
- Mass phishing: bulk emails or SMS with generic bait.
- Spear phishing: targeted messages tailored to a person, role, or company.
- Clone phishing: a legitimate email is copied and altered to include malicious links.
- Whaling: phishing aimed at executives or high-value targets.
- Vishing: social engineering over the phone.

4) Typical attacker goals
- Steal credentials (email, VPN, cloud services).
- Financial fraud (invoice manipulation, wire transfers).
- Deploy malware (ransomware, stealer, backdoor).
- Gather intelligence for later stages of an attack.

5) Common indicators of phishing
- Sender domain slightly misspelled or unfamiliar subdomain.
- The displayed link text differs from the actual URL.
- Generic salutations or missing personalized details.
- Unusually urgent language requesting immediate action.
- Poor spelling, grammar, or inconsistent logos/branding.
- Unexpected attachments, especially macros or executables.

6) Practical user defenses
- Pause and think: treat unexpected or urgent requests as suspicious.
- Hover links to reveal the actual destination before clicking.
- Use bookmarks or official apps for sensitive logins instead of links.
- Do not enable macros in Office documents unless verified.
- Use strong, unique passwords and a password manager.
- Enable multi-factor authentication (MFA) on all important accounts.

7) Organizational controls and best practices
- Enforce email authentication: SPF, DKIM, and DMARC with reporting (RUA/RUF).
- Use secure email gateways that perform URL rewriting and sandboxing.
- Block dangerous attachment types at the mail perimeter.
- Conduct periodic phishing simulations and follow-up micro-training.
- Provide an easy way for staff to report suspected phishing to security.

8) Step-by-step email analysis (safe workflow)
1. Don’t click links or open attachments in the suspect message.
2. View the full headers ("Show original" / "View source") to inspect routing.
3. Trace the Received headers to identify the origin IP and hops.
4. Compare the From domain, Return-Path, and DKIM signer for mismatches.
5. Check SPF and DKIM authentication results and DMARC policy.
6. If required, paste URLs into VirusTotal or a safe sandbox, never visit from
   a corporate workstation.

9) Handling attachments safely
- Save attachments to a secure, isolated analysis host or sandbox.
- Scan with multiple engines (VirusTotal) and consider dynamic execution in
  a controlled environment.
- Prefer blocking macro-enabled documents at the gateway, and require
  documented business justification to allow them.

10) Useful defender resources and feeds
- OpenPhish and PhishTank: community feeds for reported phishing URLs.
- URL/file scanners: VirusTotal, Hybrid-Analysis, and other sandbox providers.
- Simulation tools: GoPhish — run internal training campaigns.

11) Small, safe example (educational)
- Example subject: "Action required — verify your account".
- Red flags: sender domain is "support@bank-secure[.]com" while official bank
  domain is "bank.com"; link goes to a non-bank domain.

12) Incident response if a user clicks or submits data
- Immediately reset the compromised account password and revoke sessions.
- Revoke any exposed tokens, keys, or application credentials.
- Isolate and scan the user endpoint for indicators of compromise.
- Notify internal stakeholders and, if required, customers or partners.
- Preserve logs and samples for forensics and post-incident analysis.

13) Legal / ethical constraints
- Never perform active phishing or payload distribution without written
  authorization and proper safety controls.
- Simulations must have documented scope, opt-outs, and privacy protections.

14) Training recommendations
- Use short, focused simulations followed by immediate, actionable feedback.
- Show the exact indicators that should have been noticed and how to report them.
- Make reporting easy and non-punitive; recognise users who report real incidents.

15) Quick one-page checklist for students (printable)
- Verify the sender domain and check headers if unsure.
- Do not follow links in unexpected messages; use bookmarks.
- Don’t enable macros or execute unknown files.
- Use MFA and unique passwords; report suspicious messages.

16) Summary — key takeaways
- Phishing is a human-focused risk that is mitigated by awareness,
  authentication controls, and layered technical defenses.
- The combination of user vigilance, MFA, email authentication, and
  proactive detection makes successful phishing much harder.

