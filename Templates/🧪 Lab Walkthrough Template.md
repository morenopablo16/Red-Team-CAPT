<%*
const platform = await tp.system.prompt("Platform (HTB / THM / Other)");
const machine = await tp.system.prompt("Machine Name");
const ip_address = await tp.system.prompt("IP Address (Real IP for working)"); // Capturamos la IP real
const os_type = await tp.system.suggester(["Linux", "Windows", "Other"], ["Linux", "Windows", "Other"]); // Suggester para OS
const difficulty = await tp.system.suggester(["Easy 🟢","Medium 🟡","Hard 🔴","Insane 🟣"],["Easy","Medium","Hard","Insane"]);

// Renombrar el archivo
await tp.file.rename(platform + "_" + machine);

// Construir el YAML frontmatter con campos iniciales y placeholders para después
let frontmatter = "---\n";
frontmatter += "platform: " + platform + "\n";
frontmatter += "machine_name: " + machine + "\n";
frontmatter += "ip_address: " + ip_address + "\n"; // IP real para referencia
frontmatter += "os: " + os_type + "\n"; // OS en frontmatter
frontmatter += "difficulty: " + difficulty + "\n";
frontmatter += "date_created: " + tp.date.now("YYYY-MM-DD") + "\n"; // Fecha de creación
frontmatter += "date_completed: \n"; // Campo vacío para rellenar después
frontmatter += "status: In Progress\n"; // Estado inicial por defecto
frontmatter += "tags:\n";
frontmatter += "  - " + platform.toLowerCase().replace(/\s/g, '-') + "\n"; // Tag de plataforma (ej. htb)
frontmatter += "  - " + os_type.toLowerCase().replace(/\s/g, '-') + "\n"; // Tag de OS (ej. linux)
// Aquí no pedimos tags adicionales al inicio, se añadirán después
frontmatter += "vulnerabilities_found: \n"; // Campo vacío para rellenar después
frontmatter += "exploit_method_foothold: \n"; // Campo vacío para rellenar después
frontmatter += "exploit_method_privesc: \n"; // Campo vacío para rellenar después
frontmatter += "---\n\n";

// Añadir el título principal
tR += frontmatter;
tR += "# " + machine + " — " + platform + "\n\n";
%>

---

## Scope
- Targets: <% ip_address %> / domain

## Enumeration
- Commands:
```
 nmap -p- --open -n --max-retries 5000 -sS -vvv -Pn {target_ip} -oG allPorts
```
- Findings: (ports / services / versions)
- Web discovery: (vhosts / directories / robots / sitemap)
- Notes:

## Foothold
- Entry point:
- Exploit steps (PoC):
- Payloads used:

## PrivEsc
- Method:
- Evidence (flag & id):

## Remediation
- Short steps for admins to fix the issue.

## Lessons learned
- Key takeaways.

