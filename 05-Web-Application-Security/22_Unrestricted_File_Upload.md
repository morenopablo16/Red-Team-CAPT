# 22 - Unrestricted File Upload

## Introduction
- Unrestricted File Upload vulnerabilities arise when a web application accepts and stores user-uploaded files without adequate validation (type, size, name, content). Attackers can exploit this to upload web shells or other malicious files, often leading to Remote Code Execution (RCE) and full server compromise.

## How the vulnerability works (high level)
1. User uploads a file (e.g., profile picture, CV).
2. Server performs insufficient validation (or none) on type/size/content/extension.
3. Server stores the file in a web-accessible location.
4. Attacker uploads a malicious file (web shell) and executes it via the exposed path.

## Impacts
- Unauthorized access to sensitive files and data
- Data manipulation or deletion
- Service disruption
- Backdoor installation / persistent access

## Key concepts & terminology
- Backdoor: hidden script installed by an attacker for persistent access.
- File extension: filename suffix (e.g., .jpg, .php); attackers may rename files to bypass checks.
- Whitelist/Blacklist: allow-list or block-list filters for file types/extensions.
- Web shell: uploaded script (PHP/ASP/JSP/Python/Node) that executes commands on the server.
- MIME type: declared content type (e.g., image/png); can be forged.
- File inclusion: attacker may later include uploaded files in application logic.
- Directory traversal: using `../` sequences to escape intended directories.
- File size limit: maxima for uploaded files; attackers may use compression/fragmentation to bypass limits.

## Detection checklist (what to test)
- Check whether file upload inputs validate type, extension, and MIME.
- Upload different extensions: image(.jpg/.png), script(.php/.asp/.jsp), binary(.exe).
- Upload files with manipulated MIME types (e.g., `.php` with `image/png`).
- Upload files with modified content (insert PHP into a GIF/JPEG).
- Attempt directory traversal in filename: `../../secret.txt`.
- Confirm whether uploaded files are stored in a web-accessible directory and executed.

## Testing methods / exploitation vectors
- File type validation: try `.php`, `.asp`, `.jsp`, `.exe` and image/script mixes.
- File content validation: embed server-side code inside an allowed-format file and upload.
- MIME type manipulation: set Content-Type to `image/png` while uploading a PHP file.
- File name/path attacks: attempt dangerous characters and traversal sequences in uploaded filenames.
- File size tests: submit oversized files and see how the server enforces limits.

## Vulnerable PHP example (unsafe upload)
```php
<?php
if( isset($_POST['submit']) ){
	$tmpName = $_FILES['input_image']['tmp_name'];
	$fileName = $_FILES['input_image']['name'];

	if(!empty($fileName)){
		if(!file_exists("uploads")){
			mkdir("uploads");
		}
		$uploadPath = "uploads/".$fileName;
		if( @move_uploaded_file($tmpName,$uploadPath) ){
			$status = "success";
		}else{
			$status = "unsuccess";
		}
	}else{
		$status = "empty";
	}
}
?>
```

## Secure handling recommendations (PHP examples)
- Validate MIME type and extension against a whitelist.
- Sanitize filenames, avoid using user-supplied names directly.
- Store uploads outside the web root or use randomized filenames and deny execution.
- Set safe directory permissions and avoid executing uploaded content.
- Example: MIME & extension checks + safe move
```php
<?php
if( isset($_POST['submit']) ){
	$allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
	$allowedExtensions = ['jpg','jpeg','png','gif'];

	$fileType = mime_content_type($_FILES['input_image']['tmp_name']);
	$tmpName = $_FILES['input_image']['tmp_name'];
	$fileName = basename($_FILES['input_image']['name']);
	$fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

	$uploadPath = 'uploads/' . $fileName;
	if (in_array($fileType, $allowedTypes) && in_array($fileExtension, $allowedExtensions)) {
		if (file_exists($uploadPath)) {
			$status = 'file_exists';
		} else {
			if (!file_exists('uploads')) mkdir('uploads', 0755);
			if (@move_uploaded_file($tmpName, $uploadPath)) $status = 'success';
			else $status = 'unsuccess';
		}
	} else {
		$status = 'invalid_type_or_extension';
	}
}
?>
```

## Common filter bypass techniques (from source)
- MIME type tampering: set Content-Type to `image/png` while uploading a `.php` file.
- File signature / magic header: prepend image magic bytes (e.g., `GIF89a`) to bypass signature checks.
- Extension variants: use alternate executable extensions (e.g., `.php5`, `.phtml`, `.phar`, etc.).
- .htaccess tricks: upload a file with a benign extension and place an `.htaccess` to map that extension to PHP (`AddType application/x-httpd-php .bypass`).
- Null byte tricks (historical PHP): `cmd.php%00.jpg` to truncate enforced suffix (older PHP versions).
- Case sensitivity: varying extension case may bypass naive checks (`CMD.PHP`).

## Web shells & PoCs (provided examples)
- PHP simple web shell:
```php
<?php
if (isset($_GET['cmd'])) {
	system($_GET['cmd']);
}
?>
```
PoC (example): `http://example.com/shell.php?cmd=whoami`

- ASP, JSP, Python, Node.js examples were provided in source as reference web shells (use only in authorized labs).

## Defensive checklist / mitigations
1. Whitelist allowed file types and extensions (never rely on client-supplied MIME).
2. Validate file content server-side (magic bytes + application-level checks), but treat content checks as defense-in-depth only.
3. Store uploads outside web root or deny execution on the uploads directory (web server config).
4. Sanitize and randomize filenames; avoid original names when storing.
5. Enforce strict file size limits and quotas.
6. Use strict directory permissions and run web processes with least privilege.
7. Disable dangerous server settings (e.g., don't allow arbitrary processing of unknown extensions).
8. Use WAF rules to detect suspicious upload patterns and block common bypass payloads.
9. Conduct code review, secure coding practices, and periodic penetration testing.




