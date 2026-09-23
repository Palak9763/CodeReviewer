import re
from typing import Any, Dict, List
Finding = Dict[str, Any]
def _finding(category: str, severity: str, line: int, message: str, fix: str) -> Finding:
    return {"category": category,"severity": severity,"line": line,"message": message,"suggested_fix": fix,}
def scan_vulnerabilities(code: str, language: str | None = None) -> Dict[str, Any]:
    """Pure heuristic scanner. Returns JSON-serializable findings."""
    if not isinstance(code, str):
        raise TypeError("code must be a string")

    findings: List[Finding] = []
    lines = code.splitlines()

    def add(category, severity, i, message, fix):
        findings.append(_finding(category, severity, i + 1, message, fix))

    for i, line in enumerate(lines):
        s = line.strip()
        low = s.lower()
        if re.search(r'\b(api[_-]?key|secret|password|passwd|token|access[_-]?key)\b\s*[:=]\s*["\'][^"\']{4,}["\']', s, re.I):
            add("Hardcoded secret/credential", "high", i,
                "A credential-like value is hardcoded in source code.",
                "Move secrets to environment variables or a secret manager and rotate exposed credentials.")

        if re.search(r'\b(eval|exec)\s*\(', s):
            add("Dynamic code execution", "high", i,
                "eval()/exec() can execute attacker-controlled code when given untrusted input.",
                "Avoid dynamic execution; use explicit parsing, validation, and allow-listed operations.")

        sql_kw = re.search(r'\b(select|insert|update|delete)\b', s, re.I)
        if sql_kw and (("+" in s) or re.search(r'\bf["\']', s)):
            add("SQL injection", "high", i,
                "SQL appears to be constructed with string concatenation or interpolation.",
                "Use parameterized queries/prepared statements and pass user data as bound parameters.")

        if re.search(r'\b(subprocess\.(run|Popen|call|check_call|check_output)|os\.system)\s*\(', s) and re.search(r'\bshell\s*=\s*True\b', s):
            add("Command injection", "high", i,
                "A subprocess call enables shell interpretation, which is dangerous with untrusted input.",
                "Avoid shell=True and pass arguments as a list; validate/allow-list any user-controlled arguments.")

        if re.search(r'\bpickle\.loads?\s*\(', s):
            add("Insecure deserialization", "high", i,
                "pickle can execute dangerous object behavior when loading untrusted data.",
                "Do not unpickle untrusted data; use a safe data format such as JSON with schema validation.")
        if re.search(r'\byaml\.load\s*\(', s) and not re.search(r'SafeLoader', s):
            add("Insecure deserialization", "high", i,
                "yaml.load without SafeLoader may construct unsafe Python objects.",
                "Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).")

        if re.search(r'\b(hashlib\.)?(md5|sha1)\s*\(', s, re.I):
            add("Weak/deprecated hashing", "high", i,
                "MD5/SHA-1 are not suitable for password hashing.",
                "Use a password-hashing scheme such as Argon2id, scrypt, or bcrypt with appropriate parameters.")

        if re.search(r'\b(request\.(args|form|json|data)|input\s*\()', s):
            nearby = "\n".join(lines[max(0, i-2):min(len(lines), i+3)])
            if not re.search(r'\b(validate|validation|sanitize|escape|schema|isinstance|len\s*\()', nearby, re.I):
                add("Missing input validation", "medium", i,
                    "User-controlled input is used without nearby validation or sanitization.",
                    "Validate type, length, format, and allowed values before using the input.")
                
    unique = []
    seen = set()
    for f in findings:
        key = (f["category"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    unique.sort(key=lambda x: (-severity_rank.get(x["severity"], 0), x["line"]))

    return {"language": language,"findings": unique,"finding_count": len(unique),}
