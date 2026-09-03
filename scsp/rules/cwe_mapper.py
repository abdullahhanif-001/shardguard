"""CWE / OWASP mapping for findings."""

from __future__ import annotations

from typing import Any

OWASP_CWE_MAP = {
    "eval": ("A03:2021", "CWE-94"),
    "exec": ("A03:2021", "CWE-78"),
    "sql": ("A03:2021", "CWE-89"),
    "xss": ("A03:2021", "CWE-79"),
    "pickle": ("A08:2021", "CWE-502"),
    "deser": ("A08:2021", "CWE-502"),
    "secret": ("A02:2021", "CWE-798"),
    "crypto": ("A02:2021", "CWE-327"),
    "ssrf": ("A10:2021", "CWE-918"),
    "command": ("A03:2021", "CWE-78"),
    "supply": ("A08:2021", "CWE-829"),
    "include": ("A03:2021", "CWE-98"),
}

SONAR_EQUIVALENTS = {
    "eval": "javascript:S1523",
    "exec": "javascript:S4721",
    "sql-concat": "javascript:S3649",
    "pickle-deser": "python:S6776",
    "weak.crypto": "java:S5542",
}


def map_finding(rule_id: str, message: str = "") -> dict[str, Any]:
    rid = rule_id.lower()
    owasp = cwe = ""
    for key, (o, c) in OWASP_CWE_MAP.items():
        if key in rid or key in message.lower():
            owasp, cwe = o, c
            break
    sonar = ""
    for key, sid in SONAR_EQUIVALENTS.items():
        if key in rid:
            sonar = sid
            break
    return {"cwe_id": cwe, "owasp_category": owasp, "sonar_rule_equivalent": sonar}


def enrich_finding_dict(f: dict) -> dict:
    tags = map_finding(f.get("rule_id", ""), f.get("message", ""))
    out = dict(f)
    out.update(tags)
    return out
