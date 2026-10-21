"""Conectores: leem a saída de cada ferramenta e convertem para o Event normalizado.

Cada ferramenta tem seu próprio formato. Aqui mora o conhecimento de 'como traduzir'
cada uma para o vocabulário comum. Adicionar uma nova fonte = adicionar um parser.
"""
import json
import re
from datetime import datetime

from .model import Event

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ts(value):
    if value is None:
        return datetime.now().timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now().timestamp()


def from_loginguard(rec):
    """Alertas/eventos do LoginGuard (detector de login do Windows)."""
    rule = rec.get("rule", "")
    sev = rec.get("severity", "medium")
    mapping = {
        "account_bruteforce": "brute_force", "rdp_bruteforce": "brute_force",
        "password_spraying": "brute_force", "user_enumeration": "auth_failure",
        "success_after_failures": "auth_success", "account_lockout": "account_lockout",
        "root_login_success": "auth_success", "off_hours_logon": "auth_success",
    }
    return Event(ts=_ts(rec.get("ts")), source="loginguard",
                 type=mapping.get(rule, "auth_failure"), severity=sev,
                 ip=rec.get("source", "").split(" ")[0], user=rec.get("user", ""),
                 message=rec.get("title", rule), raw=rec)


def from_sshoney(rec):
    """Eventos do honeypot SSH (JSONL: login, command, session)."""
    ev = rec.get("event")
    ip = rec.get("ip", "")
    ts = _ts(rec.get("ts"))
    if ev == "login":
        ok = rec.get("success")
        return Event(ts=ts, source="sshoney", type="honeypot_hit",
                     severity="high" if ok else "medium", ip=ip, user=rec.get("username", ""),
                     message=f"Login no honeypot: {rec.get('username')}:{rec.get('password')} "
                             f"({'aceito' if ok else 'negado'})", raw=rec)
    if ev == "command":
        cmd = rec.get("command", "")
        is_mal = any(w in cmd for w in ("wget", "curl", "chmod +x", "bot", ".sh"))
        return Event(ts=ts, source="sshoney",
                     type="malware_download" if is_mal else "honeypot_command",
                     severity="high" if is_mal else "medium", ip=ip, user=rec.get("username", ""),
                     message=f"Comando no honeypot: {cmd}", raw=rec)
    if ev == "session":
        return Event(ts=ts, source="sshoney", type="honeypot_hit", severity="low", ip=ip,
                     message=f"Sessão no honeypot ({rec.get('commands', 0)} comandos)", raw=rec)
    return None


def from_logwatch(rec):
    """Alertas do LogWatch (SSH/web/aplicação)."""
    rule = rec.get("rule", "")
    mapping = {
        "ssh_bruteforce": "brute_force", "ssh_success_after_fail": "auth_success",
        "ssh_user_enumeration": "auth_failure", "web_attack": "web_attack",
        "web_scan_404": "web_attack", "scanner_user_agent": "web_attack",
        "sensitive_path": "web_attack", "http_flood": "web_attack",
        "root_login_success": "auth_success", "sudo_failure": "auth_failure",
    }
    return Event(ts=_ts(rec.get("ts")), source="logwatch",
                 type=mapping.get(rule, "generic"), severity=rec.get("severity", "medium"),
                 ip=rec.get("ip", ""), user=rec.get("user", ""),
                 message=rec.get("title", rule), raw=rec)


def from_webvulnscan(rec):
    """Achados do WebVulnScan (JSON de relatório)."""
    return Event(ts=datetime.now().timestamp(), source="webvulnscan", type="vuln_found",
                 severity=rec.get("severity", "medium"), ip="",
                 message=f"{rec.get('title', '')} em {rec.get('url', '')}", raw=rec)


def from_netscan(rec):
    """Hosts/portas do scanner de rede (JSON)."""
    ip = rec.get("ip", "")
    ports = rec.get("open_ports", [])
    return Event(ts=_ts(rec.get("ts")), source="netscan", type="port_scan", severity="info",
                 ip=ip, message=f"Host {ip} com {len(ports)} porta(s) aberta(s)", raw=rec)


def from_generic(rec):
    """Fallback: tenta extrair ts/ip/mensagem de um JSON qualquer."""
    ip = rec.get("ip", "") or rec.get("source_ip", "")
    if not ip:
        m = IP_RE.search(json.dumps(rec))
        ip = m.group(0) if m else ""
    return Event(ts=_ts(rec.get("ts") or rec.get("timestamp") or rec.get("time")),
                 source=rec.get("source", "generic"), type=rec.get("type", "generic"),
                 severity=rec.get("severity", "info"), ip=ip, user=rec.get("user", ""),
                 message=rec.get("message") or rec.get("title") or json.dumps(rec)[:120], raw=rec)


PARSERS = {
    "loginguard": from_loginguard, "sshoney": from_sshoney, "logwatch": from_logwatch,
    "webvulnscan": from_webvulnscan, "netscan": from_netscan, "generic": from_generic,
}


def detect_source(rec):
    """Descobre de qual ferramenta é o registro, pelos campos presentes."""
    if rec.get("source") in PARSERS:
        return rec["source"]
    if "event" in rec and rec.get("event") in ("login", "command", "session"):
        return "sshoney"
    if rec.get("rule", "").startswith(("ssh_", "web_", "http_", "log_")):
        return "logwatch"
    if rec.get("rule") in ("account_bruteforce", "rdp_bruteforce", "password_spraying",
                           "user_enumeration", "success_after_failures", "account_lockout"):
        return "loginguard"
    if "open_ports" in rec:
        return "netscan"
    if "check" in rec and "url" in rec:
        return "webvulnscan"
    return "generic"


def parse_record(rec, source=None):
    src = source or detect_source(rec)
    parser = PARSERS.get(src, from_generic)
    try:
        return parser(rec)
    except Exception:  # noqa: BLE001
        return from_generic(rec)


def load_jsonl(path, source=None):
    """Lê um arquivo JSONL e devolve eventos normalizados."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # WebVulnScan guarda os achados dentro de "findings"
            if isinstance(rec, dict) and "findings" in rec and isinstance(rec["findings"], list):
                for fnd in rec["findings"]:
                    ev = parse_record(fnd, "webvulnscan")
                    if ev:
                        events.append(ev)
                continue
            ev = parse_record(rec, source)
            if ev:
                events.append(ev)
    return events


def load_json_array(path, source=None):
    """Lê um arquivo .json que seja um array ou tenha chaves 'findings'/'hosts'."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("findings") or data.get("hosts") or [data]
    out = []
    for rec in records:
        ev = parse_record(rec, source)
        if ev:
            out.append(ev)
    return out
