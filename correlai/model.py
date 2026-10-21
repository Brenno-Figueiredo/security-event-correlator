"""Evento normalizado e incidente: o formato único para onde tudo converge."""
import hashlib
from dataclasses import dataclass, field


# Tipos de evento normalizados (o vocabulário comum do correlacionador)
EVENT_TYPES = {
    "port_scan",          # scanner de rede: host/porta descoberto
    "auth_failure",       # falha de login (SSH, Windows, web)
    "auth_success",       # login bem-sucedido
    "brute_force",        # alerta de força bruta
    "honeypot_hit",       # qualquer interação com o honeypot
    "honeypot_command",   # comando digitado no honeypot
    "web_attack",         # ataque web (SQLi, XSS...)
    "vuln_found",         # vulnerabilidade encontrada
    "account_lockout",    # conta bloqueada
    "malware_download",   # tentativa de baixar payload
    "generic",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Info"}


@dataclass
class Event:
    ts: float                      # epoch (UTC)
    source: str                    # qual ferramenta gerou (loginguard, sshoney, logwatch...)
    type: str                      # um de EVENT_TYPES
    severity: str = "info"
    ip: str = ""                   # ator (quem fez)
    user: str = ""                 # alvo (conta afetada)
    message: str = ""
    raw: dict = field(default_factory=dict)

    def id(self):
        h = hashlib.sha1(f"{self.ts}{self.source}{self.type}{self.ip}{self.user}{self.message}".encode())
        return h.hexdigest()[:12]

    def to_dict(self):
        d = {k: getattr(self, k) for k in ("ts", "source", "type", "severity", "ip", "user", "message")}
        d["id"] = self.id()
        return d


@dataclass
class Incident:
    rule: str                      # id da regra de correlação
    title: str
    severity: str
    ts: float                      # momento do evento que fechou a correlação
    ip: str = ""
    user: str = ""
    explanation: str = ""          # por que isso é um incidente (a "história")
    events: list = field(default_factory=list)   # eventos que compõem o incidente
    recommendation: str = ""

    def to_dict(self):
        return {
            "rule": self.rule, "title": self.title, "severity": self.severity, "ts": self.ts,
            "ip": self.ip, "user": self.user, "explanation": self.explanation,
            "recommendation": self.recommendation,
            "events": [e.to_dict() for e in sorted(self.events, key=lambda e: e.ts)],
            "event_count": len(self.events),
            "sources": sorted({e.source for e in self.events}),
        }


def sort_by_severity(items):
    return sorted(items, key=lambda x: (-SEVERITY_ORDER.get(x.severity, 0), -x.ts))
