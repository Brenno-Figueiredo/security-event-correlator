"""Regras de correlação: cruzam vários eventos para formar um incidente com sentido.

A ideia central: um evento isolado é um alerta; vários eventos ligados por IP, usuário e
tempo contam uma história. Cada regra olha a linha do tempo e decide se essa história aconteceu.
"""
from collections import defaultdict

from .model import Incident


def _window(events, seconds):
    """Agrupa eventos próximos no tempo (eventos já vêm ordenados por ts)."""
    return seconds  # usado como marcador de leitura; a lógica de janela fica em cada regra


class Correlator:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else DEFAULT_RULES

    def run(self, events):
        events = sorted(events, key=lambda e: e.ts)
        incidents = []
        for rule in self.rules:
            incidents.extend(rule(events))
        # deduplica incidentes idênticos (mesma regra + mesmo ip + mesmo alvo aproximado)
        seen, unique = set(), []
        for inc in incidents:
            key = (inc.rule, inc.ip, inc.user, round(inc.ts / 60))
            if key not in seen:
                seen.add(key)
                unique.append(inc)
        return unique


# --------------------------------------------------------------------------- #
# Regras. Cada uma recebe a lista de eventos e devolve uma lista de Incident.
# --------------------------------------------------------------------------- #

def rule_honeypot_then_real_login(events):
    """O MESMO IP interage com o honeypot e depois loga numa conta real. Clássico e crítico."""
    incidents = []
    by_ip = defaultdict(list)
    for e in events:
        if e.ip:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        hp = [e for e in evs if e.source == "sshoney"]
        real_login = [e for e in evs if e.type == "auth_success" and e.source != "sshoney"]
        if hp and real_login:
            first_hp = min(hp, key=lambda e: e.ts)
            login = min(real_login, key=lambda e: e.ts)
            related = sorted(hp + real_login, key=lambda e: e.ts)
            incidents.append(Incident(
                rule="honeypot_then_real_login",
                title=f"IP do honeypot conseguiu login real: {ip}",
                severity="critical", ts=login.ts, ip=ip, user=login.user,
                explanation=f"O IP {ip} interagiu com o honeypot (a partir de "
                            f"{_fmt(first_hp.ts)}) e depois obteve um login bem-sucedido em um sistema "
                            f"real ('{login.user}' em {_fmt(login.ts)}). Um atacante confirmado acessou uma conta.",
                recommendation="Isole a conta, force troca de senha e bloqueie o IP imediatamente.",
                events=related))
    return incidents


def rule_bruteforce_then_success(events):
    """Força bruta seguida de login bem-sucedido, no mesmo IP e/ou usuário."""
    incidents = []
    bf = [e for e in events if e.type == "brute_force"]
    success = [e for e in events if e.type == "auth_success"]
    for b in bf:
        for s in success:
            if s.ts < b.ts or s.ts - b.ts > 1800:
                continue
            if (b.ip and b.ip == s.ip) or (b.user and b.user == s.user):
                incidents.append(Incident(
                    rule="bruteforce_then_success",
                    title=f"Força bruta seguida de acesso: {s.user or s.ip}",
                    severity="critical", ts=s.ts, ip=s.ip or b.ip, user=s.user or b.user,
                    explanation=f"Um alerta de força bruta ({b.source}) foi seguido, em até 30 min, "
                                f"por um login bem-sucedido ({s.source}). A conta pode ter sido comprometida.",
                    recommendation="Trate como conta comprometida: encerre sessões, troque a senha e investigue.",
                    events=[b, s]))
                break
    return incidents


def rule_scan_then_attack(events):
    """Reconhecimento (port scan ou varredura web) seguido de ataque do mesmo IP."""
    incidents = []
    by_ip = defaultdict(list)
    for e in events:
        if e.ip:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        recon = [e for e in evs if e.type in ("port_scan", "web_attack") and "404" in e.message or
                 e.type == "port_scan"]
        attacks = [e for e in evs if e.type in ("web_attack", "brute_force", "malware_download")
                   and e not in recon]
        if recon and attacks:
            r0 = min(recon, key=lambda e: e.ts)
            a0 = max(attacks, key=lambda e: e.ts)
            if a0.ts >= r0.ts:
                incidents.append(Incident(
                    rule="scan_then_attack",
                    title=f"Reconhecimento seguido de ataque: {ip}",
                    severity="high", ts=a0.ts, ip=ip,
                    explanation=f"O IP {ip} fez reconhecimento (porta/varredura) e em seguida partiu "
                                f"para ataques ({', '.join(sorted({a.type for a in attacks}))}). "
                                "Padrão típico de uma intrusão em andamento.",
                    recommendation="Bloqueie o IP e revise os serviços que ele sondou.",
                    events=sorted(recon + attacks, key=lambda e: e.ts)[:20]))
    return incidents


def rule_distributed_bruteforce(events):
    """Vários IPs atacando a MESMA conta em pouco tempo (ataque distribuído)."""
    incidents = []
    by_user = defaultdict(list)
    for e in events:
        if e.type in ("brute_force", "auth_failure") and e.user:
            by_user[e.user].append(e)
    for user, evs in by_user.items():
        ips = {e.ip for e in evs if e.ip}
        if len(ips) >= 3:
            evs_sorted = sorted(evs, key=lambda e: e.ts)
            span = evs_sorted[-1].ts - evs_sorted[0].ts
            if span <= 3600:
                incidents.append(Incident(
                    rule="distributed_bruteforce",
                    title=f"Ataque distribuído à conta '{user}'",
                    severity="high", ts=evs_sorted[-1].ts, user=user,
                    explanation=f"A conta '{user}' foi alvo de {len(ips)} IPs diferentes em "
                                f"{int(span/60)} min. Indica um ataque coordenado (botnet).",
                    recommendation="Ative bloqueio de conta, MFA e monitore a conta de perto.",
                    events=evs_sorted[:20]))
    return incidents


def rule_malware_on_honeypot(events):
    """Tentativa de baixar payload no honeypot: intenção maliciosa clara."""
    incidents = []
    by_ip = defaultdict(list)
    for e in events:
        if e.type == "malware_download" and e.source == "sshoney" and e.ip:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        incidents.append(Incident(
            rule="malware_on_honeypot",
            title=f"Tentativa de baixar payload no honeypot: {ip}",
            severity="high", ts=max(e.ts for e in evs), ip=ip,
            explanation=f"O IP {ip} tentou baixar/executar arquivos no honeypot "
                        f"({len(evs)} comando(s)), comportamento típico de instalação de malware/botnet.",
            recommendation="Adicione o IP à blocklist e extraia as URLs de payload dos comandos para análise.",
            events=evs[:20]))
    return incidents


def rule_repeat_offender(events):
    """Um IP que aparece em MÚLTIPLAS fontes diferentes é um ator persistente."""
    incidents = []
    by_ip = defaultdict(set)
    ip_events = defaultdict(list)
    for e in events:
        if e.ip:
            by_ip[e.ip].add(e.source)
            ip_events[e.ip].append(e)
    for ip, sources in by_ip.items():
        if len(sources) >= 3:
            evs = sorted(ip_events[ip], key=lambda e: e.ts)
            incidents.append(Incident(
                rule="repeat_offender",
                title=f"Ator persistente visto em {len(sources)} sistemas: {ip}",
                severity="high", ts=evs[-1].ts, ip=ip,
                explanation=f"O IP {ip} gerou eventos em {len(sources)} ferramentas diferentes "
                            f"({', '.join(sorted(sources))}). Um mesmo ator ativo em várias frentes "
                            "merece atenção prioritária.",
                recommendation="Priorize este IP: bloqueie na borda e busque todos os eventos ligados a ele.",
                events=evs[:25]))
    return incidents


def _fmt(ts):
    from datetime import datetime
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")


DEFAULT_RULES = [
    rule_honeypot_then_real_login,
    rule_bruteforce_then_success,
    rule_scan_then_attack,
    rule_distributed_bruteforce,
    rule_malware_on_honeypot,
    rule_repeat_offender,
]

RULE_INFO = {
    "honeypot_then_real_login": "IP visto no honeypot consegue login em sistema real.",
    "bruteforce_then_success": "Força bruta seguida de login bem-sucedido.",
    "scan_then_attack": "Reconhecimento seguido de ataque pelo mesmo IP.",
    "distributed_bruteforce": "Vários IPs atacam a mesma conta (ataque distribuído).",
    "malware_on_honeypot": "Tentativa de baixar payload no honeypot.",
    "repeat_offender": "Mesmo IP aparece em várias ferramentas.",
}
