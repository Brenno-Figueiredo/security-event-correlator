"""Painel HTML autônomo (sem JS externo) com os incidentes correlacionados."""
import html
import json
from datetime import datetime

SEV_COLOR = {"critical": "#ff5c7a", "high": "#ff9f45", "medium": "#f2cd3b", "low": "#5aa9ff", "info": "#8aa5b3"}
SEV_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Info"}
SOURCE_LABEL = {"sshoney": "Honeypot", "loginguard": "LoginGuard", "logwatch": "LogWatch",
                "webvulnscan": "Scanner Web", "netscan": "Scanner de Rede", "generic": "Outro"}

CSS = """
:root{color-scheme:dark;--bg:#0c1420;--panel:#141f2e;--line:#243347;--text:#e3edf5;--muted:#8ba2b8;--accent:#4db6ac}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:1060px;margin:0 auto;padding:30px 22px 70px}h1{margin:0;font-size:27px}
.sub{color:var(--muted);margin:4px 0 0}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}
.card{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:15px}
.card b{display:block;font-size:30px}.card span{color:var(--muted);font-size:13px}
svg{width:100%;height:90px;display:block;margin:10px 0 0}
.inc{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:9px;padding:16px;margin:12px 0}
.inc h3{margin:0 0 6px;font-size:16px}.badge{font-size:12px;font-weight:700;border-radius:999px;padding:1px 10px;color:#09141b}
.expl{margin:6px 0 10px}.chips{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}
.chip{font-size:11.5px;background:#0e1b27;border:1px solid var(--line);border-radius:6px;padding:2px 8px;color:var(--muted)}
.tl{margin:10px 0;border-left:2px solid var(--line);padding-left:14px}
.tl .e{position:relative;padding:3px 0;font-size:13px;color:var(--muted)}
.tl .e::before{content:"";position:absolute;left:-19px;top:9px;width:8px;height:8px;border-radius:50%;background:var(--accent)}
.tl .e b{color:var(--text);font-weight:600}.rec{font-size:13px;margin-top:8px}.rec b{color:var(--text)}
.note{color:var(--muted);font-size:12.5px;margin-top:28px;border-top:1px solid var(--line);padding-top:16px}
.src{font-family:ui-monospace,Consolas,monospace;font-size:11px}
"""


def _timeline_svg(tl):
    counts = tl.get("counts") or []
    if not counts:
        return ""
    mx = max(counts) or 1
    w, h, n = 1000, 80, len(counts)
    bw = w / n
    bars = "".join(
        f'<rect x="{i*bw:.1f}" y="{h-(c/mx*h):.1f}" width="{bw-1:.1f}" height="{c/mx*h:.1f}" fill="#4db6ac" opacity="0.8"/>'
        for i, c in enumerate(counts))
    return f'<svg viewBox="0 0 {w} {h}" preserveAspectRatio="none" role="img" aria-label="Eventos no tempo">{bars}</svg>'


def _incident_block(inc):
    col = SEV_COLOR.get(inc["severity"], "#888")
    chips = "".join(f'<span class="chip">{html.escape(SOURCE_LABEL.get(s, s))}</span>' for s in inc["sources"])
    events = "".join(
        f'<div class="e"><b>{datetime.fromtimestamp(e["ts"]):%d/%m %H:%M}</b> '
        f'<span class="src">[{html.escape(SOURCE_LABEL.get(e["source"], e["source"]))}]</span> '
        f'{html.escape(e["message"][:90])}</div>'
        for e in inc["events"][:8])
    who = []
    if inc["ip"]:
        who.append(f'IP {html.escape(inc["ip"])}')
    if inc["user"]:
        who.append(f'conta {html.escape(inc["user"])}')
    return (f'<div class="inc" style="border-left-color:{col}">'
            f'<h3><span class="badge" style="background:{col}">{SEV_LABEL[inc["severity"]]}</span> '
            f'{html.escape(inc["title"])}</h3>'
            f'<div class="chips">{chips}{"".join(f"<span class=chip>{w}</span>" for w in who)}</div>'
            f'<p class="expl">{html.escape(inc["explanation"])}</p>'
            f'<div class="tl">{events}</div>'
            f'<p class="rec"><b>Ação recomendada:</b> {html.escape(inc["recommendation"])}</p></div>')


def render_html(payload):
    c = payload["by_severity"]
    crit = c.get("critical", 0) + c.get("high", 0)
    cards = (
        f'<div class="card"><b>{payload["event_count"]}</b><span>Eventos analisados</span></div>'
        f'<div class="card"><b>{payload["incident_count"]}</b><span>Incidentes</span></div>'
        f'<div class="card"><b style="color:#ff5c7a">{crit}</b><span>Críticos e altos</span></div>'
        f'<div class="card"><b>{len(payload["top_ips"])}</b><span>IPs envolvidos</span></div>')
    blocks = "".join(_incident_block(i) for i in payload["incidents"]) or '<p class="sub">Nenhum incidente.</p>'
    doc = f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>CorrelAI - painel</title>
<style>{CSS}</style></head><body><main>
<h1>CorrelAI</h1><p class="sub">Correlacionador de eventos de segurança · {datetime.now():%d/%m/%Y %H:%M}</p>
<div class="cards">{cards}</div>
{_timeline_svg(payload["timeline"])}
<h2 style="margin-top:26px">Incidentes correlacionados</h2>
{blocks}
<p class="note">Cada incidente reúne eventos de ferramentas diferentes ligados por IP, usuário e tempo.
Pode conter IPs reais — revise antes de publicar.</p>
</main></body></html>"""
    return doc
