"""Linha de comando do CorrelAI."""
import argparse
import glob
import json
import os
import sys

from . import __version__, report
from .model import sort_by_severity
from .parsers import load_json_array, load_jsonl
from .rules import RULE_INFO, Correlator
from .samples import generate
from .parsers import parse_record


def build_parser():
    ap = argparse.ArgumentParser(
        prog="correlai", description="Correlacionador de eventos de segurança: cruza alertas de várias "
        "ferramentas e forma incidentes.",
        epilog="Dica: comece com 'python app.py demo' para ver a correlação funcionando.")
    sub = ap.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="correlaciona arquivos de eventos (JSONL/JSON)")
    run.add_argument("paths", nargs="+", help="arquivos ou pastas com eventos (aceita curingas)")
    run.add_argument("--source", help="força a fonte (loginguard, sshoney, logwatch, webvulnscan, netscan)")
    run.add_argument("--json", metavar="ARQ.json", help="salva o resultado em JSON")
    run.add_argument("--html", metavar="ARQ.html", help="gera o painel HTML")
    run.add_argument("--no-color", action="store_true")

    demo = sub.add_parser("demo", help="roda uma demonstração com eventos de exemplo")
    demo.add_argument("--json", metavar="ARQ.json")
    demo.add_argument("--html", metavar="ARQ.html")
    demo.add_argument("--no-color", action="store_true")

    sub.add_parser("rules", help="lista as regras de correlação")

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _expand(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += glob.glob(os.path.join(p, "*.jsonl")) + glob.glob(os.path.join(p, "*.json"))
        else:
            files += glob.glob(p)
    return sorted(set(files))


def _write_html(path, payload):
    from .webui import render_html
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(payload))


def _finish(incidents, events, args):
    report.print_incidents(incidents, len(events), use_color=not getattr(args, "no_color", False))
    payload = report.build_payload(incidents, events)
    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"\nJSON salvo em: {args.json}")
    if getattr(args, "html", None):
        _write_html(args.html, payload)
        print(f"Painel HTML salvo em: {args.html}")
    return 1 if any(i.severity in ("critical", "high") for i in incidents) else 0


def cmd_run(args):
    files = _expand(args.paths)
    if not files:
        print("Nenhum arquivo encontrado.", file=sys.stderr)
        return 2
    events = []
    for path in files:
        try:
            if path.endswith(".jsonl"):
                events += load_jsonl(path, args.source)
            else:
                events += load_json_array(path, args.source)
        except (OSError, ValueError) as exc:
            print(f"Aviso: falha ao ler {path}: {exc}", file=sys.stderr)
    print(f"Carregados {len(events)} eventos de {len(files)} arquivo(s).")
    incidents = Correlator().run(events)
    return _finish(incidents, events, args)


def cmd_demo(args):
    events = [parse_record(rec, src) for src, rec in generate()]
    events = [e for e in events if e]
    incidents = Correlator().run(events)
    return _finish(incidents, events, args)


def cmd_rules(args):
    print("Regras de correlação:\n")
    for rid, desc in RULE_INFO.items():
        print(f"  {rid:<28} {desc}")
    return 0


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return {"run": cmd_run, "demo": cmd_demo, "rules": cmd_rules}[args.cmd](args)
