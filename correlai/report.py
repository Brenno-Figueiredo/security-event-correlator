"""Resumo no terminal e dados para o painel."""
from collections import Counter
from datetime import datetime

from .model import SEVERITY_LABEL, sort_by_severity

ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
        "low": "\033[1;34m", "info": "\033[2m", "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m"}


def print_incidents(incidents, n_events, use_color=True):
    def p(t, k):
        return f"{ANSI[k]}{t}{ANSI['reset']}" if use_color else t
    print(p(f"\nCorrelAI - {n_events} eventos analisados, {len(incidents)} incidente(s)", "bold"))
    print("=" * 72)
    if not incidents:
        print("Nenhum incidente correlacionado.")
        return
    for inc in sort_by_severity(incidents):
        print(f"\n{p(' ' + SEVERITY_LABEL[inc.severity].upper() + ' ', inc.severity)} {p(inc.title, 'bold')}")
        print(f"   {inc.explanation}")
        print(p(f"   Eventos ({len(inc.events)}) de: {', '.join(sorted({e.source for e in inc.events}))}", "dim"))
        for e in sorted(inc.events, key=lambda e: e.ts)[:6]:
            t = datetime.fromtimestamp(e.ts).strftime("%d/%m %H:%M")
            print(p(f"     {t}  [{e.source}] {e.message[:70]}", "dim"))
        print(f"   → {inc.recommendation}")
    c = Counter(i.severity for i in incidents)
    print("\n" + "=" * 72)
    resumo = "  ".join(f"{SEVERITY_LABEL[k]}: {c[k]}" for k in ("critical", "high", "medium", "low") if c.get(k))
    print(p(f"Total: {len(incidents)} incidente(s)  |  {resumo}", "bold"))


def build_payload(incidents, events):
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "event_count": len(events),
        "incident_count": len(incidents),
        "by_severity": dict(Counter(i.severity for i in incidents)),
        "incidents": [i.to_dict() for i in sort_by_severity(incidents)],
        "timeline": _timeline(events),
        "top_ips": [{"ip": ip, "n": n} for ip, n in
                    Counter(e.ip for e in events if e.ip).most_common(10)],
        "by_source": dict(Counter(e.source for e in events)),
    }


def _timeline(events, buckets=40):
    if not events:
        return {"labels": [], "counts": []}
    lo = min(e.ts for e in events)
    hi = max(e.ts for e in events)
    step = max((hi - lo) / buckets, 1)
    counts = [0] * buckets
    for e in events:
        counts[min(buckets - 1, int((e.ts - lo) / step))] += 1
    labels = [datetime.fromtimestamp(lo + i * step).strftime("%H:%M") for i in range(buckets)]
    return {"labels": labels, "counts": counts}
