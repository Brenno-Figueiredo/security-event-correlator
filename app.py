#!/usr/bin/env python3
"""CorrelAI - correlacionador de eventos de segurança.
Exemplos:
    python app.py demo --html painel.html
    python app.py run logs/ --html painel.html
    python app.py run sessions.jsonl alerts.jsonl
"""
import sys

from correlai.cli import main

if __name__ == "__main__":
    sys.exit(main())
