# CorrelAI

Correlacionador de eventos de segurança em Python, **sem dependências externas**. Ele reúne os alertas de várias
ferramentas (scanner de rede, honeypot, detector de login, monitor de logs, scanner web), cruza esses eventos por
**IP, usuário e tempo**, e forma **incidentes** que contam uma história que nenhuma ferramenta sozinha enxergaria.

É o tipo de peça que fica no coração de um SIEM (os sistemas que empresas grandes usam para monitorar segurança).

## A ideia em um exemplo

- O **honeypot** registra o IP `203.0.113.50` tentando senhas. Sozinho, é só mais um bot.
- Minutos depois, o **detector de login** vê esse **mesmo IP** conseguindo entrar na conta `deploy`. Sozinho, é um alerta comum.
- O CorrelAI liga os dois e gera **um incidente crítico**: *"Um IP conhecido do honeypot invadiu uma conta real."*

Esse salto, de alertas isolados para um incidente com contexto, é o que o correlacionador faz.

## Fontes suportadas

Ele entende o formato dos projetos da mesma série (todos geram JSON/JSONL):

| Fonte | O que traz |
|---|---|
| `sshoney` | tentativas e comandos no honeypot SSH |
| `loginguard` | alertas de login do Windows |
| `logwatch` | alertas de SSH, web e aplicação |
| `webvulnscan` | vulnerabilidades encontradas |
| `netscan` | hosts e portas do scanner de rede |
| `generic` | qualquer JSON com ip/ts/mensagem |

## Regras de correlação

| Regra | Dispara quando | Severidade |
|---|---|---|
| `honeypot_then_real_login` | um IP visto no honeypot consegue login em sistema real | crítica |
| `bruteforce_then_success` | força bruta seguida de login bem-sucedido (mesmo IP/conta) | crítica |
| `scan_then_attack` | reconhecimento seguido de ataque pelo mesmo IP | alta |
| `distributed_bruteforce` | vários IPs atacam a mesma conta em pouco tempo | alta |
| `malware_on_honeypot` | tentativa de baixar/executar payload no honeypot | alta |
| `repeat_offender` | o mesmo IP aparece em 3+ ferramentas diferentes | alta |

## Como rodar

Requisito: Python 3.9+.

```bash
# demonstração: eventos de exemplo + correlação + painel
python app.py demo --html painel.html

# correlacionar arquivos reais das ferramentas
python app.py run samples/            # uma pasta
python app.py run sessions.jsonl alerts.jsonl --html painel.html

# listar as regras
python app.py rules
```

Abra o `painel.html` no navegador para ver os incidentes, a linha do tempo e as ações recomendadas.
A pasta `samples/` traz arquivos de exemplo de cada ferramenta, para testar o modo `run`.

## Como funciona (passo a passo)

1. **Ingestão** (`parsers.py`): cada ferramenta tem um formato próprio. Um conector por fonte traduz o
   registro para um **evento normalizado** (mesmos campos: ts, fonte, tipo, ip, usuário, severidade).
2. **Normalização** (`model.py`): com todos os eventos no mesmo formato, dá para compará-los entre si.
3. **Correlação** (`rules.py`): cada regra percorre a linha do tempo e procura combinações suspeitas,
   agrupando por IP, usuário e janela de tempo.
4. **Incidentes**: cada combinação vira um incidente com uma explicação em linguagem natural, os eventos
   que o compõem e uma recomendação de ação.
5. **Saída** (`report.py`, `webui.py`): terminal, JSON e painel HTML.

## Estrutura

```
app.py              ponto de entrada
correlai/
  model.py          Event e Incident (o formato comum)
  parsers.py        conectores: traduzem cada ferramenta para o formato comum
  rules.py          regras de correlação (o coração do projeto)
  samples.py        gerador de eventos de exemplo
  report.py         resumo no terminal e payload do painel
  webui.py          painel HTML
  cli.py            linha de comando
samples/            eventos de exemplo de cada ferramenta
tests/              testes automatizados
```

## Por que isso importa

Correlação é a diferença entre "ter mil alertas" e "entender o que está acontecendo". Reduz o ruído,
liga os pontos entre sistemas e transforma dados soltos em incidentes acionáveis. É também a base natural
para uma camada de IA: com os eventos já normalizados e correlacionados, um modelo pode explicar, priorizar
e sugerir respostas.

## Testes

```bash
python -m unittest discover -s tests -v
```

## Projetos da série

- [network-scanner](https://github.com/Brenno-Figueiredo/network-scanner)
- [logwatch](https://github.com/Brenno-Figueiredo/logwatch)
- [loginguard](https://github.com/Brenno-Figueiredo/loginguard)
- [web-vuln-scanner](https://github.com/Brenno-Figueiredo/web-vuln-scanner)
- [ssh-honeypot](https://github.com/Brenno-Figueiredo/ssh-honeypot)
