# Clotho

Compliance auditing tool I wrote to stop manually checking if my servers are still configured right.

SSH into boxes, check if anything drifted from baseline, spit out a PDF. ISO 27002 mapping because why not.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Needs `pdflatex` for PDF output (texlive).

## Usage

```bash
# validate baseline syntax
python clotho.py --validate-only

# audit all nodes
python clotho.py

# audit specific node
python clotho.py --node athena

# local dry-run (test on this machine)
python clotho.py --local

# use specific SSH key
python clotho.py --key-file ~/.ssh/id_ed25519
```

## Baseline

Edit `baseline.yaml` to define your nodes and what you expect:

```yaml
nodes:
  athena:
    host: "athena.local"
    port: 22
    user: "auditor"

controls:
  "8.20":  # ISO 27002:2022 control
    title: "Network Security"
    collectors:
      ports:
        allowed: [22, 443]
        forbidden: [23, 21]
```

Collectors available: `ports`, `users`, `files`, `processes`.

## Output

Reports land in `output/`:
- `.tex` - LaTeX source
- `.pdf` - compiled report
- `.json` - machine-readable

## License

MIT
