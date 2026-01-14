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

# dry-run to see planned checks without execution
python clotho.py --dry-run

# run specific controls only
python clotho.py --control 8.20,5.15

# run all 8.x controls (range support)
python clotho.py --control 8:9

# exclude specific controls
python clotho.py --exclude-control 8.31

# show file diffs when hash mismatches detected
python clotho.py --show-diffs

# compare with previous audit
python clotho.py --compare-with previous

# compare with specific audit (use node filtering)
python clotho.py --node athena --compare-with audit_20260114_120000

# show compliance trends
python clotho.py --trend --days 30

# specify output formats (default: html,pdf,json)
python clotho.py --format html,json
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
