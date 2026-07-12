# Nexa Development

## Requirements

- Python 3.11+
- Node.js and npm for frontend development

## Setup

```bash
git clone https://github.com/wanan-life/Nexa.git
cd Nexa
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
npm --prefix web install
npm --prefix web run build
nexa init
```

Run tests and rebuild the frontend:

```bash
python -m unittest discover -s tests -v
npm --prefix web run build
nexa web --rebuild
```

Build the current platform's single-file release artifact:

```bash
pip install -e ".[release]"
python scripts/build_binary.py
```

The output is written to `release/`.
