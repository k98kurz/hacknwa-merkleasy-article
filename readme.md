# Overview

This repo contains some sample code and an article written for HackNWA about
Merklized data structures and their uses in distributed technologies.

# Prerequisites

## *nix

```bash
python -m venv venv/
source venv/bin/activate
pip install merkleasy==0.0.3
pip install pynacl
```

## Winderps

```bash
python -m venv venv/
source venv/Scripts/activate
pip install merkleasy==0.0.3
pip install pynacl
```

## pip hash

To use hashing mode, use the `requirements.txt file` instead of the
`pip install...` commands:

```bash
pip install -r requirements.txt
```

Note: the hash for a package can be found using the following:

```bash
pip download merkleasy==0.0.3
pip hash merkleasy-0.0.3-py3-none-any.whl
```
