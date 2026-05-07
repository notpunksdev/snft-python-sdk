# Release

## Checks

```bash
PYTHONPATH=src python3.11 -m pytest
python3.11 -m py_compile src/snft_sdk/__init__.py src/snft_sdk/protocol.py
python3.11 -m build
```

## Publish

```bash
python3.11 -m twine upload dist/*
```

## Tag

```bash
git tag -a v0.1.1 -m "sNFT Python SDK v0.1.1"
git push origin main
git push origin v0.1.1
```
