# sNFT Python SDK

Python helpers for sNFT Protocol agent runtimes, including protected flows where
private skill source stays inside a secret encrypted cartridge until
wallet-gated runtime unlock.

This package mirrors the agent-facing protocol helpers from the TypeScript
`@notpunks/snft-agent-sdk` / `@notpunks/snft-protocol` packages where Python
agents need deterministic behavior.

It includes:

- sNFT metadata detection and descriptor validation;
- chain adapter selection;
- unlock challenge building;
- wallet proof request building;
- normalized unlock request building;
- registry trust evaluation;
- protected runtime attestation headers.

It does not include:

- wallet UI;
- chain RPC/indexer clients;
- decrypt-key service;
- scanner policy;
- cartridge installation;
- sandbox/runtime execution;
- absolute local DRM after an authorized unlock.

## Install

```bash
pip install notpunks-snft-sdk
```

## Example

```python
from snft_sdk import (
    create_runtime_attestation_headers,
    create_chain_unlock_request,
    select_chain_adapter,
)

snft = metadata["snft"]
adapter = select_chain_adapter(snft, preferred_chains=["ton"])
unlock_request = create_chain_unlock_request(
    snft,
    adapter,
    wallet="EQ...",
    proof={"method": "ton_proof", "wallet": "EQ...", "ton_proof": {...}},
)

headers = create_runtime_attestation_headers(
    skill_id=snft["skill_id"],
    encrypted_sha256=snft["content"]["encrypted_sha256"],
    agent_version="0.11.4",
    build_hash="sha256:...",
    attestation_secret="secret",
)
```
