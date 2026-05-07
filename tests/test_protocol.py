from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from snft_sdk import (
    build_runtime_attestation_payload,
    build_unlock_challenge,
    build_wallet_proof_request,
    create_chain_unlock_request,
    create_runtime_attestation_headers,
    evaluate_registry_trust,
    is_snft_metadata,
    select_chain_adapter,
    validate_snft_descriptor,
    validate_unlock_request,
)


ROOT = Path(__file__).resolve().parent.parent


def load_metadata() -> dict:
    return json.loads((ROOT / "examples" / "deploy-bot.metadata.json").read_text(encoding="utf-8"))


def test_registry_first_metadata_is_valid() -> None:
    metadata = load_metadata()
    assert is_snft_metadata(metadata)
    descriptor = metadata["snft"]
    assert validate_snft_descriptor(descriptor) == []
    assert build_unlock_challenge(descriptor) == descriptor["chains"][0]["proof"]["challenge"]


def test_ton_unlock_request_shape() -> None:
    descriptor = load_metadata()["snft"]
    adapter = select_chain_adapter(descriptor, ["ton"])
    proof = {"method": "ton_proof", "wallet": "EQwallet", "ton_proof": {"payload": "signed"}}

    request = create_chain_unlock_request(descriptor, adapter, "EQwallet", proof)

    assert request["protocol"] == "snft"
    assert request["chain"] == "ton"
    assert request["nft"]["item_address"] == "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c"
    assert request["proof"] == proof
    assert validate_unlock_request(request, descriptor, adapter) == []


def test_ton_collection_only_unlock_request_shape() -> None:
    descriptor = load_metadata()["snft"]
    adapter = select_chain_adapter(descriptor, ["ton"])
    adapter["proof"].pop("item_address", None)
    proof = {"method": "ton_proof", "wallet": "EQwallet", "ton_proof": {"payload": "signed"}}

    request = create_chain_unlock_request(descriptor, adapter, "EQwallet", proof)

    assert "item_address" not in request["nft"]
    assert request["nft"]["collection_address"] == "EQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBx"
    assert validate_unlock_request(request, descriptor, adapter) == []


def test_evm_unlock_request_shape() -> None:
    descriptor = load_metadata()["snft"]
    adapter = select_chain_adapter(descriptor, ["evm"])
    proof = {"method": "eip712", "wallet": "0x0000000000000000000000000000000000000001", "signature": "0xsig"}

    request = create_chain_unlock_request(descriptor, adapter, proof["wallet"], proof)

    assert request["chain"] == "evm"
    assert request["nft"]["chain_id"] == 1
    assert request["nft"]["contract"] == "0x0000000000000000000000000000000000000000"
    assert request["nft"]["token_id"] == "1"
    assert validate_unlock_request(request, descriptor, adapter) == []


def test_wallet_proof_request() -> None:
    descriptor = load_metadata()["snft"]
    adapter = select_chain_adapter(descriptor, ["ton"])

    request = build_wallet_proof_request(descriptor, adapter, "EQwallet", nonce="nonce-1")

    assert request["protocol"] == "snft"
    assert request["proof_method"] == "ton_proof"
    assert request["challenge"] == descriptor["chains"][0]["proof"]["challenge"]
    assert request["nonce"] == "nonce-1"


def test_registry_trust() -> None:
    descriptor = load_metadata()["snft"]
    attestation = {
        "registry": "https://skilzzz.com",
        "skill_id": "deploy-bot",
        "trust_level": "verified",
        "verified": True,
        "scan_verdict": "pass",
    }

    result = evaluate_registry_trust(
        descriptor,
        attestation=attestation,
        trusted_registries=["https://skilzzz.com"],
        minimum_trust_level="verified",
        require_registry=True,
    )

    assert result["ok"] is True
    assert result["warnings"] == []


def test_runtime_attestation_headers_match_backend_payload() -> None:
    payload = build_runtime_attestation_payload(
        skill_id="deploy-bot",
        encrypted_sha256="sha256:encrypted",
        agent_version="0.11.4",
        build_hash="sha256:runtime",
        timestamp=1234567890,
    )
    assert payload == "snft-agent-unlock:deploy-bot:sha256:encrypted:0.11.4:sha256:runtime:1234567890"

    headers = create_runtime_attestation_headers(
        skill_id="deploy-bot",
        encrypted_sha256="sha256:encrypted",
        agent_version="0.11.4",
        build_hash="sha256:runtime",
        attestation_secret="secret",
        timestamp=1234567890,
    )

    expected = hmac.new(b"secret", payload.encode("utf-8"), hashlib.sha256).hexdigest()
    assert headers["X-NOTPUNKS-Agent-Version"] == "0.11.4"
    assert headers["X-NOTPUNKS-Agent-Build-Hash"] == "sha256:runtime"
    assert headers["X-NOTPUNKS-Agent-Timestamp"] == "1234567890"
    assert headers["X-NOTPUNKS-Agent-Attestation"] == f"sha256={expected}"
