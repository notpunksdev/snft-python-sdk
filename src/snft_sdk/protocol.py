from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import time
from typing import Any, Literal, NotRequired, TypedDict


SnftChain = Literal["ton", "evm", "solana", "bitcoin", "other"]
SnftProofMethod = Literal["ton_proof", "eip712", "solana_sign_message", "bitcoin_sign_message", "none", "custom"]
SnftTrustLevel = Literal["unknown", "community", "verified", "official"]


class SnftError(ValueError):
    pass


class SnftValidationIssue(TypedDict, total=False):
    code: str
    message: str
    path: str


class SnftUnlockProof(TypedDict, total=False):
    method: SnftProofMethod
    wallet: str
    signature: str
    payload: Any
    nonce: str
    issued_at: str


class SnftUnlockRequest(TypedDict):
    protocol: Literal["snft"]
    version: str
    skill_id: str
    chain: SnftChain
    wallet: str
    challenge: str
    nft: dict[str, Any]
    proof: SnftUnlockProof


class SnftWalletProofRequest(TypedDict):
    protocol: Literal["snft"]
    version: str
    skill_id: str
    chain: SnftChain
    wallet: str
    proof_method: SnftProofMethod
    challenge: str
    adapter: dict[str, Any]
    domain: NotRequired[str]
    nonce: NotRequired[str]
    issued_at: NotRequired[str]


class SnftRuntimeAttestationHeaders(TypedDict):
    X_NOTPUNKS_Agent_Version: str
    X_NOTPUNKS_Agent_Build_Hash: str
    X_NOTPUNKS_Agent_Timestamp: str
    X_NOTPUNKS_Agent_Attestation: str


TRUST_ORDER: dict[str, int] = {
    "unknown": 0,
    "community": 1,
    "verified": 2,
    "official": 3,
}


@dataclass(frozen=True)
class RuntimeAdapter:
    chain: SnftChain
    proof_method: SnftProofMethod
    required_nft_fields: tuple[str, ...]


RUNTIME_ADAPTERS: dict[str, RuntimeAdapter] = {
    "ton": RuntimeAdapter("ton", "ton_proof", ("item_address",)),
    "evm": RuntimeAdapter("evm", "eip712", ("chain_id", "contract", "token_id")),
    "solana": RuntimeAdapter("solana", "solana_sign_message", ("mint",)),
}


def _issue(code: str, message: str, path: str | None = None) -> SnftValidationIssue:
    issue: SnftValidationIssue = {"code": code, "message": message}
    if path:
        issue["path"] = path
    return issue


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str_list(value: Any) -> list[str]:
    return [item for item in _as_list(value) if isinstance(item, str)]


def is_snft_metadata(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    snft = _as_dict(value.get("snft"))
    return (
        snft.get("protocol") == "snft"
        and snft.get("standard") == "Skill NFT Protocol"
        and isinstance(snft.get("version"), str)
        and snft.get("type") == "agent_skill"
        and isinstance(snft.get("skill_id"), str)
    )


def assert_supported_snft(metadata: dict[str, Any], supported_major: str = "1") -> dict[str, Any]:
    if not is_snft_metadata(metadata):
        raise SnftError("Metadata does not contain a valid sNFT descriptor")
    snft = _as_dict(metadata.get("snft"))
    major = str(snft.get("version", "")).split(".")[0]
    if major != supported_major:
        raise SnftError(f"Unsupported sNFT descriptor version: {snft.get('version')}")
    return snft


def supported_chains() -> list[SnftChain]:
    return ["ton", "evm", "solana"]


def build_unlock_challenge(descriptor: dict[str, Any]) -> str:
    content = _as_dict(descriptor.get("content"))
    encrypted_hash = content.get("encrypted_sha256") or content.get("plaintext_sha256") or "unknown"
    return f"snft-unlock:{descriptor.get('skill_id')}:{encrypted_hash}"


def validate_snft_descriptor(descriptor: dict[str, Any]) -> list[SnftValidationIssue]:
    issues: list[SnftValidationIssue] = []
    chains = _as_list(descriptor.get("chains"))
    content = _as_dict(descriptor.get("content"))
    runtime = _as_dict(descriptor.get("runtime"))
    mode = str(content.get("mode") or "")
    unlock = _as_dict(descriptor.get("unlock"))
    if not chains:
        issues.append(_issue("chains_missing", "snft.chains must include at least one chain adapter", "snft.chains"))
    if not mode:
        issues.append(_issue("content_mode_missing", "snft.content.mode is required", "snft.content.mode"))
    if not runtime.get("entrypoint"):
        issues.append(_issue("entrypoint_missing", "snft.runtime.entrypoint is required", "snft.runtime.entrypoint"))
    has_unlock_route = bool(unlock.get("endpoint") or unlock.get("registry") or unlock.get("nodes"))
    if mode.startswith("encrypted") and not has_unlock_route:
        issues.append(_issue("unlock_route_missing", "Encrypted content requires snft.unlock endpoint, registry, or nodes", "snft.unlock"))
    if mode == "encrypted_external" and not _as_list(content.get("uris")):
        issues.append(_issue("content_uris_missing", "encrypted_external content requires snft.content.uris", "snft.content.uris"))
    return issues


def select_chain_adapter(descriptor: dict[str, Any], preferred_chains: list[SnftChain] | None = None) -> dict[str, Any]:
    preferred = preferred_chains or supported_chains()
    chains = [item for item in _as_list(descriptor.get("chains")) if isinstance(item, dict)]
    for chain in preferred:
        for adapter in chains:
            if adapter.get("chain") == chain and chain in RUNTIME_ADAPTERS:
                return adapter
    raise SnftError(f"No supported sNFT chain adapter found. Supported chains: {', '.join(preferred)}")


def build_wallet_proof_request(
    descriptor: dict[str, Any],
    adapter: dict[str, Any],
    wallet: str,
    *,
    domain: str | None = None,
    nonce: str | None = None,
    issued_at: str | None = None,
) -> SnftWalletProofRequest:
    proof = _as_dict(adapter.get("proof"))
    request: SnftWalletProofRequest = {
        "protocol": "snft",
        "version": str(descriptor.get("version") or "1.0"),
        "skill_id": str(descriptor.get("skill_id") or ""),
        "chain": str(adapter.get("chain") or "other"),  # type: ignore[typeddict-item]
        "wallet": wallet,
        "proof_method": str(proof.get("method") or "custom"),  # type: ignore[typeddict-item]
        "challenge": str(proof.get("challenge") or build_unlock_challenge(descriptor)),
        "adapter": adapter,
    }
    if domain:
        request["domain"] = domain
    if nonce:
        request["nonce"] = nonce
    request["issued_at"] = issued_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return request


def get_runtime_adapter(chain: str) -> RuntimeAdapter | None:
    return RUNTIME_ADAPTERS.get(chain)


def create_ton_nft_reference(adapter: dict[str, Any]) -> dict[str, Any]:
    proof = _as_dict(adapter.get("proof"))
    item_address = proof.get("item_address")
    if not item_address:
        raise SnftError("Missing required TON item_address")
    nft = {"item_address": item_address}
    if proof.get("collection_address"):
        nft["collection_address"] = proof.get("collection_address")
    return nft


def create_evm_nft_reference(adapter: dict[str, Any]) -> dict[str, Any]:
    proof = _as_dict(adapter.get("proof"))
    for field in ("chain_id", "contract", "token_id"):
        if proof.get(field) in (None, ""):
            raise SnftError(f"Missing required EVM {field}")
    return {
        "chain_id": proof.get("chain_id"),
        "contract": proof.get("contract"),
        "token_id": proof.get("token_id"),
        "standard": adapter.get("standard") or "ERC-721",
    }


def create_solana_nft_reference(adapter: dict[str, Any]) -> dict[str, Any]:
    proof = _as_dict(adapter.get("proof"))
    mint = proof.get("mint")
    if not mint:
        raise SnftError("Missing required Solana mint")
    nft = {"mint": mint}
    if proof.get("asset_id"):
        nft["asset_id"] = proof.get("asset_id")
    if proof.get("collection"):
        nft["collection"] = proof.get("collection")
    return nft


def create_chain_unlock_request(
    descriptor: dict[str, Any],
    adapter: dict[str, Any],
    wallet: str,
    proof: SnftUnlockProof,
) -> SnftUnlockRequest:
    runtime = get_runtime_adapter(str(adapter.get("chain") or ""))
    if not runtime:
        raise SnftError(f"No runtime adapter registered for chain: {adapter.get('chain')}")
    adapter_proof = _as_dict(adapter.get("proof"))
    if adapter_proof.get("method") != runtime.proof_method:
        raise SnftError(f"Invalid proof method for {runtime.chain}: expected {runtime.proof_method}, got {adapter_proof.get('method')}")
    if runtime.chain == "ton":
        nft = create_ton_nft_reference(adapter)
    elif runtime.chain == "evm":
        nft = create_evm_nft_reference(adapter)
    else:
        nft = create_solana_nft_reference(adapter)
    return {
        "protocol": "snft",
        "version": str(descriptor.get("version") or "1.0"),
        "skill_id": str(descriptor.get("skill_id") or ""),
        "chain": runtime.chain,
        "wallet": wallet,
        "challenge": str(adapter_proof.get("challenge") or build_unlock_challenge(descriptor)),
        "nft": nft,
        "proof": proof,
    }


def validate_unlock_request(
    request: dict[str, Any],
    descriptor: dict[str, Any],
    adapter: dict[str, Any],
) -> list[SnftValidationIssue]:
    issues: list[SnftValidationIssue] = []
    runtime = get_runtime_adapter(str(request.get("chain") or ""))
    if not runtime:
        return [_issue("runtime_adapter_missing", f"No runtime adapter registered for chain: {request.get('chain')}", "chain")]
    if request.get("protocol") != "snft":
        issues.append(_issue("protocol_invalid", "Unlock request protocol must be snft", "protocol"))
    if request.get("version") != descriptor.get("version"):
        issues.append(_issue("version_mismatch", "Unlock request version does not match descriptor version", "version"))
    if request.get("skill_id") != descriptor.get("skill_id"):
        issues.append(_issue("skill_id_mismatch", "Unlock request skill_id does not match descriptor skill_id", "skill_id"))
    if request.get("chain") != adapter.get("chain"):
        issues.append(_issue("chain_mismatch", "Unlock request chain does not match selected adapter", "chain"))
    proof = _as_dict(request.get("proof"))
    if proof.get("method") != runtime.proof_method:
        issues.append(_issue("proof_method_invalid", f"Expected {runtime.proof_method} proof for {request.get('chain')}", "proof.method"))
    adapter_proof = _as_dict(adapter.get("proof"))
    expected_challenge = adapter_proof.get("challenge") or build_unlock_challenge(descriptor)
    if request.get("challenge") != expected_challenge:
        issues.append(_issue("challenge_mismatch", "Unlock request challenge does not match descriptor challenge", "challenge"))
    nft = _as_dict(request.get("nft"))
    for field in runtime.required_nft_fields:
        if nft.get(field) in (None, ""):
            issues.append(_issue("nft_field_missing", f"Missing NFT field: {field}", f"nft.{field}"))
    return issues


def evaluate_registry_trust(
    descriptor: dict[str, Any],
    *,
    attestation: dict[str, Any] | None = None,
    trusted_registries: list[str] | None = None,
    minimum_trust_level: SnftTrustLevel = "community",
    require_registry: bool = False,
) -> dict[str, Any]:
    warnings: list[SnftValidationIssue] = []
    if not attestation:
        if require_registry:
            warnings.append(_issue("registry_missing", "No registry attestation is attached", "registry"))
        return {"ok": not require_registry, "level": "unknown", "warnings": warnings}
    if attestation.get("skill_id") != descriptor.get("skill_id"):
        warnings.append(_issue("registry_skill_mismatch", "Registry attestation skill_id does not match metadata", "registry.skill_id"))
    if trusted_registries and attestation.get("registry") not in trusted_registries:
        warnings.append(_issue("registry_untrusted", f"Registry is not trusted: {attestation.get('registry')}", "registry.registry"))
    level = str(attestation.get("trust_level") or "unknown")
    if TRUST_ORDER.get(level, -1) < TRUST_ORDER[minimum_trust_level]:
        warnings.append(_issue("registry_trust_low", f"Registry trust level is below required {minimum_trust_level}", "registry.trust_level"))
    if not attestation.get("verified"):
        warnings.append(_issue("registry_unverified", "Skill is not verified by the selected registry", "registry.verified"))
    if attestation.get("scan_verdict") == "blocked":
        warnings.append(_issue("registry_scan_blocked", "Registry security scan blocked this skill", "registry.scan_verdict"))
    return {"ok": not warnings, "level": level, "attestation": attestation, "warnings": warnings}


def build_runtime_attestation_payload(
    *,
    skill_id: str,
    encrypted_sha256: str,
    agent_version: str,
    build_hash: str,
    timestamp: int | str,
) -> str:
    return f"snft-agent-unlock:{skill_id}:{encrypted_sha256}:{agent_version}:{build_hash}:{timestamp}"


def create_runtime_attestation_headers(
    *,
    skill_id: str,
    encrypted_sha256: str,
    agent_version: str,
    build_hash: str,
    attestation_secret: str,
    timestamp: int | str | None = None,
) -> dict[str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    payload = build_runtime_attestation_payload(
        skill_id=skill_id,
        encrypted_sha256=encrypted_sha256,
        agent_version=agent_version,
        build_hash=build_hash,
        timestamp=ts,
    )
    signature = hmac.new(attestation_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-NOTPUNKS-Agent-Version": agent_version,
        "X-NOTPUNKS-Agent-Build-Hash": build_hash,
        "X-NOTPUNKS-Agent-Timestamp": ts,
        "X-NOTPUNKS-Agent-Attestation": f"sha256={signature}",
    }
