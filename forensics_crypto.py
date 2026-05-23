"""
forensics_crypto.py  —  EIP-712 Signature Verification
Cryptographically sign forensics findings for legal defensibility.
Requires: pip install eth-account web3
"""

import hashlib
import json
import streamlit as st
from datetime import datetime
from typing import Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


def _hash_findings(findings: Dict) -> str:
    """SHA-256 hash of findings dict for tamper detection."""
    serialized = json.dumps(findings, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def sign_findings_eip712(
    case_id: str,
    investigator: str,
    findings: Dict,
    private_key: str,
) -> Tuple[Optional[str], str]:
    """
    Sign forensics findings with EIP-712 structured data.
    Returns (signature_hex, findings_hash).
    Falls back to SHA-256 hash-only if eth_account not installed.
    """
    findings_hash = _hash_findings(findings)

    try:
        from eth_account import Account
        from eth_account.messages import encode_structured_data

        message = {
            "types": {
                "EIP712Domain": [
                    {"name": "name",    "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                ],
                "ForensicsReport": [
                    {"name": "caseId",      "type": "string"},
                    {"name": "investigator","type": "string"},
                    {"name": "timestamp",   "type": "uint256"},
                    {"name": "findingsHash","type": "bytes32"},
                    {"name": "riskScore",   "type": "uint8"},
                ],
            },
            "primaryType": "ForensicsReport",
            "domain": {
                "name":    "CryptoForensicsAnalyzer",
                "version": "5.0",
                "chainId": 1,
            },
            "message": {
                "caseId":       case_id,
                "investigator": investigator,
                "timestamp":    int(datetime.now().timestamp()),
                "findingsHash": bytes.fromhex(findings_hash[:64]),
                "riskScore":    min(255, int(findings.get("overall_risk_score", 0))),
            },
        }

        encoded  = encode_structured_data(message)
        account  = Account.from_key(private_key)
        signed   = account.sign_message(encoded)
        return signed.signature.hex(), findings_hash

    except ImportError:
        logger.warning("eth_account not installed — using SHA-256 hash only")
        return None, findings_hash
    except Exception as e:
        logger.error(f"EIP-712 signing failed: {e}")
        return None, findings_hash


def verify_findings_signature(
    signature_hex: str,
    case_id: str,
    investigator: str,
    findings: Dict,
    expected_signer: str,
) -> Tuple[bool, str]:
    """
    Verify an EIP-712 signature on forensics findings.
    Returns (is_valid, recovered_address_or_error).
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_structured_data

        findings_hash = _hash_findings(findings)
        message = {
            "types": {
                "EIP712Domain": [
                    {"name": "name",    "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                ],
                "ForensicsReport": [
                    {"name": "caseId",      "type": "string"},
                    {"name": "investigator","type": "string"},
                    {"name": "timestamp",   "type": "uint256"},
                    {"name": "findingsHash","type": "bytes32"},
                    {"name": "riskScore",   "type": "uint8"},
                ],
            },
            "primaryType": "ForensicsReport",
            "domain": {"name": "CryptoForensicsAnalyzer", "version": "5.0", "chainId": 1},
            "message": {
                "caseId":       case_id,
                "investigator": investigator,
                "timestamp":    int(datetime.now().timestamp()),
                "findingsHash": bytes.fromhex(findings_hash[:64]),
                "riskScore":    min(255, int(findings.get("overall_risk_score", 0))),
            },
        }
        encoded   = encode_structured_data(message)
        recovered = Account.recover_message(encoded, signature=signature_hex)
        match     = recovered.lower() == expected_signer.lower()
        return match, recovered
    except ImportError:
        return False, "eth_account not installed — install with: pip install eth-account"
    except Exception as e:
        return False, str(e)


def generate_findings_certificate(
    case_id: str,
    investigator: str,
    findings: Dict,
    signature: Optional[str],
    findings_hash: str,
    signer_address: Optional[str] = None,
) -> str:
    """Generate a human-readable tamper-evident certificate."""
    signed_status = (
        f"CRYPTOGRAPHICALLY SIGNED\nSigner: {signer_address}\nSignature: {signature[:40]}…"
        if signature else
        "HASH-ONLY (install eth-account for EIP-712 signing)"
    )

    return f"""
╔══════════════════════════════════════════════════════════════════╗
║           CRYPTO FORENSICS FINDINGS CERTIFICATE                  ║
╚══════════════════════════════════════════════════════════════════╝

Case ID:       {case_id}
Investigator:  {investigator}
Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

INTEGRITY VERIFICATION
──────────────────────────────────────────────────────────────────
Findings Hash (SHA-256):
{findings_hash}

Signing Status:
{signed_status}

VERIFICATION INSTRUCTIONS
──────────────────────────────────────────────────────────────────
To verify this certificate:
1. Recalculate SHA-256 of the findings JSON
2. Compare with the hash above
3. If signed: verify EIP-712 signature via ethers.js or web3.py
4. Any mismatch indicates tampering

This certificate provides forensic evidence of findings at time of signing.
──────────────────────────────────────────────────────────────────
Crypto Forensics Analyzer Pro v5.0  |  CONFIDENTIAL
""".strip()


def render_signing_ui(findings: Optional[Dict] = None):
    """EIP-712 signing UI."""
    st.markdown("### 🔐 EIP-712 Cryptographic Signing")
    st.caption(
        "Sign your forensics findings with EIP-712 structured data for legal defensibility. "
        "The signature proves findings were not modified after signing."
    )

    if not findings:
        findings = st.session_state.get("ai_result_dict", {
            "case_id": "DEMO",
            "overall_risk_score": 75,
            "summary": "Demo findings for signing demonstration",
        })

    col1, col2 = st.columns(2)
    with col1:
        case_id      = st.text_input("Case ID",       value=findings.get("case_id",""), key="sig_case")
        investigator = st.text_input("Investigator",  key="sig_inv")
        signer_addr  = st.text_input("Signer Ethereum address (0x…)", key="sig_addr")
    with col2:
        private_key  = st.text_input("Signing private key (local only, never stored)",
                                      type="password", key="sig_pk",
                                      help="Key is used locally to sign — never transmitted")

    st.info("💡 **No eth-account?** Run `pip install eth-account` to enable full EIP-712. "
            "Without it, SHA-256 hash verification is still available.")

    if st.button("✍️ Sign Findings", type="primary", key="sign_btn"):
        with st.spinner("Signing…"):
            sig, fhash = sign_findings_eip712(case_id, investigator, findings,
                                               private_key or "0x" + "0"*64)
            cert = generate_findings_certificate(case_id, investigator, findings,
                                                  sig, fhash, signer_addr)
            st.session_state.certificate = cert
            st.session_state.findings_hash = fhash

    if "certificate" in st.session_state:
        st.text_area("Certificate", st.session_state.certificate, height=300)
        st.download_button("⬇️ Download Certificate",
            st.session_state.certificate.encode(),
            f"certificate_{findings.get('case_id','case')}.txt", "text/plain")
        st.code(f"SHA-256: {st.session_state.findings_hash}", language="text")

    st.markdown("---")
    st.markdown("**🔍 Verify a Signature**")
    verify_sig = st.text_input("Signature to verify (0x…)", key="verify_sig")
    verify_addr = st.text_input("Expected signer address", key="verify_addr")
    if st.button("✅ Verify", key="verify_btn") and verify_sig and verify_addr:
        valid, recovered = verify_findings_signature(verify_sig, case_id, investigator,
                                                      findings, verify_addr)
        if valid:
            st.success(f"✅ Signature VALID — recovered address: `{recovered}`")
        else:
            st.error(f"❌ Signature INVALID — {recovered}")
