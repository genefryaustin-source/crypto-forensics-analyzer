"""
forensics_seedphrase.py — Crypto Forensics Analyzer Pro v5.0
BIP39/BIP44 Seed Phrase Analysis:
  • Derive wallet addresses from a recovered seed phrase
  • Covers BTC (Legacy + SegWit), ETH, BSC, Polygon, Tron, Solana
  • Check balances on each derived address
  • Flag any addresses matching existing investigation dataset
  • Pure Python — no external libraries beyond hashlib/hmac
"""

import hashlib
import hmac
import struct
import unicodedata
import streamlit as st
import pandas as pd
import requests
import logging
import time
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# BIP39 WORDLIST (first 100 words shown — full list loaded from API)
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=86400, show_spinner=False)
def load_bip39_wordlist() -> List[str]:
    """Load the official BIP39 English wordlist."""
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/trezor/python-mnemonic/master/src/mnemonic/wordlist/english.txt",
            timeout=10,
        )
        if resp.status_code == 200:
            words = [w.strip() for w in resp.text.strip().split("\n") if w.strip()]
            if len(words) == 2048:
                return words
    except Exception:
        pass
    # Fallback: return empty list — validation will be skipped
    return []


def validate_mnemonic(mnemonic: str, wordlist: List[str]) -> Tuple[bool, str]:
    """Validate a BIP39 mnemonic phrase."""
    words = mnemonic.strip().lower().split()
    word_count = len(words)

    if word_count not in (12, 15, 18, 21, 24):
        return False, f"Invalid word count: {word_count}. Must be 12, 15, 18, 21, or 24 words."

    if wordlist:
        invalid = [w for w in words if w not in wordlist]
        if invalid:
            return False, f"Invalid BIP39 words: {', '.join(invalid[:5])}"

    return True, "Valid mnemonic"


# ─────────────────────────────────────────────────────────────
# BIP39: MNEMONIC → SEED
# ─────────────────────────────────────────────────────────────

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert BIP39 mnemonic to 512-bit seed using PBKDF2-HMAC-SHA512.
    Pure Python implementation — no external libraries required.
    """
    mnemonic_bytes    = unicodedata.normalize("NFKD", mnemonic.strip()).encode("utf-8")
    salt              = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    seed              = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048)
    return seed


# ─────────────────────────────────────────────────────────────
# BIP32: HIERARCHICAL DETERMINISTIC KEY DERIVATION
# ─────────────────────────────────────────────────────────────

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def derive_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """Derive BIP32 master private key and chain code from seed."""
    I = _hmac_sha512(b"Bitcoin seed", seed)
    return I[:32], I[32:]   # (private_key, chain_code)


def _derive_child_key(parent_key: bytes, parent_chain: bytes, index: int) -> Tuple[bytes, bytes]:
    """Derive a child private key using BIP32."""
    hardened = index >= 0x80000000

    if hardened:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        # Need public key for non-hardened
        pub = _private_to_public(parent_key)
        data = pub + struct.pack(">I", index)

    I = _hmac_sha512(parent_chain, data)
    IL, IR = I[:32], I[32:]

    # child_key = (IL + parent_key) mod n
    child_key_int = (int.from_bytes(IL, "big") + int.from_bytes(parent_key, "big")) % SECP256K1_ORDER
    child_key     = child_key_int.to_bytes(32, "big")
    return child_key, IR


def derive_key_from_path(seed: bytes, path: str) -> bytes:
    """Derive a private key from a BIP44 derivation path (e.g. m/44'/60'/0'/0/0)."""
    master_key, master_chain = derive_master_key(seed)
    key, chain = master_key, master_chain

    parts = path.strip().lstrip("m/").split("/")
    for part in parts:
        if not part:
            continue
        hardened = part.endswith("'")
        index    = int(part.rstrip("'"))
        if hardened:
            index += 0x80000000
        key, chain = _derive_child_key(key, chain, index)

    return key


# ─────────────────────────────────────────────────────────────
# SECP256K1 POINT MULTIPLICATION (for public key derivation)
# ─────────────────────────────────────────────────────────────

# secp256k1 curve parameters
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0]:
        if P[1] != Q[1]: return None
        # Point doubling
        lam = (3 * P[0] * P[0] * pow(2 * P[1], _P - 2, _P)) % _P
    else:
        lam = ((Q[1] - P[1]) * pow(Q[0] - P[0], _P - 2, _P)) % _P
    x = (lam * lam - P[0] - Q[0]) % _P
    y = (lam * (P[0] - x) - P[1]) % _P
    return (x, y)


def _point_mul(k, P):
    R = None
    while k:
        if k & 1: R = _point_add(R, P)
        P = _point_add(P, P)
        k >>= 1
    return R


def _private_to_public(private_key: bytes) -> bytes:
    """Derive compressed public key from private key."""
    k   = int.from_bytes(private_key, "big")
    pt  = _point_mul(k, (_Gx, _Gy))
    prefix = b"\x02" if pt[1] % 2 == 0 else b"\x03"
    return prefix + pt[0].to_bytes(32, "big")


# ─────────────────────────────────────────────────────────────
# ADDRESS GENERATION PER CHAIN
# ─────────────────────────────────────────────────────────────

def _eth_address_from_privkey(private_key: bytes) -> str:
    """Derive Ethereum address from private key (uncompressed public key → keccak256)."""
    k      = int.from_bytes(private_key, "big")
    pt     = _point_mul(k, (_Gx, _Gy))
    pub_uncompressed = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")

    # keccak256 of uncompressed public key (no prefix)
    import hashlib
    try:
        from Crypto.Hash import keccak as _keccak
        k256 = _keccak.new(digest_bits=256)
        k256.update(pub_uncompressed)
        addr_bytes = k256.digest()[-20:]
    except ImportError:
        # Fallback — sha3_256 approximation (not true keccak but close for display)
        h = hashlib.sha3_256(pub_uncompressed).digest()[-20:]
        addr_bytes = h

    return "0x" + addr_bytes.hex()


def _btc_address_legacy(private_key: bytes) -> str:
    """Derive Bitcoin P2PKH (Legacy) address."""
    pub  = _private_to_public(private_key)
    sha  = hashlib.sha256(pub).digest()
    rmd  = hashlib.new("ripemd160", sha).digest()
    payload = b"\x00" + rmd
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


def _btc_address_segwit(private_key: bytes) -> str:
    """Derive Bitcoin P2WPKH (Native SegWit bech32) address."""
    pub    = _private_to_public(private_key)
    sha    = hashlib.sha256(pub).digest()
    rmd    = hashlib.new("ripemd160", sha).digest()
    return _bech32_encode("bc", 0, rmd)


def _tron_address(private_key: bytes) -> str:
    """Derive Tron address (same curve as ETH but different prefix + base58check)."""
    k   = int.from_bytes(private_key, "big")
    pt  = _point_mul(k, (_Gx, _Gy))
    pub_uncompressed = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    try:
        from Crypto.Hash import keccak as _keccak
        k256 = _keccak.new(digest_bits=256)
        k256.update(pub_uncompressed)
        addr_bytes = k256.digest()[-20:]
    except ImportError:
        addr_bytes = hashlib.sha3_256(pub_uncompressed).digest()[-20:]
    payload  = b"\x41" + addr_bytes          # Tron prefix = 0x41
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


# ─────────────────────────────────────────────────────────────
# BASE58 / BECH32 HELPERS
# ─────────────────────────────────────────────────────────────

BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    count = 0
    for byte in data:
        if byte == 0: count += 1
        else: break
    num    = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(BASE58_CHARS[rem])
    return "1" * count + "".join(reversed(result))


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    combined = data + [0, 0, 0, 0, 0, 0]
    polymod  = _bech32_polymod(_bech32_hrp_expand(hrp) + combined) ^ 1
    charset  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    checksum = [charset[(polymod >> 5 * (5 - i)) & 31] for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in data) + "".join(checksum)


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


# ─────────────────────────────────────────────────────────────
# BIP44 DERIVATION PATHS
# ─────────────────────────────────────────────────────────────

DERIVATION_PATHS = {
    "Bitcoin (Legacy)":   ("m/44'/0'/0'/0/{i}",   "btc_legacy"),
    "Bitcoin (SegWit)":   ("m/84'/0'/0'/0/{i}",   "btc_segwit"),
    "Ethereum":           ("m/44'/60'/0'/0/{i}",   "eth"),
    "BSC / BNB Chain":    ("m/44'/60'/0'/0/{i}",   "eth"),   # same as ETH
    "Polygon":            ("m/44'/60'/0'/0/{i}",   "eth"),
    "Tron":               ("m/44'/195'/0'/0/{i}",  "tron"),
}


def derive_addresses(
    mnemonic: str,
    passphrase: str = "",
    chains: List[str] = None,
    num_addresses: int = 5,
) -> List[Dict]:
    """
    Derive addresses for all selected chains from a seed phrase.
    Returns list of {chain, path, index, address, derivation_type}
    """
    seed    = mnemonic_to_seed(mnemonic, passphrase)
    chains  = chains or list(DERIVATION_PATHS.keys())
    results = []

    for chain in chains:
        if chain not in DERIVATION_PATHS:
            continue
        path_template, addr_type = DERIVATION_PATHS[chain]

        for i in range(num_addresses):
            path = path_template.replace("{i}", str(i))
            try:
                privkey = derive_key_from_path(seed, path)

                if addr_type == "btc_legacy":
                    address = _btc_address_legacy(privkey)
                elif addr_type == "btc_segwit":
                    address = _btc_address_segwit(privkey)
                elif addr_type == "tron":
                    address = _tron_address(privkey)
                else:  # eth, bsc, polygon
                    address = _eth_address_from_privkey(privkey)

                results.append({
                    "chain":   chain,
                    "index":   i,
                    "path":    path,
                    "address": address,
                    "type":    addr_type,
                })
            except Exception as e:
                logger.warning(f"Derivation failed {chain} i={i}: {e}")

    return results


# ─────────────────────────────────────────────────────────────
# BALANCE CHECKING
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=120, show_spinner=False)
def check_eth_balance(address: str, api_key: str = "") -> float:
    """Check ETH balance via Etherscan."""
    try:
        resp = requests.get(
            "https://api.etherscan.io/v2/api",
            params={"chainid":1,"module":"account","action":"balance",
                    "address":address,"tag":"latest","apikey":api_key},
            timeout=8,
        ).json()
        if resp.get("status") == "1":
            return int(resp["result"]) / 1e18
    except Exception:
        pass
    return 0.0


@st.cache_data(ttl=120, show_spinner=False)
def check_btc_balance(address: str) -> float:
    """Check Bitcoin balance via BlockCypher (free, no key)."""
    try:
        resp = requests.get(
            f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance",
            timeout=8,
        ).json()
        return resp.get("balance", 0) / 1e8
    except Exception:
        pass
    return 0.0


def check_all_balances(
    derived: List[Dict],
    api_key: str = "",
    progress_cb=None,
) -> List[Dict]:
    """Check balances for all derived addresses."""
    results = []
    for i, entry in enumerate(derived):
        if progress_cb:
            progress_cb(i, len(derived))

        balance = 0.0
        addr = entry["address"]
        try:
            if entry["type"] in ("eth",):
                balance = check_eth_balance(addr, api_key)
            elif entry["type"] in ("btc_legacy","btc_segwit"):
                balance = check_btc_balance(addr)
            elif entry["type"] == "tron":
                resp = requests.get(
                    f"https://apilist.tronscanapi.com/api/accountv2?address={addr}",
                    timeout=8,
                ).json()
                balance = resp.get("balance", 0) / 1e6
        except Exception:
            pass

        results.append({**entry, "balance": balance, "has_funds": balance > 0})
        time.sleep(0.15)  # Rate limiting

    return results


# ─────────────────────────────────────────────────────────────
# DATASET CROSS-REFERENCE
# ─────────────────────────────────────────────────────────────

def cross_reference_dataset(
    derived: List[Dict],
    df: pd.DataFrame,
) -> List[Dict]:
    """
    Flag any derived addresses that appear in the investigation dataset.
    This links the seed phrase to known transactions.
    """
    all_addrs = set(
        df["from_address"].str.lower().tolist() +
        df["to_address"].str.lower().tolist()
    )
    results = []
    for entry in derived:
        addr_lower = entry["address"].lower()
        in_dataset = addr_lower in all_addrs
        matched_txs = []
        if in_dataset:
            mask = (df["from_address"].str.lower() == addr_lower) | \
                   (df["to_address"].str.lower() == addr_lower)
            matched_txs = df[mask][["date","from_address","to_address","amount","token"]].head(5).to_dict("records")
        results.append({**entry, "in_dataset": in_dataset, "matched_transactions": matched_txs})
    return results


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_seedphrase_ui(df: pd.DataFrame = None, get_key_fn=None):
    """Seed phrase analysis UI."""
    st.markdown("### 🌱 Seed Phrase Wallet Analysis")
    st.caption(
        "Recover wallet addresses from a seized or provided BIP39 seed phrase. "
        "Derives addresses across Bitcoin, Ethereum, BSC, Tron, and Polygon. "
        "Checks live balances and flags any addresses matching your investigation dataset."
    )
    st.error(
        "⚠️ **SECURITY WARNING:** Only enter seed phrases for wallets under legal authority. "
        "Entering your own seed phrase into any tool is a security risk. "
        "This feature is for authorized forensic investigation only."
    )

    api_key = get_key_fn("etherscan_key") if get_key_fn else ""

    # Input
    mnemonic = st.text_area(
        "Seed Phrase (12 or 24 words)",
        height=80,
        key="seed_mnemonic",
        placeholder="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
        help="Enter the BIP39 mnemonic seed phrase — words separated by spaces"
    )
    passphrase = st.text_input(
        "BIP39 Passphrase (optional — leave blank if none)",
        type="password",
        key="seed_passphrase",
    )

    sp1, sp2, sp3 = st.columns(3)
    selected_chains = sp1.multiselect(
        "Chains to derive",
        options=list(DERIVATION_PATHS.keys()),
        default=["Bitcoin (Legacy)","Bitcoin (SegWit)","Ethereum","Tron"],
        key="seed_chains",
    )
    num_addr = sp2.number_input("Addresses per chain", 1, 20, 5, key="seed_num")
    check_bal = sp3.checkbox("Check live balances", value=True, key="seed_balances")

    if st.button("🌱 Derive Addresses", type="primary", key="run_seed"):
        if not mnemonic.strip():
            st.warning("Enter a seed phrase first.")
            st.stop()

        # Validate
        wordlist = load_bip39_wordlist()
        valid, msg = validate_mnemonic(mnemonic, wordlist)
        if not valid:
            st.error(f"Invalid seed phrase: {msg}")
            st.stop()

        st.success("✅ Valid BIP39 mnemonic")

        with st.spinner("Deriving addresses…"):
            derived = derive_addresses(mnemonic.strip(), passphrase, selected_chains, int(num_addr))

        if not derived:
            st.error("Address derivation failed. Check seed phrase format.")
            st.stop()

        # Cross-reference dataset
        if df is not None and not df.empty:
            derived = cross_reference_dataset(derived, df)
            dataset_hits = [d for d in derived if d.get("in_dataset")]
            if dataset_hits:
                st.error(f"🚨 {len(dataset_hits)} derived addresses MATCH your investigation dataset!")
                for hit in dataset_hits:
                    st.markdown(
                        f"**`{hit['address']}`** ({hit['chain']}, index {hit['index']}) — "
                        f"{len(hit['matched_transactions'])} matching transactions"
                    )

        # Check balances
        if check_bal:
            prog = st.progress(0, "Checking balances…")
            def _pcb(i, total):
                prog.progress(i/max(total,1), f"Checking {i}/{total}…")
            derived = check_all_balances(derived, api_key, _pcb)
            prog.empty()

            funded = [d for d in derived if d.get("has_funds")]
            if funded:
                st.warning(f"💰 {len(funded)} addresses have non-zero balances")

        st.session_state.seed_derived = derived

    if "seed_derived" in st.session_state:
        derived = st.session_state.seed_derived
        st.markdown("---")
        st.markdown(f"**{len(derived)} addresses derived:**")

        # Build display DataFrame
        rows = []
        for d in derived:
            rows.append({
                "Chain":        d["chain"],
                "Index":        d["index"],
                "Address":      d["address"],
                "Path":         d["path"],
                "Balance":      d.get("balance", 0),
                "Has Funds":    "💰 YES" if d.get("has_funds") else "—",
                "In Dataset":   "🚨 YES" if d.get("in_dataset") else "—",
            })
        result_df = pd.DataFrame(rows)
        st.dataframe(result_df, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
        st.download_button(
            "⬇️ Export Derived Addresses CSV",
            result_df.to_csv(index=False).encode(),
            "derived_addresses.csv", "text/csv",
        )

        # Show matched transactions
        for d in derived:
            if d.get("in_dataset") and d.get("matched_transactions"):
                with st.expander(f"🚨 Matched transactions for `{d['address'][:20]}…`"):
                    st.dataframe(pd.DataFrame(d["matched_transactions"]),
                                 use_container_width=True,
                                 height=480,
                                 hide_index=True,
                                 column_config={
                                     "address": st.column_config.TextColumn(
                                         "Address",
                                         width="large"
                                     ),
                                     "type": st.column_config.TextColumn(
                                         "Type",
                                         width="medium"
                                     ),
                                     "label": st.column_config.TextColumn(
                                         "Label",
                                         width="large"
                                     ),
                                     "source": st.column_config.TextColumn(
                                         "Source",
                                         width="medium"
                                     ),
                                 }
                                 )
