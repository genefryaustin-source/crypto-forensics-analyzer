"""
forensics_db.py — Crypto Forensics Analyzer Pro v5.0
Centralized SQLite database for all persistent investigation data.

Replaces flat JSON files with a single robust .db file:
  • Cases (with notes, off-chain payments, evidence files)
  • Watchlist addresses
  • MiCA CASP registrations
  • Evidence audit log
  • API response cache

Database file: crypto_forensics.db (same folder as the app)
No new dependencies — uses Python's built-in sqlite3.
"""

import sqlite3
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import streamlit as st

logger = logging.getLogger(__name__)

DB_PATH = Path("crypto_forensics.db")

# ─────────────────────────────────────────────────────────────
# CONNECTION MANAGEMENT
# ─────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """
    Return a thread-safe SQLite connection with WAL journal mode
    (safe for concurrent Streamlit reruns) and foreign key enforcement.
    """
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row   # rows accessible by column name
    return conn


def initialize_db():
    """
    Create all tables if they don't already exist.
    Safe to call on every app startup — idempotent.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # ── Cases ─────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id         TEXT PRIMARY KEY,
                name            TEXT,
                type            TEXT,
                priority        TEXT DEFAULT 'MEDIUM',
                analyst         TEXT,
                total_value     REAL DEFAULT 0,
                description     TEXT,
                status          TEXT DEFAULT 'OPEN',
                created_at      TEXT,
                updated_at      TEXT,
                sar_filed       INTEGER DEFAULT 0,
                sar_date        TEXT,
                le_referral     INTEGER DEFAULT 0,
                le_date         TEXT,
                le_agency       TEXT,
                assets_frozen   INTEGER DEFAULT 0,
                freeze_amount   REAL DEFAULT 0,
                disposition     TEXT DEFAULT 'PENDING',
                extra_json      TEXT
            )
        """)

        # Ensure newer case metadata columns exist for existing databases
        try:
            existing_cols = {r[1] for r in cur.execute("PRAGMA table_info(cases)").fetchall()}
            if "extra_json" not in existing_cols:
                cur.execute("ALTER TABLE cases ADD COLUMN extra_json TEXT")
        except Exception as e:
            logger.warning(f"Could not verify/migrate cases.extra_json: {e}")

        # ── Case Notes ────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                text        TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id)")

        # ── Off-chain Payments ────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS offchain_payments (
                id                  TEXT PRIMARY KEY,
                case_id             TEXT NOT NULL,
                platform            TEXT,
                transaction_id      TEXT,
                sender_name         TEXT,
                sender_account      TEXT,
                receiver_name       TEXT,
                receiver_account    TEXT,
                amount              REAL DEFAULT 0,
                currency            TEXT DEFAULT 'USD',
                payment_date        TEXT,
                description         TEXT,
                linked_crypto_address TEXT,
                linked_tx_hash      TEXT,
                notes               TEXT,
                screenshot          BLOB,
                screenshot_name     TEXT,
                screenshot_type     TEXT,
                added_at            TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pay_case ON offchain_payments(case_id)")

        # ── Evidence Files ────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS evidence_files (
                id              TEXT PRIMARY KEY,
                case_id         TEXT NOT NULL,
                filename        TEXT,
                file_type       TEXT,
                size_bytes      INTEGER DEFAULT 0,
                data            BLOB,
                description     TEXT,
                linked_address  TEXT,
                added_at        TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_case ON evidence_files(case_id)")

        # ── Watchlist ─────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS watchlist (
                address     TEXT PRIMARY KEY,
                label       TEXT,
                chain       TEXT DEFAULT 'ethereum',
                added_at    TEXT,
                notes       TEXT,
                alert_count INTEGER DEFAULT 0,
                last_alert  TEXT
            )
        """)

        # ── MiCA CASP Registrations ───────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS casp_registrations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                member_state    TEXT,
                category        TEXT,
                status          TEXT DEFAULT 'Pending',
                auth_date       TEXT,
                reference       TEXT,
                added_at        TEXT
            )
        """)

        # ── Evidence Audit Log ────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                action      TEXT NOT NULL,
                analyst     TEXT DEFAULT 'System',
                details     TEXT,
                entry_hash  TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC)")

        # ── API Cache ─────────────────────────────────────────
        # Replaces the scattered JSON cache files
        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_cache (
                cache_key       TEXT PRIMARY KEY,
                value_json      TEXT,
                cached_at       TEXT,
                expires_at      TEXT
            )
        """)

        # ── SAR Drafts ────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sar_drafts (
                id          TEXT PRIMARY KEY,
                case_id     TEXT,
                narrative   TEXT,
                xml_content TEXT,
                created_at  TEXT,
                filed_at    TEXT,
                status      TEXT DEFAULT 'DRAFT'
            )
        """)

        conn.commit()
        logger.info(f"✅ Database initialized: {DB_PATH.resolve()}")
    except Exception as e:
        logger.error(f"DB init error: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# CASES — CRUD
# ─────────────────────────────────────────────────────────────

def load_cases() -> List[Dict]:
    """Load all cases with their notes, payments, and evidence files."""
    conn = get_connection()
    try:
        cur  = conn.cursor()
        rows = cur.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        cases = []
        for row in rows:
            case = dict(row)

            # Merge append-only extended case state stored as JSON.
            # This preserves report lineage, screening runs, evidence timeline,
            # case versions, latest report pointers, and other future metadata.
            extra_raw = case.pop("extra_json", None)
            if extra_raw:
                try:
                    extra = json.loads(extra_raw)
                    if isinstance(extra, dict):
                        case.update(extra)
                except Exception as e:
                    logger.warning(f"Failed to parse cases.extra_json for {case.get('case_id')}: {e}")

            # Convert integer booleans back
            for bool_col in ("sar_filed","le_referral","assets_frozen"):
                case[bool_col] = bool(case.get(bool_col))

            # Always expose append-only collections so UI panels never disappear.
            case.setdefault("screening_runs", [])
            case.setdefault("case_versions", [])
            case.setdefault("evidence_log", [])
            case.setdefault("reports", [])

            # Load notes
            notes = cur.execute(
                "SELECT timestamp, text FROM case_notes WHERE case_id=? ORDER BY timestamp",
                (case["case_id"],)
            ).fetchall()
            case["notes"] = [dict(n) for n in notes]

            # Load off-chain payments (without BLOB data for list view)
            pays = cur.execute("""
                SELECT id,platform,transaction_id,sender_name,sender_account,
                       receiver_name,receiver_account,amount,currency,payment_date,
                       description,linked_crypto_address,linked_tx_hash,notes,
                       screenshot_name,screenshot_type,added_at
                FROM offchain_payments WHERE case_id=? ORDER BY added_at
            """, (case["case_id"],)).fetchall()
            case["offchain_payments"] = [dict(p) for p in pays]

            # Load screenshots separately (BLOB)
            for pay in case["offchain_payments"]:
                ss_row = cur.execute(
                    "SELECT screenshot FROM offchain_payments WHERE id=?", (pay["id"],)
                ).fetchone()
                if ss_row and ss_row["screenshot"]:
                    import base64
                    pay["screenshot"] = base64.b64encode(ss_row["screenshot"]).decode()
                else:
                    pay["screenshot"] = None

            # Load evidence file metadata (without BLOB)
            evs = cur.execute("""
                SELECT id,filename,file_type,size_bytes,description,linked_address,added_at
                FROM evidence_files WHERE case_id=? ORDER BY added_at
            """, (case["case_id"],)).fetchall()
            case["evidence_files"] = []
            for ev in evs:
                ev_dict = dict(ev)
                # Load data BLOB
                blob_row = cur.execute(
                    "SELECT data FROM evidence_files WHERE id=?", (ev["id"],)
                ).fetchone()
                if blob_row and blob_row["data"]:
                    import base64
                    ev_dict["data"] = base64.b64encode(blob_row["data"]).decode()
                else:
                    ev_dict["data"] = ""
                case["evidence_files"].append(ev_dict)

            cases.append(case)
        return cases
    except Exception as e:
        logger.error(f"load_cases error: {e}")
        return []
    finally:
        conn.close()


def save_cases(cases: List[Dict]):
    """
    Upsert a list of cases into the database.
    Notes, payments, and evidence are synced per case.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        for case in cases:
            cid = case["case_id"]

            # Persist append-only / versioned investigation metadata in JSON.
            # Keep the relational columns for dashboard sorting, but do not lose
            # report lineage or rescreen history on reload.
            _extra_keys = [
                "screening_runs", "case_versions", "evidence_log", "reports",
                "latest_report_path", "latest_report_version",
                "latest_report_id", "latest_report_timestamp",
                "global_sanctions_summary", "case_lineage",
            ]
            _extra_payload = {k: case.get(k) for k in _extra_keys if k in case}
            extra_json = json.dumps(_extra_payload, default=str)

            # Upsert case row
            cur.execute("""
                INSERT INTO cases
                    (case_id,name,type,priority,analyst,total_value,description,
                     status,created_at,updated_at,sar_filed,sar_date,
                     le_referral,le_date,le_agency,assets_frozen,freeze_amount,disposition,extra_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(case_id) DO UPDATE SET
                    name=excluded.name, type=excluded.type,
                    priority=excluded.priority, analyst=excluded.analyst,
                    total_value=excluded.total_value, description=excluded.description,
                    status=excluded.status, updated_at=excluded.updated_at,
                    sar_filed=excluded.sar_filed, sar_date=excluded.sar_date,
                    le_referral=excluded.le_referral, le_date=excluded.le_date,
                    le_agency=excluded.le_agency, assets_frozen=excluded.assets_frozen,
                    freeze_amount=excluded.freeze_amount, disposition=excluded.disposition,
                    extra_json=excluded.extra_json
            """, (
                cid,
                case.get("name",""), case.get("type",""), case.get("priority","MEDIUM"),
                case.get("analyst",""), float(case.get("total_value",0)),
                case.get("description",""), case.get("status","OPEN"),
                case.get("created_at",""), case.get("updated_at",""),
                int(case.get("sar_filed",False)), case.get("sar_date"),
                int(case.get("le_referral",False)), case.get("le_date"),
                case.get("le_agency",""), int(case.get("assets_frozen",False)),
                float(case.get("freeze_amount",0)), case.get("disposition","PENDING"),
                extra_json,
            ))

            # Sync notes — delete and re-insert (notes are small)
            cur.execute("DELETE FROM case_notes WHERE case_id=?", (cid,))
            for note in case.get("notes",[]):
                cur.execute(
                    "INSERT INTO case_notes (case_id,timestamp,text) VALUES (?,?,?)",
                    (cid, note.get("timestamp",""), note.get("text",""))
                )

            # Upsert payments
            existing_pay_ids = {
                r[0] for r in cur.execute(
                    "SELECT id FROM offchain_payments WHERE case_id=?", (cid,)
                ).fetchall()
            }
            new_pay_ids = set()
            for pay in case.get("offchain_payments",[]):
                pid = pay.get("id","")
                new_pay_ids.add(pid)
                # Decode screenshot from base64 back to bytes for BLOB storage
                ss_bytes = None
                if pay.get("screenshot"):
                    try:
                        import base64
                        ss_bytes = base64.b64decode(pay["screenshot"].encode())
                    except Exception:
                        pass
                cur.execute("""
                    INSERT INTO offchain_payments
                        (id,case_id,platform,transaction_id,sender_name,sender_account,
                         receiver_name,receiver_account,amount,currency,payment_date,
                         description,linked_crypto_address,linked_tx_hash,notes,
                         screenshot,screenshot_name,screenshot_type,added_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        platform=excluded.platform, amount=excluded.amount,
                        notes=excluded.notes, screenshot=excluded.screenshot,
                        screenshot_name=excluded.screenshot_name,
                        linked_crypto_address=excluded.linked_crypto_address
                """, (
                    pid, cid,
                    pay.get("platform",""), pay.get("transaction_id",""),
                    pay.get("sender_name",""), pay.get("sender_account",""),
                    pay.get("receiver_name",""), pay.get("receiver_account",""),
                    float(pay.get("amount",0)), pay.get("currency","USD"),
                    pay.get("payment_date",""), pay.get("description",""),
                    pay.get("linked_crypto_address",""), pay.get("linked_tx_hash",""),
                    pay.get("notes",""), ss_bytes,
                    pay.get("screenshot_name",""), pay.get("screenshot_type",""),
                    pay.get("added_at",""),
                ))
            # Remove deleted payments
            for old_id in existing_pay_ids - new_pay_ids:
                cur.execute("DELETE FROM offchain_payments WHERE id=?", (old_id,))

            # Upsert evidence files
            existing_ev_ids = {
                r[0] for r in cur.execute(
                    "SELECT id FROM evidence_files WHERE case_id=?", (cid,)
                ).fetchall()
            }
            new_ev_ids = set()
            for ev in case.get("evidence_files",[]):
                eid = ev.get("id","")
                new_ev_ids.add(eid)
                data_bytes = None
                if ev.get("data"):
                    try:
                        import base64
                        data_bytes = base64.b64decode(ev["data"].encode())
                    except Exception:
                        pass
                cur.execute("""
                    INSERT INTO evidence_files
                        (id,case_id,filename,file_type,size_bytes,data,
                         description,linked_address,added_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        filename=excluded.filename, description=excluded.description,
                        data=excluded.data, linked_address=excluded.linked_address
                """, (
                    eid, cid,
                    ev.get("filename",""), ev.get("file_type",""),
                    int(ev.get("size_bytes",0)), data_bytes,
                    ev.get("description",""), ev.get("linked_address",""),
                    ev.get("added_at",""),
                ))
            for old_id in existing_ev_ids - new_ev_ids:
                cur.execute("DELETE FROM evidence_files WHERE id=?", (old_id,))

        conn.commit()
    except Exception as e:
        logger.error(f"save_cases error: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_case(case_id: str):
    """Permanently delete a case and all related data (CASCADE)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM cases WHERE case_id=?", (case_id,))
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# WATCHLIST — CRUD
# ─────────────────────────────────────────────────────────────

def load_watchlist() -> List[Dict]:
    """Load all watchlist addresses."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM watchlist ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_to_watchlist(address: str, label: str = "", chain: str = "ethereum",
                     notes: str = "") -> bool:
    """Add an address to the watchlist. Returns True if added, False if duplicate."""
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO watchlist (address,label,chain,added_at,notes)
            VALUES (?,?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET
                label=excluded.label, chain=excluded.chain, notes=excluded.notes
        """, (address.lower(), label, chain, datetime.now().isoformat(), notes))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_to_watchlist error: {e}")
        return False
    finally:
        conn.close()


def remove_from_watchlist(address: str):
    """Remove an address from the watchlist."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM watchlist WHERE address=?", (address.lower(),))
        conn.commit()
    finally:
        conn.close()


def is_on_watchlist(address: str) -> bool:
    """Check if an address is on the watchlist."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM watchlist WHERE address=?", (address.lower(),)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def increment_alert_count(address: str):
    """Increment the alert counter for a watchlist address."""
    conn = get_connection()
    try:
        conn.execute("""
            UPDATE watchlist
            SET alert_count = alert_count + 1,
                last_alert  = ?
            WHERE address = ?
        """, (datetime.now().isoformat(), address.lower()))
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────────────────────

def log_evidence_action(action: str, details: str, analyst: str = "System"):
    """Append an entry to the evidence audit log."""
    ts        = datetime.now().isoformat()
    raw       = f"{ts}|{action}|{details}"
    entry_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log (timestamp,action,analyst,details,entry_hash) VALUES (?,?,?,?,?)",
            (ts, action, analyst, details, entry_hash)
        )
        conn.commit()
    finally:
        conn.close()


def load_audit_log(limit: int = 200) -> List[Dict]:
    """Load the most recent audit log entries."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# CASP REGISTRATIONS
# ─────────────────────────────────────────────────────────────

def load_casp_registrations() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM casp_registrations ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_casp_registration(member_state: str, category: str, status: str,
                          auth_date: str, reference: str) -> int:
    conn = get_connection()
    try:
        cur = conn.execute("""
            INSERT INTO casp_registrations
                (member_state,category,status,auth_date,reference,added_at)
            VALUES (?,?,?,?,?,?)
        """, (member_state, category, status, auth_date, reference,
              datetime.now().strftime("%Y-%m-%d")))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# API CACHE (replaces scattered JSON cache files)
# ─────────────────────────────────────────────────────────────

def cache_get(key: str) -> Optional[Any]:
    """Retrieve a cached value. Returns None if missing or expired."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT value_json, expires_at FROM api_cache WHERE cache_key=?",
            (key,)
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] and row["expires_at"] < datetime.now().isoformat():
            # Expired
            conn.execute("DELETE FROM api_cache WHERE cache_key=?", (key,))
            conn.commit()
            return None
        return json.loads(row["value_json"])
    finally:
        conn.close()


def cache_set(key: str, value: Any, ttl_seconds: int = 3600):
    """Store a value in the API cache with a TTL."""
    from datetime import timedelta
    expires = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO api_cache (cache_key, value_json, cached_at, expires_at)
            VALUES (?,?,?,?)
            ON CONFLICT(cache_key) DO UPDATE SET
                value_json=excluded.value_json,
                cached_at=excluded.cached_at,
                expires_at=excluded.expires_at
        """, (key, json.dumps(value, default=str), datetime.now().isoformat(), expires))
        conn.commit()
    finally:
        conn.close()


def cache_clear_expired():
    """Remove all expired cache entries."""
    conn = get_connection()
    try:
        conn.execute(
            "DELETE FROM api_cache WHERE expires_at < ?",
            (datetime.now().isoformat(),)
        )
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# SAR DRAFTS
# ─────────────────────────────────────────────────────────────

def save_sar_draft(case_id: str, narrative: str, xml_content: str = "") -> str:
    """Save a SAR draft. Returns the draft ID."""
    import uuid
    draft_id = f"sar_{uuid.uuid4().hex[:12]}"
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO sar_drafts (id,case_id,narrative,xml_content,created_at,status)
            VALUES (?,?,?,?,?,?)
        """, (draft_id, case_id, narrative, xml_content,
              datetime.now().isoformat(), "DRAFT"))
        conn.commit()
        return draft_id
    finally:
        conn.close()


def load_sar_drafts(case_id: str = None) -> List[Dict]:
    conn = get_connection()
    try:
        if case_id:
            rows = conn.execute(
                "SELECT * FROM sar_drafts WHERE case_id=? ORDER BY created_at DESC",
                (case_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sar_drafts ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────
# DATABASE BACKUP / RESTORE
# ─────────────────────────────────────────────────────────────

def export_database() -> bytes:
    """
    Export the entire SQLite database as bytes for download.
    Returns the raw .db file contents — can be restored with import_database().
    """
    if not DB_PATH.exists():
        return b""
    return DB_PATH.read_bytes()


def import_database(db_bytes: bytes) -> bool:
    """
    Replace the current database with an uploaded backup.
    Returns True on success.
    """
    try:
        # Validate: try connecting to the uploaded bytes as SQLite
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
            tmp.write(db_bytes)
            tmp_path = tmp.name

        test_conn = sqlite3.connect(tmp_path)
        test_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        test_conn.close()
        os.unlink(tmp_path)

        # Write to production path
        DB_PATH.write_bytes(db_bytes)
        logger.info(f"✅ Database restored from backup ({len(db_bytes):,} bytes)")
        return True
    except Exception as e:
        logger.error(f"Database restore failed: {e}")
        return False


def migrate_from_json():
    """
    One-time migration: import existing regulatory_cases.json into SQLite.
    Runs automatically if the JSON file exists and has content.
    """
    json_path = Path("regulatory_cases.json")
    if not json_path.exists():
        return

    try:
        cases = json.loads(json_path.read_text(encoding="utf-8"))
        if not cases:
            return

        # Check if we already migrated
        conn = get_connection()
        existing = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        conn.close()
        if existing > 0:
            return  # Already have data — don't overwrite

        save_cases(cases)
        # Rename old file so we don't migrate again
        json_path.rename(json_path.with_suffix(".json.migrated"))
        logger.info(f"✅ Migrated {len(cases)} cases from regulatory_cases.json → SQLite")
    except Exception as e:
        logger.warning(f"JSON migration failed: {e}")


def migrate_from_watchlist_json():
    """One-time migration of watchlist.json."""
    wl_path = Path("watchlist.json")
    if not wl_path.exists():
        return
    try:
        data = json.loads(wl_path.read_text(encoding="utf-8"))
        conn = get_connection()
        existing = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
        conn.close()
        if existing > 0:
            return
        entries = data if isinstance(data, list) else [
            {"address": k, "label": v if isinstance(v, str) else v.get("label",""),
             "chain": v.get("chain","ethereum") if isinstance(v, dict) else "ethereum"}
            for k, v in data.items()
        ] if isinstance(data, dict) else []
        for e in entries:
            add_to_watchlist(e.get("address",""), e.get("label",""),
                             e.get("chain","ethereum"))
        wl_path.rename(wl_path.with_suffix(".json.migrated"))
        logger.info(f"✅ Migrated {len(entries)} watchlist entries from JSON → SQLite")
    except Exception as e:
        logger.warning(f"Watchlist migration failed: {e}")


# ─────────────────────────────────────────────────────────────
# DATABASE STATUS WIDGET (sidebar)
# ─────────────────────────────────────────────────────────────

def render_db_sidebar():
    """
    Small sidebar widget showing database status and
    download/upload buttons for backup/restore.
    """
    with st.sidebar.expander("🗄️ Database", expanded=False):
        if DB_PATH.exists():
            size_kb = DB_PATH.stat().st_size / 1024

            # Quick stats
            try:
                conn   = get_connection()
                cases  = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
                pays   = conn.execute("SELECT COUNT(*) FROM offchain_payments").fetchone()[0]
                evs    = conn.execute("SELECT COUNT(*) FROM evidence_files").fetchone()[0]
                wl     = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
                conn.close()
                st.caption(
                    f"📁 `{DB_PATH.name}` · {size_kb:.1f} KB\n\n"
                    f"Cases: **{cases}** · Payments: **{pays}** · "
                    f"Files: **{evs}** · Watchlist: **{wl}**"
                )
            except Exception:
                st.caption(f"📁 {DB_PATH.name} · {size_kb:.1f} KB")

            # Download backup
            db_bytes = export_database()
            if db_bytes:
                st.download_button(
                    "⬇️ Download Database Backup",
                    data=db_bytes,
                    file_name=f"crypto_forensics_{datetime.now().strftime('%Y%m%d_%H%M')}.db",
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="dl_db_backup",
                )
        else:
            st.caption("Database not yet created")

        # Restore from backup
        uploaded_db = st.file_uploader(
            "Restore from backup (.db)",
            type=["db"],
            key="db_restore_upload",
        )
        if uploaded_db is not None:
            if st.button("🔄 Restore Now", type="primary",
                         use_container_width=True, key="db_restore_btn"):
                if import_database(uploaded_db.read()):
                    st.success("✅ Database restored — restart app")
                    st.rerun()
                else:
                    st.error("❌ Restore failed — invalid database file")
