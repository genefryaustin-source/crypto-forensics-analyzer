"""
Advanced Multi-hop Fund Tracing Module
Traces funds through blockchain networks with configurable depth.
"""

import pandas as pd
from typing import Dict, List, Set, Tuple, Optional
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HopTracer:
    """
    Traces funds through transactions across multiple hops.
    Supports both forward tracing (where funds go) and backward tracing (where funds come from).
    """

    def __init__(
        self,
        df: pd.DataFrame,
        max_hops: int = 10,
        max_addresses_per_hop: int = 100,
        include_internal: bool = False,
    ):
        """
        Initialize the tracer.
        
        Args:
            df: DataFrame with columns: from_address, to_address, amount, date, tx_hash, chain, token
            max_hops: Maximum number of hops to trace
            max_addresses_per_hop: Maximum addresses to follow per hop
            include_internal: Include internal/contract transactions
        """
        self.df = df.copy()
        # Normalize address columns safely
        for col in ["from_address", "to_address"]:
            if col in df.columns:
                df[col] = (
                    df[col]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                )

        # Normalize token safely
        if "token" in df.columns:
            df["token"] = (
                df["token"]
                .fillna("")
                .astype(str)
                .str.strip()
            )

        # Normalize risk safely
        if "risk_level" in df.columns:
            df["risk_level"] = (
                df["risk_level"]
                .fillna("LOW")
                .astype(str)
                .str.upper()
            )

        # Normalize amount safely
        if "amount" in df.columns:
            df["amount"] = pd.to_numeric(
                df["amount"],
                errors="coerce"
            ).fillna(0)
        # Normalize address columns safely
        for col in ["from_address", "to_address"]:
            if col in df.columns:
                df[col] = (
                    df[col]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                )

        # Normalize token safely
        if "token" in df.columns:
            df["token"] = (
                df["token"]
                .fillna("")
                .astype(str)
                .str.strip()
            )

        # Normalize risk safely
        if "risk_level" in df.columns:
            df["risk_level"] = (
                df["risk_level"]
                .fillna("LOW")
                .astype(str)
                .str.upper()
            )

        # Normalize amount safely
        if "amount" in df.columns:
            df["amount"] = pd.to_numeric(
                df["amount"],
                errors="coerce"
            ).fillna(0)
        self.max_hops = max_hops
        self.max_addresses_per_hop = max_addresses_per_hop
        self.include_internal = include_internal
        self.trace_history = {}
        self.visited_addresses = set()

    def _normalize_address(self, addr: str) -> str:
        """Normalize address for comparison."""
        return str(addr).lower().strip()

    def _get_outbound_txs(self, address: str) -> pd.DataFrame:
        """Get all outbound transactions from an address."""
        norm_addr = self._normalize_address(address)
        mask = self.df["from_address"].apply(lambda x: self._normalize_address(x) == norm_addr)
        return self.df[mask].copy()

    def _get_inbound_txs(self, address: str) -> pd.DataFrame:
        """Get all inbound transactions to an address."""
        norm_addr = self._normalize_address(address)
        mask = self.df["to_address"].apply(lambda x: self._normalize_address(x) == norm_addr)
        return self.df[mask].copy()

    def trace_forward(
        self, start_address: str, max_hops: Optional[int] = None, progress_callback=None
    ) -> Dict:
        """
        Trace funds FORWARD from starting address (where the money goes).
        
        Args:
            start_address: Starting address
            max_hops: Override default max_hops
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict with hop information and statistics
        """
        max_hops = max_hops or self.max_hops
        hops = {}
        current_layer = {self._normalize_address(start_address)}
        self.visited_addresses = {self._normalize_address(start_address)}
        total_volume = 0
        total_txs = 0

        for hop_num in range(1, max_hops + 1):
            if progress_callback:
                progress_callback(f"Tracing forward... Hop {hop_num}/{max_hops}")

            next_layer = set()
            hop_txs = []

            for address in current_layer:
                outbound = self._get_outbound_txs(address)

                for _, tx in outbound.iterrows():
                    to_addr = self._normalize_address(tx["to_address"])
                    
                    hop_data = {
                        "hop": hop_num,
                        "from_address": tx["from_address"],
                        "to_address": tx["to_address"],
                        "amount": float(tx.get("amount", 0)),
                        "token": str(tx.get("token", "UNKNOWN")),
                        "tx_hash": str(tx.get("tx_hash", "")),
                        "date": str(tx.get("date", "")),
                        "chain": str(tx.get("chain", "Unknown")),
                        "risk_level": str(tx.get("risk_level", "UNKNOWN")),
                    }
                    hop_txs.append(hop_data)
                    total_volume += hop_data["amount"]
                    total_txs += 1
                    
                    # Add to next layer if not visited and under limit
                    if to_addr not in self.visited_addresses:
                        next_layer.add(to_addr)
                        self.visited_addresses.add(to_addr)

            # Limit addresses for next hop
            if len(next_layer) > self.max_addresses_per_hop:
                # Keep only top addresses by transaction volume
                next_layer_with_vol = {}
                for addr in next_layer:
                    vol = sum(
                        tx.get("amount", 0)
                        for tx in hop_txs
                        if self._normalize_address(tx["to_address"]) == addr
                    )
                    next_layer_with_vol[addr] = vol

                next_layer = set(
                    sorted(next_layer_with_vol.items(), key=lambda x: x[1], reverse=True)[
                        : self.max_addresses_per_hop
                    ][0]
                )
                logger.info(f"Limited hop {hop_num} to top {self.max_addresses_per_hop} addresses")

            if hop_txs:
                hops[hop_num] = hop_txs
            
            if not next_layer:
                logger.info(f"Trace ended at hop {hop_num} - no more outbound txs")
                break

            current_layer = next_layer

        return {
            "direction": "forward",
            "start_address": start_address,
            "hops": hops,
            "total_hops": len(hops),
            "total_transactions": total_txs,
            "total_volume": total_volume,
            "unique_addresses": len(self.visited_addresses),
        }

    def trace_backward(
        self, start_address: str, max_hops: Optional[int] = None, progress_callback=None
    ) -> Dict:
        """
        Trace funds BACKWARD to starting address (where the money came from).
        
        Args:
            start_address: Starting address
            max_hops: Override default max_hops
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict with hop information and statistics
        """
        max_hops = max_hops or self.max_hops
        hops = {}
        current_layer = {self._normalize_address(start_address)}
        self.visited_addresses = {self._normalize_address(start_address)}
        total_volume = 0
        total_txs = 0

        for hop_num in range(1, max_hops + 1):
            if progress_callback:
                progress_callback(f"Tracing backward... Hop {hop_num}/{max_hops}")

            next_layer = set()
            hop_txs = []

            for address in current_layer:
                inbound = self._get_inbound_txs(address)

                for _, tx in inbound.iterrows():
                    from_addr = self._normalize_address(tx["from_address"])
                    
                    hop_data = {
                        "hop": hop_num,
                        "from_address": tx["from_address"],
                        "to_address": tx["to_address"],
                        "amount": float(tx.get("amount", 0)),
                        "token": str(tx.get("token", "UNKNOWN")),
                        "tx_hash": str(tx.get("tx_hash", "")),
                        "date": str(tx.get("date", "")),
                        "chain": str(tx.get("chain", "Unknown")),
                        "risk_level": str(tx.get("risk_level", "UNKNOWN")),
                    }
                    hop_txs.append(hop_data)
                    total_volume += hop_data["amount"]
                    total_txs += 1
                    
                    # Add to next layer if not visited and under limit
                    if from_addr not in self.visited_addresses:
                        next_layer.add(from_addr)
                        self.visited_addresses.add(from_addr)

            # Limit addresses for next hop
            if len(next_layer) > self.max_addresses_per_hop:
                next_layer_with_vol = {}
                for addr in next_layer:
                    vol = sum(
                        tx.get("amount", 0)
                        for tx in hop_txs
                        if self._normalize_address(tx["from_address"]) == addr
                    )
                    next_layer_with_vol[addr] = vol

                next_layer = set(
                    sorted(next_layer_with_vol.items(), key=lambda x: x[1], reverse=True)[
                        : self.max_addresses_per_hop
                    ][0]
                )
                logger.info(f"Limited hop {hop_num} to top {self.max_addresses_per_hop} addresses")

            if hop_txs:
                hops[hop_num] = hop_txs
            
            if not next_layer:
                logger.info(f"Trace ended at hop {hop_num} - no more inbound txs")
                break

            current_layer = next_layer

        return {
            "direction": "backward",
            "start_address": start_address,
            "hops": hops,
            "total_hops": len(hops),
            "total_transactions": total_txs,
            "total_volume": total_volume,
            "unique_addresses": len(self.visited_addresses),
        }

    def trace_both_directions(
        self, start_address: str, max_hops: Optional[int] = None, progress_callback=None
    ) -> Dict:
        """
        Trace in BOTH directions (funds coming in and going out).
        """
        forward = self.trace_forward(start_address, max_hops, progress_callback)
        backward = self.trace_backward(start_address, max_hops, progress_callback)

        return {
            "forward": forward,
            "backward": backward,
            "combined_unique_addresses": len(self.visited_addresses),
        }

    def get_trace_summary(self, trace_result: Dict) -> str:
        """
        Generate a human-readable summary of the trace.
        """
        if "forward" in trace_result:  # Both directions
            fwd = trace_result["forward"]
            bwd = trace_result["backward"]
            summary = f"""
FUND TRACING SUMMARY (BOTH DIRECTIONS)
{'='*60}
Start Address: {fwd['start_address']}

FORWARD TRACE (Outbound):
  Total Hops: {fwd['total_hops']}
  Total Transactions: {fwd['total_transactions']}
  Total Volume: ${fwd['total_volume']:,.2f}
  Unique Addresses Reached: {fwd['unique_addresses']}

BACKWARD TRACE (Inbound):
  Total Hops: {bwd['total_hops']}
  Total Transactions: {bwd['total_transactions']}
  Total Volume: ${bwd['total_volume']:,.2f}
  Unique Addresses Reached: {bwd['unique_addresses']}

Combined Unique Addresses: {trace_result['combined_unique_addresses']}
"""
        else:
            direction = trace_result.get("direction", "unknown")
            summary = f"""
FUND TRACING SUMMARY ({direction.upper()})
{'='*60}
Start Address: {trace_result['start_address']}
Total Hops: {trace_result['total_hops']}
Total Transactions: {trace_result['total_transactions']}
Total Volume: ${trace_result['total_volume']:,.2f}
Unique Addresses: {trace_result['unique_addresses']}
"""

        return summary

    def get_address_risk_summary(self, trace_result: Dict) -> pd.DataFrame:
        """
        Get risk summary for all addresses in the trace.
        Returns a DataFrame with address risk analysis.
        """
        all_hops = []
        
        # Extract hops from both single direction and both directions results
        if "forward" in trace_result:
            # Both directions case
            all_hops.extend(trace_result["forward"]["hops"].values())
            all_hops.extend(trace_result["backward"]["hops"].values())
        else:
            # Single direction case
            all_hops = list(trace_result.get("hops", {}).values())

        # Return empty DataFrame if no hops
        if not all_hops:
            logger.warning("No hops found in trace result")
            return pd.DataFrame(columns=[
                "address", "total_volume", "transaction_count", "avg_transaction_value",
                "risk_critical_count", "risk_high_count", "risk_medium_count", "risk_low_count",
                "primary_risk", "chains_involved", "tokens_involved"
            ])

        addresses = {}
        
        # Process all transactions in all hops
        for hops_list in all_hops:
            for tx in hops_list:
                for addr in [tx.get("from_address"), tx.get("to_address")]:
                    if not addr:
                        continue
                        
                    if addr not in addresses:
                        addresses[addr] = {
                            "address": addr,
                            "total_volume": 0,
                            "transaction_count": 0,
                            "risk_levels": [],
                            "chains": set(),
                            "tokens": set(),
                        }

                    addresses[addr]["total_volume"] += tx.get("amount", 0)
                    addresses[addr]["transaction_count"] += 1
                    addresses[addr]["risk_levels"].append(tx.get("risk_level", "UNKNOWN"))
                    addresses[addr]["chains"].add(tx.get("chain", ""))
                    addresses[addr]["tokens"].add(tx.get("token", ""))

        # Convert to DataFrame
        rows = []
        for addr, data in addresses.items():
            risk_counts = {}
            for risk in data["risk_levels"]:
                risk_counts[risk] = risk_counts.get(risk, 0) + 1

            rows.append({
                "address": addr,
                "total_volume": data["total_volume"],
                "transaction_count": data["transaction_count"],
                "avg_transaction_value": data["total_volume"] / data["transaction_count"]
                if data["transaction_count"] > 0
                else 0,
                "risk_critical_count": risk_counts.get("CRITICAL", 0),
                "risk_high_count": risk_counts.get("HIGH", 0),
                "risk_medium_count": risk_counts.get("MEDIUM", 0),
                "risk_low_count": risk_counts.get("LOW", 0),
                "primary_risk": max(risk_counts.items(), key=lambda x: x[1])[0]
                if risk_counts else "UNKNOWN",
                "chains_involved": ", ".join(sorted(data["chains"])),
                "tokens_involved": ", ".join(sorted(data["tokens"])),
            })

        # Return sorted DataFrame, handling empty case
        if not rows:
            logger.warning("No addresses found in trace result")
            return pd.DataFrame(columns=[
                "address", "total_volume", "transaction_count", "avg_transaction_value",
                "risk_critical_count", "risk_high_count", "risk_medium_count", "risk_low_count",
                "primary_risk", "chains_involved", "tokens_involved"
            ])

        return pd.DataFrame(rows).sort_values("total_volume", ascending=False)