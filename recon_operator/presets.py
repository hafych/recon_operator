"""Named recon presets / ordered engagement phases.

Data-driven profiles map to existing scan_type/ports/scripts values so
operators and AI agents can follow discovery → map → safe without inventing
ad-hoc sequences. Presets never auto-exploit; they only select recon profiles.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Ordered engagement phases (playbook skeleton).
PHASE_ORDER: List[str] = ["discovery", "map", "safe"]

PRESETS: Dict[str, Dict[str, Any]] = {
    "discovery": {
        "id": "discovery",
        "phase": "PB-DISC",
        "label": "Host discovery",
        "description": "Lightweight liveness (Ping). First phase of an authorized engagement.",
        "scan_type": "Ping",
        "ports": None,
        "scripts": None,
        "discovery": None,
        "order": 1,
    },
    "map": {
        "id": "map",
        "phase": "PB-MAP",
        "label": "Service map",
        "description": "TCP connect + version detection on common ports.",
        "scan_type": "Version",
        "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443",
        "scripts": None,
        "discovery": None,
        "order": 2,
    },
    "safe": {
        "id": "safe",
        "phase": "PB-SAFE",
        "label": "Safe NSE depth",
        "description": "Version scan plus safe NSE scripts (authorized depth).",
        "scan_type": "Safe",
        "ports": None,
        "scripts": None,
        "discovery": None,
        "order": 3,
    },
    "depth": {
        "id": "depth",
        "phase": "PB-DEPTH",
        "label": "Full TCP/script pass",
        "description": "Broader TCP + default scripts when engagement allows more depth.",
        "scan_type": "Full",
        "ports": None,
        "scripts": None,
        "discovery": None,
        "order": 4,
    },
    "vuln": {
        "id": "vuln",
        "phase": "PB-VULN",
        "label": "Vuln NSE (authorized)",
        "description": "Version + vuln scripts only with explicit authorization.",
        "scan_type": "Vuln",
        "ports": None,
        "scripts": None,
        "discovery": None,
        "order": 5,
    },
    "hybrid": {
        "id": "hybrid",
        "phase": "PB-MAP",
        "label": "Hybrid discovery + version",
        "description": "Fast port discovery frontend then Nmap Version on found ports.",
        "scan_type": "Hybrid",
        "ports": None,
        "scripts": None,
        "discovery": "auto",
        "order": 2,
    },
}


def list_presets() -> List[Dict[str, Any]]:
    rows = [dict(value) for value in PRESETS.values()]
    rows.sort(key=lambda item: (item.get("order") or 99, item.get("id") or ""))
    return rows


def get_preset(preset_id: str) -> Optional[Dict[str, Any]]:
    key = str(preset_id or "").strip().lower()
    if not key:
        return None
    preset = PRESETS.get(key)
    return dict(preset) if preset else None


def apply_preset_to_payload(
    payload: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Merge preset fields into a scan payload.

    Explicit payload keys may refine a preset, but cannot replace its scan
    profile while retaining dependent preset defaults.
    Returns (merged_payload, error).
    """
    if not isinstance(payload, dict):
        return None, "Missing or invalid request body"
    data = dict(payload)
    raw = data.get("preset") or data.get("playbook") or data.get("phase")
    if raw is None or raw == "":
        return data, None
    preset = get_preset(str(raw))
    if preset is None:
        known = ", ".join(sorted(PRESETS.keys()))
        return None, f"Unknown preset {raw!r}. Known: {known}"

    explicit_scan_type = data.get("scan_type")
    if (
        explicit_scan_type not in (None, "")
        and str(explicit_scan_type).strip().lower()
        != str(preset["scan_type"]).strip().lower()
    ):
        return (
            None,
            f"Preset {preset['id']!r} requires scan_type={preset['scan_type']}; "
            "remove preset to use a different scan_type",
        )

    # Fill only when caller did not set the field (None/missing).
    if data.get("scan_type") in (None, ""):
        data["scan_type"] = preset["scan_type"]
    if data.get("ports") in (None, "") and preset.get("ports") is not None:
        data["ports"] = preset["ports"]
    if data.get("scripts") in (None, "") and preset.get("scripts") is not None:
        data["scripts"] = preset["scripts"]
    if data.get("discovery") in (None, "") and preset.get("discovery") is not None:
        data["discovery"] = preset["discovery"]
    data["preset"] = preset["id"]
    data["preset_phase"] = preset["phase"]
    return data, None


def next_phase(preset_id: str) -> Optional[str]:
    """Return the next ordered engagement phase id after preset_id, if any."""
    key = str(preset_id or "").strip().lower()
    if key not in PHASE_ORDER:
        return None
    index = PHASE_ORDER.index(key)
    if index + 1 >= len(PHASE_ORDER):
        return None
    return PHASE_ORDER[index + 1]
