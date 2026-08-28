from dataclasses import dataclass, asdict, field
import json
import subprocess
from typing import Optional, List, Dict, Any

from bitwarden_helper.keyring import KeyringManager
from bitwarden_helper.health import resolve_executable

TYPE_MAP = {
    1: "login",
    2: "note",
    3: "card",
    4: "identity",
}

@dataclass
class VaultItem:
    id: str
    name: str
    type: int
    type_name: str
    sub_title: str
    notes: Optional[str] = None
    favorite: bool = False
    login: Optional[Dict[str, Any]] = None
    card: Optional[Dict[str, Any]] = None
    identity: Optional[Dict[str, Any]] = None
    fields: List[Dict[str, Any]] = field(default_factory=list)
    search_text: str = ""

def is_fuzzy_match(pattern: str, text: str) -> bool:
    if not pattern:
        return True
    pattern = pattern.lower()
    text = text.lower()
    if pattern in text:
        return True
    
    # Subsequence match
    p_idx = 0
    p_len = len(pattern)
    for char in text:
        if char == pattern[p_idx]:
            p_idx += 1
            if p_idx == p_len:
                return True
    return False

class VaultManager:
    def __init__(self, bw_path: str = "bw", keyring_mgr: Optional[KeyringManager] = None):
        self.bw_path = resolve_executable(bw_path) or bw_path
        self.keyring_mgr = keyring_mgr or KeyringManager()

    def _get_active_session(self, session: Optional[str] = None) -> Optional[str]:
        return session or self.keyring_mgr.get_session()

    def sync(self, session: Optional[str] = None) -> bool:
        session_key = self._get_active_session(session)
        if not session_key:
            return False
        try:
            res = subprocess.run(
                [self.bw_path, "sync", "--session", session_key],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def fetch_items(self, session: Optional[str] = None) -> List[VaultItem]:
        session_key = self._get_active_session(session)
        if not session_key:
            return []
        try:
            res = subprocess.run(
                [self.bw_path, "list", "items", "--session", session_key],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw_items = json.loads(res.stdout)
                return self.parse_raw_items(raw_items)
            return []
        except Exception:
            return []

    def parse_raw_items(self, raw_items: List[Dict[str, Any]]) -> List[VaultItem]:
        parsed_items: List[VaultItem] = []
        for raw in raw_items:
            item_type = raw.get("type", 1)
            type_name = TYPE_MAP.get(item_type, "login")
            name = raw.get("name", "Untitled")
            notes = raw.get("notes") or ""
            favorite = bool(raw.get("favorite", False))
            fields = raw.get("fields") or []
            
            sub_title, search_tokens = self._extract_metadata(item_type, raw, name, notes, fields)
            search_text = " ".join(t for t in search_tokens if t)

            parsed_items.append(
                VaultItem(
                    id=raw.get("id", ""),
                    name=name,
                    type=item_type,
                    type_name=type_name,
                    sub_title=sub_title,
                    notes=notes,
                    favorite=favorite,
                    login=raw.get("login"),
                    card=raw.get("card"),
                    identity=raw.get("identity"),
                    fields=fields,
                    search_text=search_text,
                )
            )
        return parsed_items

    def _extract_metadata(
        self,
        item_type: int,
        raw: Dict[str, Any],
        name: str,
        notes: str,
        fields: List[Dict[str, Any]],
    ) -> tuple[str, List[str]]:
        search_tokens = [name.lower(), notes.lower()]
        sub_title = ""

        if item_type == 1 and raw.get("login"):  # Login
            login_data = raw["login"]
            username = login_data.get("username") or ""
            sub_title = username
            search_tokens.append(username.lower())
            for u in login_data.get("uris") or []:
                uri_val = u.get("uri") or ""
                search_tokens.append(uri_val.lower())
        elif item_type == 3 and raw.get("card"):  # Card
            card_data = raw["card"]
            num = card_data.get("number") or ""
            brand = card_data.get("brand") or "Card"
            last4 = num[-4:] if len(num) >= 4 else num
            sub_title = f"{brand} •••• {last4}" if last4 else brand
            search_tokens.extend([brand.lower(), num])
        elif item_type == 4 and raw.get("identity"):  # Identity
            identity_data = raw["identity"]
            email = identity_data.get("email") or ""
            fname = identity_data.get("firstName") or ""
            lname = identity_data.get("lastName") or ""
            full_name = f"{fname} {lname}".strip()
            sub_title = email or full_name or "Identity"
            search_tokens.extend([email.lower(), fname.lower(), lname.lower(), full_name.lower()])
        elif item_type == 2:  # Note
            sub_title = "Secure Note"

        for f in fields:
            f_name = f.get("name") or ""
            f_val = str(f.get("value") or "")
            search_tokens.extend([f_name.lower(), f_val.lower()])

        return sub_title, search_tokens

    def search(
        self,
        items: List[VaultItem],
        query: str = "",
        category: Optional[str] = None,
    ) -> List[VaultItem]:
        q = (query or "").strip().lower()
        cat = (category or "").strip().lower()
        if cat in ("all", ""):
            cat = None

        filtered: List[VaultItem] = []
        for item in items:
            if cat and item.type_name != cat:
                continue

            if not q:
                filtered.append(item)
                continue

            # Query matching: check if all query tokens fuzzy match the item's search text
            query_words = q.split()
            if all(is_fuzzy_match(word, item.search_text) for word in query_words):
                filtered.append(item)

        def score(item: VaultItem) -> int:
            pts = 0
            if item.favorite:
                pts += 100
            name_lower = item.name.lower()
            if q:
                if name_lower == q:
                    pts += 1000
                elif name_lower.startswith(q):
                    pts += 500
                elif q in name_lower:
                    pts += 200
                elif is_fuzzy_match(q, name_lower):
                    pts += 50
            return pts

        return sorted(filtered, key=score, reverse=True)
