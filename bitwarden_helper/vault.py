from dataclasses import dataclass, asdict, field
import json
import os
import re
import subprocess
from typing import Optional, List, Dict, Any

from bitwarden_helper.keyring import KeyringManager
from bitwarden_helper.health import resolve_executable

TYPE_MAP = {
    1: "login",
    2: "note",
    3: "card",
    4: "identity",
    5: "ssh_key",
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
    ssh_key: Optional[Dict[str, Any]] = None
    fields: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
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

def detect_ssh_key_metadata(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    notes = raw.get("notes") or ""
    fields = raw.get("fields") or []
    
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    passphrase: Optional[str] = None
    key_type: str = "SSH"

    # Extract private key block from notes if present
    priv_block_match = re.search(r"(-----BEGIN (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----)", notes)
    if priv_block_match:
        private_key = priv_block_match.group(1).strip()
        if "BEGIN OPENSSH PRIVATE KEY" in private_key:
            key_type = "ED25519" if "ssh-ed25519" in private_key else "OPENSSH"
        elif "BEGIN RSA PRIVATE KEY" in private_key:
            key_type = "RSA"
        elif "BEGIN EC PRIVATE KEY" in private_key:
            key_type = "ECDSA"
        elif "BEGIN DSA PRIVATE KEY" in private_key:
            key_type = "DSA"
        elif "BEGIN PRIVATE KEY" in private_key:
            key_type = "PKCS8"

    # Extract public key line from notes
    pub_match = re.search(r"((?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-[a-z0-9]+)\s+[A-Za-z0-9+/=.]+(?:\s+.*)?)", notes)
    if pub_match:
        public_key = pub_match.group(1).strip()
        if "ssh-ed25519" in public_key:
            key_type = "ED25519"
        elif "ssh-rsa" in public_key:
            key_type = "RSA"
        elif "ecdsa-sha2" in public_key:
            key_type = "ECDSA"
        elif "ssh-dss" in public_key:
            key_type = "DSA"

    # Search in custom fields
    for f in fields:
        fname = (f.get("name") or "").strip().lower().replace("-", "_").replace(" ", "_")
        fval = str(f.get("value") or "").strip()
        
        if fname in ("private_key", "privatekey", "ssh_private_key", "id_rsa", "id_ed25519") or "-----BEGIN " in fval:
            if "-----BEGIN " in fval:
                private_key = fval
                if "RSA" in fval:
                    key_type = "RSA"
                elif "OPENSSH" in fval:
                    key_type = "OPENSSH" if "ed25519" not in fval else "ED25519"
                elif "EC" in fval:
                    key_type = "ECDSA"
                elif "DSA" in fval:
                    key_type = "DSA"
                elif "PRIVATE KEY" in fval:
                    key_type = "PKCS8"
            elif not private_key:
                private_key = fval
        elif fname in ("public_key", "publickey", "ssh_public_key", "ssh_key") or fval.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-")):
            public_key = fval
            if "ssh-ed25519" in fval:
                key_type = "ED25519"
            elif "ssh-rsa" in fval:
                key_type = "RSA"
            elif "ecdsa" in fval:
                key_type = "ECDSA"
        elif fname in ("passphrase", "pass_phrase", "key_passphrase", "ssh_passphrase"):
            passphrase = fval

    if private_key or public_key:
        return {
            "is_ssh_key": True,
            "key_type": key_type,
            "private_key": private_key,
            "public_key": public_key,
            "passphrase": passphrase,
        }
    return None

class VaultManager:
    def __init__(self, bw_path: str = "bw", keyring_mgr: Optional[KeyringManager] = None, max_output_bytes: int = 10 * 1024 * 1024):
        self.bw_path = resolve_executable(bw_path) or bw_path
        self.keyring_mgr = keyring_mgr or KeyringManager()
        self.max_output_bytes = max_output_bytes

    def _get_active_session(self, session: Optional[str] = None) -> Optional[str]:
        return session or self.keyring_mgr.get_session()

    def _safe_env(self, session_key: str) -> Dict[str, str]:
        env = os.environ.copy()
        env["BW_SESSION"] = session_key
        return env

    def sync(self, session: Optional[str] = None) -> bool:
        session_key = self._get_active_session(session)
        if not session_key:
            return False
        try:
            # Pass session key strictly via isolated child env, never in argv
            res = subprocess.run(
                [self.bw_path, "sync"],
                capture_output=True,
                text=True,
                env=self._safe_env(session_key),
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
            # Pass session key strictly via isolated child env, never in argv
            res = subprocess.run(
                [self.bw_path, "list", "items"],
                capture_output=True,
                text=True,
                env=self._safe_env(session_key),
                timeout=25,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                # Enforce bounded stream parsing before json.loads
                raw_text = res.stdout[:self.max_output_bytes]
                raw_items = json.loads(raw_text)
                return self.parse_raw_items(raw_items)
            return []
        except Exception:
            return []

    def parse_raw_items(self, raw_items: List[Dict[str, Any]]) -> List[VaultItem]:
        parsed_items: List[VaultItem] = []
        for raw in raw_items:
            item_type = raw.get("type", 1)
            name = raw.get("name", "Untitled")
            notes = raw.get("notes") or ""
            favorite = bool(raw.get("favorite", False))
            fields = raw.get("fields") or []
            attachments = raw.get("attachments") or []

            # Check for SSH Key heuristics
            ssh_meta = detect_ssh_key_metadata(raw)
            if ssh_meta:
                type_name = "ssh_key"
                sub_title = f"SSH Key ({ssh_meta['key_type']})"
                search_tokens = [name.lower(), "ssh", "ssh key", ssh_meta["key_type"].lower()]
                if ssh_meta["public_key"]:
                    search_tokens.append(ssh_meta["public_key"].lower())
                for att in attachments:
                    if att.get("fileName"):
                        search_tokens.append(att["fileName"].lower())
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
                        ssh_key=ssh_meta,
                        fields=fields,
                        attachments=attachments,
                        search_text=search_text,
                    )
                )
                continue

            type_name = TYPE_MAP.get(item_type, "login")
            sub_title, search_tokens = self._extract_metadata(item_type, raw, name, notes, fields)
            for att in attachments:
                if att.get("fileName"):
                    search_tokens.append(att["fileName"].lower())
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
                    attachments=attachments,
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

        def match_and_score(item: VaultItem) -> tuple[bool, int]:
            if not q:
                return True, (100 if item.favorite else 0)


            query_words = q.split()
            total_score = 100 if item.favorite else 0
            name_lower = item.name.lower()
            sub_lower = (item.sub_title or "").lower()
            search_lower = (item.search_text or "").lower()
            notes_lower = (item.notes or "").lower()

            for w in query_words:
                word_matched = False
                if name_lower == w:
                    total_score += 2000
                    word_matched = True
                elif name_lower.startswith(w):
                    total_score += 1000
                    word_matched = True
                elif w in name_lower:
                    total_score += 500
                    word_matched = True
                elif sub_lower.startswith(w):
                    total_score += 400
                    word_matched = True
                elif w in sub_lower:
                    total_score += 300
                    word_matched = True
                elif w in search_lower or w in notes_lower:
                    total_score += 100
                    word_matched = True
                elif is_fuzzy_match(w, name_lower):
                    total_score += 80
                    word_matched = True

                if not word_matched:
                    return False, 0

            return True, total_score

        scored_items: List[tuple[VaultItem, int]] = []
        for item in items:
            if cat and item.type_name != cat:
                continue
            matched, pts = match_and_score(item)
            if matched:
                scored_items.append((item, pts))

        scored_items.sort(key=lambda pair: pair[1], reverse=True)
        return [pair[0] for pair in scored_items]

