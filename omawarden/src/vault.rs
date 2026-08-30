use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::BitwardenApiClient;
use crate::keyring::KeyringManager;
use crate::storage::StorageManager;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshMetadata {
    pub is_ssh_key: bool,
    pub key_type: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: i64,
    pub type_name: String,
    pub sub_title: String,
    pub notes: Option<String>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<SshMetadata>,
    #[serde(default)]
    pub fields: Vec<Value>,
    #[serde(default)]
    pub attachments: Vec<Value>,
    pub search_text: String,
}

pub fn is_fuzzy_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let p_lower = pattern.to_lowercase();
    let t_lower = text.to_lowercase();
    if t_lower.contains(&p_lower) {
        return true;
    }

    let p_chars: Vec<char> = p_lower.chars().collect();
    let mut p_idx = 0;
    for c in t_lower.chars() {
        if c == p_chars[p_idx] {
            p_idx += 1;
            if p_idx == p_chars.len() {
                return true;
            }
        }
    }
    false
}

pub fn detect_ssh_key_metadata(raw: &Value) -> Option<SshMetadata> {
    let notes = raw.get("notes").and_then(|v| v.as_str()).unwrap_or("");
    let fields = raw.get("fields").and_then(|v| v.as_array());

    let mut private_key: Option<String> = None;
    let mut public_key: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut key_type = "SSH".to_string();

    let priv_re = Regex::new(
        r"(-----BEGIN (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----)",
    )
    .unwrap();
    if let Some(caps) = priv_re.captures(notes) {
        let matched = caps.get(1).unwrap().as_str().trim().to_string();
        if matched.contains("BEGIN OPENSSH PRIVATE KEY") {
            key_type = if matched.contains("ssh-ed25519") {
                "ED25519".to_string()
            } else {
                "OPENSSH".to_string()
            };
        } else if matched.contains("BEGIN RSA PRIVATE KEY") {
            key_type = "RSA".to_string();
        } else if matched.contains("BEGIN EC PRIVATE KEY") {
            key_type = "ECDSA".to_string();
        } else if matched.contains("BEGIN DSA PRIVATE KEY") {
            key_type = "DSA".to_string();
        } else if matched.contains("BEGIN PRIVATE KEY") {
            key_type = "PKCS8".to_string();
        }
        private_key = Some(matched);
    }

    let pub_re = Regex::new(
        r"((?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-[a-z0-9]+)\s+[A-Za-z0-9+/=.]+(?:\s+.*)?)",
    )
    .unwrap();
    if let Some(caps) = pub_re.captures(notes) {
        let matched = caps.get(1).unwrap().as_str().trim().to_string();
        if matched.contains("ssh-ed25519") {
            key_type = "ED25519".to_string();
        } else if matched.contains("ssh-rsa") {
            key_type = "RSA".to_string();
        } else if matched.contains("ecdsa-sha2") {
            key_type = "ECDSA".to_string();
        } else if matched.contains("ssh-dss") {
            key_type = "DSA".to_string();
        }
        public_key = Some(matched);
    }

    if let Some(fields_arr) = fields {
        for f in fields_arr {
            let fname = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase()
                .replace('-', "_")
                .replace(' ', "_");
            let fval = f
                .get("value")
                .map(|v| match v {
                    Value::String(s) => s.trim().to_string(),
                    other => other.to_string(),
                })
                .unwrap_or_default();

            if matches!(
                fname.as_str(),
                "private_key" | "privatekey" | "ssh_private_key" | "id_rsa" | "id_ed25519"
            ) || fval.contains("-----BEGIN ")
            {
                if fval.contains("-----BEGIN ") {
                    if fval.contains("RSA") {
                        key_type = "RSA".to_string();
                    } else if fval.contains("OPENSSH") {
                        key_type = if fval.contains("ed25519") {
                            "ED25519".to_string()
                        } else {
                            "OPENSSH".to_string()
                        };
                    } else if fval.contains("EC") {
                        key_type = "ECDSA".to_string();
                    } else if fval.contains("DSA") {
                        key_type = "DSA".to_string();
                    } else if fval.contains("PRIVATE KEY") {
                        key_type = "PKCS8".to_string();
                    }
                    private_key = Some(fval);
                } else if private_key.is_none() {
                    private_key = Some(fval);
                }
            } else if matches!(
                fname.as_str(),
                "public_key" | "publickey" | "ssh_public_key" | "ssh_key"
            ) || fval.starts_with("ssh-rsa ")
                || fval.starts_with("ssh-ed25519 ")
                || fval.starts_with("ecdsa-sha2-")
            {
                if fval.contains("ssh-ed25519") {
                    key_type = "ED25519".to_string();
                } else if fval.contains("ssh-rsa") {
                    key_type = "RSA".to_string();
                } else if fval.contains("ecdsa") {
                    key_type = "ECDSA".to_string();
                }
                public_key = Some(fval);
            } else if matches!(
                fname.as_str(),
                "passphrase" | "pass_phrase" | "key_passphrase" | "ssh_passphrase"
            ) {
                passphrase = Some(fval);
            }
        }
    }

    if private_key.is_some() || public_key.is_some() {
        Some(SshMetadata {
            is_ssh_key: true,
            key_type,
            private_key,
            public_key,
            passphrase,
        })
    } else {
        None
    }
}

pub struct VaultManager {
    pub server_url: String,
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
}

impl VaultManager {
    pub fn new(
        server_url: &str,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        Self {
            server_url: server_url.to_string(),
            storage_mgr: storage_mgr.unwrap_or_default(),
            keyring_mgr: keyring_mgr.unwrap_or_default(),
        }
    }

    pub fn sync(&self, _session: Option<&str>) -> bool {
        let storage = self.storage_mgr.load();
        let token = match storage.access_token.as_ref() {
            Some(t) if !t.is_empty() => t,
            _ => return false,
        };

        let client = BitwardenApiClient::new(&self.server_url);
        match client.sync_vault(token) {
            Ok(sync_resp) => {
                let mut updated = storage;
                updated.ciphers = sync_resp.ciphers;
                updated.last_sync = Some(chrono::Utc::now().to_rfc3339());
                self.storage_mgr.save(&updated).is_ok()
            }
            Err(_) => false,
        }
    }

    pub fn fetch_items(&self, _session: Option<&str>) -> Vec<VaultItem> {
        let storage = self.storage_mgr.load();
        self.parse_raw_items(&storage.ciphers)
    }

    pub fn parse_raw_items(&self, raw_items: &[Value]) -> Vec<VaultItem> {
        let mut parsed: Vec<VaultItem> = Vec::new();

        for raw in raw_items {
            let item_type = raw.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
            let name = raw
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled")
                .to_string();
            let notes = raw
                .get("notes")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let favorite = raw
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = raw
                .get("fields")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let attachments = raw
                .get("attachments")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let id = raw
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(ssh_meta) = detect_ssh_key_metadata(raw) {
                let type_name = "ssh_key".to_string();
                let sub_title = format!("SSH Key ({})", ssh_meta.key_type);
                let mut search_tokens = vec![
                    name.to_lowercase(),
                    "ssh".to_string(),
                    "ssh key".to_string(),
                    ssh_meta.key_type.to_lowercase(),
                ];
                if let Some(ref pubk) = ssh_meta.public_key {
                    search_tokens.push(pubk.to_lowercase());
                }
                for att in &attachments {
                    if let Some(fname) = att.get("fileName").and_then(|v| v.as_str()) {
                        search_tokens.push(fname.to_lowercase());
                    }
                }
                let search_text = search_tokens
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");

                parsed.push(VaultItem {
                    id,
                    name,
                    item_type,
                    type_name,
                    sub_title,
                    notes,
                    favorite,
                    login: None,
                    card: None,
                    identity: None,
                    ssh_key: Some(ssh_meta),
                    fields,
                    attachments,
                    search_text,
                });
                continue;
            }

            let type_name = match item_type {
                1 => "login",
                2 => "note",
                3 => "card",
                4 => "identity",
                5 => "ssh_key",
                _ => "login",
            }
            .to_string();

            let (sub_title, mut search_tokens) = self.extract_metadata(
                item_type,
                raw,
                &name,
                notes.as_deref().unwrap_or(""),
                &fields,
            );

            for att in &attachments {
                if let Some(fname) = att.get("fileName").and_then(|v| v.as_str()) {
                    search_tokens.push(fname.to_lowercase());
                }
            }
            let search_text = search_tokens
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            parsed.push(VaultItem {
                id,
                name,
                item_type,
                type_name,
                sub_title,
                notes,
                favorite,
                login: raw.get("login").cloned(),
                card: raw.get("card").cloned(),
                identity: raw.get("identity").cloned(),
                ssh_key: None,
                fields,
                attachments,
                search_text,
            });
        }

        parsed
    }

    fn extract_metadata(
        &self,
        item_type: i64,
        raw: &Value,
        name: &str,
        notes: &str,
        fields: &[Value],
    ) -> (String, Vec<String>) {
        let mut search_tokens = vec![name.to_lowercase(), notes.to_lowercase()];
        let mut sub_title = String::new();

        match item_type {
            1 => {
                if let Some(login_data) = raw.get("login") {
                    let username = login_data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    sub_title = username.to_string();
                    search_tokens.push(username.to_lowercase());
                    if let Some(uris) = login_data.get("uris").and_then(|v| v.as_array()) {
                        for u in uris {
                            if let Some(uri_val) = u.get("uri").and_then(|v| v.as_str()) {
                                search_tokens.push(uri_val.to_lowercase());
                            }
                        }
                    }
                }
            }
            3 => {
                if let Some(card_data) = raw.get("card") {
                    let num = card_data
                        .get("number")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let brand = card_data
                        .get("brand")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Card");
                    let last4 = if num.len() >= 4 {
                        &num[num.len() - 4..]
                    } else {
                        num
                    };
                    sub_title = if !last4.is_empty() {
                        format!("{} •••• {}", brand, last4)
                    } else {
                        brand.to_string()
                    };
                    search_tokens.push(brand.to_lowercase());
                    search_tokens.push(num.to_string());
                }
            }
            4 => {
                if let Some(id_data) = raw.get("identity") {
                    let email = id_data
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let fname = id_data
                        .get("firstName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let lname = id_data
                        .get("lastName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full_name = format!("{} {}", fname, lname).trim().to_string();
                    sub_title = if !email.is_empty() {
                        email.to_string()
                    } else if !full_name.is_empty() {
                        full_name.clone()
                    } else {
                        "Identity".to_string()
                    };
                    search_tokens.push(email.to_lowercase());
                    search_tokens.push(fname.to_lowercase());
                    search_tokens.push(lname.to_lowercase());
                    search_tokens.push(full_name.to_lowercase());
                }
            }
            2 => {
                sub_title = "Secure Note".to_string();
            }
            _ => {}
        }

        for f in fields {
            let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let fval = f
                .get("value")
                .map(|v| match v {
                    Value::String(s) => s.as_str(),
                    _ => "",
                })
                .unwrap_or("");
            search_tokens.push(fname.to_lowercase());
            search_tokens.push(fval.to_lowercase());
        }

        (sub_title, search_tokens)
    }

    pub fn search(
        &self,
        items: &[VaultItem],
        query: &str,
        category: Option<&str>,
    ) -> Vec<VaultItem> {
        let q = query.trim().to_lowercase();
        let cat = category.unwrap_or("").trim().to_lowercase();
        let cat_filter = if cat.is_empty() || cat == "all" {
            None
        } else {
            Some(cat)
        };

        let mut scored_items: Vec<(&VaultItem, i64)> = Vec::new();

        for item in items {
            if let Some(ref c) = cat_filter {
                if &item.type_name != c {
                    continue;
                }
            }

            if q.is_empty() {
                scored_items.push((item, if item.favorite { 100 } else { 0 }));
                continue;
            }

            let query_words: Vec<&str> = q.split_whitespace().collect();
            let mut total_score: i64 = if item.favorite { 100 } else { 0 };
            let name_lower = item.name.to_lowercase();
            let sub_lower = item.sub_title.to_lowercase();
            let search_lower = item.search_text.to_lowercase();
            let notes_lower = item.notes.as_deref().unwrap_or("").to_lowercase();

            let mut all_words_matched = true;
            for w in query_words {
                let mut word_matched = false;
                if name_lower == w {
                    total_score += 2000;
                    word_matched = true;
                } else if name_lower.starts_with(w) {
                    total_score += 1000;
                    word_matched = true;
                } else if name_lower.contains(w) {
                    total_score += 500;
                    word_matched = true;
                } else if sub_lower.starts_with(w) {
                    total_score += 400;
                    word_matched = true;
                } else if sub_lower.contains(w) {
                    total_score += 300;
                    word_matched = true;
                } else if search_lower.contains(w) || notes_lower.contains(w) {
                    total_score += 100;
                    word_matched = true;
                } else if is_fuzzy_match(w, &name_lower) {
                    total_score += 80;
                    word_matched = true;
                }

                if !word_matched {
                    all_words_matched = false;
                    break;
                }
            }

            if all_words_matched {
                scored_items.push((item, total_score));
            }
        }

        scored_items.sort_by(|a, b| b.1.cmp(&a.1));
        scored_items.into_iter().map(|(item, _)| item.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fuzzy_match() {
        assert!(is_fuzzy_match("", "anything"));
        assert!(is_fuzzy_match("git", "github"));
        assert!(is_fuzzy_match("gh", "github"));
        assert!(is_fuzzy_match("gthb", "github"));
        assert!(!is_fuzzy_match("xyz", "github"));
    }

    #[test]
    fn test_ssh_heuristics_rsa_in_notes() {
        let raw = json!({
            "name": "Server Key",
            "notes": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nssh-rsa AAAAB3NzaC1yc2E... user@host"
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "RSA");
        assert!(meta.private_key.unwrap().contains("BEGIN RSA PRIVATE KEY"));
        assert!(meta.public_key.unwrap().starts_with("ssh-rsa"));
    }

    #[test]
    fn test_ssh_heuristics_ed25519_openssh() {
        let raw = json!({
            "name": "Dev Ed25519 Key",
            "notes": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...ssh-ed25519\n-----END OPENSSH PRIVATE KEY-----\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "ED25519");
        assert!(meta.private_key.is_some());
        assert_eq!(meta.public_key.unwrap(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host");
    }

    #[test]
    fn test_ssh_heuristics_custom_fields() {
        let raw = json!({
            "name": "Custom SSH Item",
            "notes": "Some regular notes",
            "fields": [
                { "name": "private_key", "value": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----" },
                { "name": "public_key", "value": "ecdsa-sha2-nistp256 AAAAE2VjZHNh... user@host" },
                { "name": "passphrase", "value": "secret_passphrase_123" }
            ]
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "ECDSA");
        assert!(meta.private_key.unwrap().contains("BEGIN EC PRIVATE KEY"));
        assert!(meta.public_key.unwrap().starts_with("ecdsa-sha2-nistp256"));
        assert_eq!(meta.passphrase.unwrap(), "secret_passphrase_123");
    }

    #[test]
    fn test_parse_and_search_categories() {
        let raw_items = vec![
            json!({
                "id": "1",
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "octocat",
                    "uris": [{ "uri": "https://github.com" }]
                },
                "favorite": true
            }),
            json!({
                "id": "2",
                "name": "Bank Card",
                "type": 3,
                "card": {
                    "brand": "Visa",
                    "number": "4111222233334444"
                }
            }),
            json!({
                "id": "3",
                "name": "Server Access",
                "type": 2,
                "notes": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
            })
        ];

        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let items = vault_mgr.parse_raw_items(&raw_items);
        assert_eq!(items.len(), 3);

        assert_eq!(items[0].type_name, "login");
        assert_eq!(items[0].sub_title, "octocat");

        assert_eq!(items[1].type_name, "card");
        assert_eq!(items[1].sub_title, "Visa •••• 4444");

        assert_eq!(items[2].type_name, "ssh_key");
        assert!(items[2].sub_title.contains("SSH Key"));

        let search_gh = vault_mgr.search(&items, "github", None);
        assert_eq!(search_gh.len(), 1);
        assert_eq!(search_gh[0].id, "1");

        let search_card = vault_mgr.search(&items, "", Some("card"));
        assert_eq!(search_card.len(), 1);
        assert_eq!(search_card[0].id, "2");

        let search_ssh = vault_mgr.search(&items, "", Some("ssh_key"));
        assert_eq!(search_ssh.len(), 1);
        assert_eq!(search_ssh[0].id, "3");
    }
}
