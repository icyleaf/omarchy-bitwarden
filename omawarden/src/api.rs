use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

use crate::crypto::{
    derive_master_key, derive_master_password_hash, EncString, KdfType, SymmetricCryptoKey,
};
use crate::vault::{detect_ssh_key_metadata, VaultItem};

#[derive(Debug, Clone)]
pub enum ApiError {
    Http(String),
    Json(String),
    AuthFailed(String),
    TwoFactorRequired { providers: Vec<i32> },
    Crypto(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Http(s) => write!(f, "Network HTTP error: {}", s),
            ApiError::Json(s) => write!(f, "JSON decode error: {}", s),
            ApiError::AuthFailed(s) => write!(f, "API authentication failed: {}", s),
            ApiError::TwoFactorRequired { .. } => write!(f, "Two-factor authentication required"),
            ApiError::Crypto(s) => write!(f, "Cryptographic error: {}", s),
        }
    }
}
impl std::error::Error for ApiError {}

#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponse {
    #[serde(alias = "kdf", alias = "Kdf")]
    pub kdf: Option<u32>,
    #[serde(alias = "kdfIterations", alias = "KdfIterations", alias = "iterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(alias = "kdfMemory", alias = "KdfMemory", alias = "memory")]
    pub kdf_memory: Option<u32>,
    #[serde(
        alias = "kdfParallelism",
        alias = "KdfParallelism",
        alias = "parallelism"
    )]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    #[serde(rename = "token_type", alias = "tokenType")]
    pub token_type: Option<String>,
    #[serde(alias = "Key", alias = "key", alias = "userKey", alias = "UserKey")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "private_key", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Kdf", alias = "kdf")]
    pub kdf: Option<u32>,
    #[serde(alias = "KdfIterations", alias = "kdfIterations", alias = "iterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(alias = "KdfMemory", alias = "kdfMemory", alias = "memory")]
    pub kdf_memory: Option<u32>,
    #[serde(
        alias = "KdfParallelism",
        alias = "kdfParallelism",
        alias = "parallelism"
    )]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    pub profile: Option<Value>,
    #[serde(default)]
    pub folders: Vec<Value>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub ciphers: Vec<Value>,
}

pub struct BitwardenApiClient {
    pub server_url: String,
    client: Client,
}

impl BitwardenApiClient {
    pub fn new(server_url: &str) -> Self {
        let base = server_url.trim_end_matches('/');
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            server_url: base.to_string(),
            client,
        }
    }

    pub fn prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError> {
        let url = format!("{}/api/accounts/prelogin", self.server_url);
        let resp = self
            .client
            .post(&url)
            .json(&json!({ "email": email.trim().to_lowercase() }))
            .send()
            .map_err(|e| ApiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ApiError::Http(format!(
                "Prelogin returned status {}",
                resp.status()
            )));
        }

        resp.json::<PreloginResponse>()
            .map_err(|e| ApiError::Json(e.to_string()))
    }

    pub fn login_password(
        &self,
        email: &str,
        password: &str,
        two_factor_token: Option<&str>,
    ) -> Result<(TokenResponse, SymmetricCryptoKey), ApiError> {
        let prelogin = self.prelogin(email)?;
        let kdf_type = KdfType::from(prelogin.kdf.unwrap_or(0));
        let iterations = prelogin.kdf_iterations.unwrap_or(600_000);

        let master_key = derive_master_key(
            email,
            password,
            kdf_type,
            iterations,
            prelogin.kdf_memory,
            prelogin.kdf_parallelism,
        )
        .map_err(|e| ApiError::Crypto(e.to_string()))?;

        let password_hash = derive_master_password_hash(&master_key, password);

        // Connect token endpoint (supports both Bitwarden official cloud and Vaultwarden)
        let identity_url = format!("{}/identity/connect/token", self.server_url);
        let fallback_url = format!("{}/connect/token", self.server_url);

        let mut form_params: HashMap<&str, String> = HashMap::new();
        form_params.insert("grant_type", "password".to_string());
        form_params.insert("username", email.trim().to_lowercase());
        form_params.insert("password", password_hash);
        form_params.insert("scope", "api offline_access".to_string());
        form_params.insert("client_id", "web".to_string());
        form_params.insert("deviceType", "linux".to_string());
        form_params.insert("deviceIdentifier", "omarchy-bitwarden".to_string());
        form_params.insert("deviceName", "Omarchy Bitwarden".to_string());

        if let Some(code) = two_factor_token {
            form_params.insert("twoFactorToken", code.trim().to_string());
            form_params.insert("twoFactorProvider", "0".to_string()); // Authenticator
            form_params.insert("twoFactorRemember", "1".to_string());
        }

        let mut resp = self.client.post(&identity_url).form(&form_params).send();
        if let Ok(ref r) = resp {
            if r.status() == reqwest::StatusCode::NOT_FOUND {
                resp = self.client.post(&fallback_url).form(&form_params).send();
            }
        }

        let resp = resp.map_err(|e| ApiError::Http(e.to_string()))?;
        let status = resp.status();
        let body_text = resp.text().map_err(|e| ApiError::Http(e.to_string()))?;

        if status.is_success() {
            let mut token_resp = serde_json::from_str::<TokenResponse>(&body_text)
                .map_err(|e| ApiError::Json(e.to_string()))?;

            if token_resp.kdf.is_none() {
                token_resp.kdf = prelogin.kdf;
            }
            if token_resp.kdf_iterations.is_none() {
                token_resp.kdf_iterations = prelogin.kdf_iterations;
            }
            if token_resp.kdf_memory.is_none() {
                token_resp.kdf_memory = prelogin.kdf_memory;
            }
            if token_resp.kdf_parallelism.is_none() {
                token_resp.kdf_parallelism = prelogin.kdf_parallelism;
            }

            // Decrypt User Key
            let enc_user_key = token_resp.key.as_ref().ok_or_else(|| {
                ApiError::Crypto("User key missing in login response".to_string())
            })?;
            let parsed_enc_key =
                EncString::parse(enc_user_key).map_err(|e| ApiError::Crypto(e.to_string()))?;

            let decrypted_raw_user_key =
                SymmetricCryptoKey::decrypt_with_master_key(&parsed_enc_key, &master_key)
                    .map_err(|e| ApiError::Crypto(format!("{:?}", e)))?;

            let user_key = SymmetricCryptoKey::from_raw_bytes(&decrypted_raw_user_key)
                .map_err(|e| ApiError::Crypto(format!("{:?}", e)))?;

            Ok((token_resp, user_key))
        } else {
            if let Ok(err_json) = serde_json::from_str::<Value>(&body_text) {
                if let Some(err_desc) = err_json.get("error_description").and_then(|v| v.as_str()) {
                    if err_desc.contains("TwoFactor") || err_desc.contains("Two-factor") {
                        return Err(ApiError::TwoFactorRequired { providers: vec![0] });
                    }
                    return Err(ApiError::AuthFailed(err_desc.to_string()));
                }
                if let Some(err_msg) = err_json.get("Message").and_then(|v| v.as_str()) {
                    return Err(ApiError::AuthFailed(err_msg.to_string()));
                }
            }
            Err(ApiError::AuthFailed(format!("HTTP {}", status)))
        }
    }

    pub fn login_apikey(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, ApiError> {
        let identity_url = format!("{}/identity/connect/token", self.server_url);
        let fallback_url = format!("{}/connect/token", self.server_url);

        let mut form_params: HashMap<&str, String> = HashMap::new();
        form_params.insert("grant_type", "client_credentials".to_string());
        form_params.insert("client_id", client_id.trim().to_string());
        form_params.insert("client_secret", client_secret.trim().to_string());
        form_params.insert("scope", "api".to_string());
        form_params.insert("deviceType", "linux".to_string());
        form_params.insert("deviceIdentifier", "omarchy-bitwarden".to_string());
        form_params.insert("deviceName", "Omarchy Bitwarden".to_string());

        let mut resp = self.client.post(&identity_url).form(&form_params).send();
        if let Ok(ref r) = resp {
            if r.status() == reqwest::StatusCode::NOT_FOUND {
                resp = self.client.post(&fallback_url).form(&form_params).send();
            }
        }

        let resp = resp.map_err(|e| ApiError::Http(e.to_string()))?;
        let status = resp.status();
        let body_text = resp.text().map_err(|e| ApiError::Http(e.to_string()))?;

        if status.is_success() {
            serde_json::from_str::<TokenResponse>(&body_text)
                .map_err(|e| ApiError::Json(e.to_string()))
        } else {
            if let Ok(err_json) = serde_json::from_str::<Value>(&body_text) {
                if let Some(err_desc) = err_json.get("error_description").and_then(|v| v.as_str()) {
                    return Err(ApiError::AuthFailed(err_desc.to_string()));
                }
                if let Some(err_msg) = err_json.get("Message").and_then(|v| v.as_str()) {
                    return Err(ApiError::AuthFailed(err_msg.to_string()));
                }
            }
            Err(ApiError::AuthFailed(format!("HTTP {}", status)))
        }
    }

    pub fn sync_vault(&self, access_token: &str) -> Result<SyncResponse, ApiError> {
        let url = format!("{}/api/sync", self.server_url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .map_err(|e| ApiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ApiError::Http(format!(
                "Sync returned status {}",
                resp.status()
            )));
        }

        resp.json::<SyncResponse>()
            .map_err(|e| ApiError::Json(e.to_string()))
    }
}

pub fn decrypt_cipher_string(
    enc_str_opt: Option<&str>,
    key: &SymmetricCryptoKey,
) -> Option<String> {
    let s = enc_str_opt?;
    if s.is_empty() {
        return Some(String::new());
    }
    match EncString::parse(s) {
        Ok(parsed) => parsed.decrypt_string(key).ok(),
        Err(_) => None,
    }
}

pub fn decrypt_sync_ciphers(ciphers: &[Value], user_key: &SymmetricCryptoKey) -> Vec<VaultItem> {
    let mut items: Vec<VaultItem> = Vec::new();

    for c in ciphers {
        let id = c
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let item_type = c.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
        let favorite = c.get("favorite").and_then(|v| v.as_bool()).unwrap_or(false);

        // Determine item key: if cipher has an encrypted key, decrypt it using user_key
        let mut cipher_key = user_key.clone();
        if let Some(enc_key_str) = c.get("key").and_then(|v| v.as_str()) {
            if let Ok(parsed_k) = EncString::parse(enc_key_str) {
                if let Ok(raw_k) = parsed_k.decrypt(user_key) {
                    if let Ok(k) = SymmetricCryptoKey::from_raw_bytes(&raw_k) {
                        cipher_key = k;
                    }
                }
            }
        }

        let name = decrypt_cipher_string(c.get("name").and_then(|v| v.as_str()), &cipher_key)
            .unwrap_or_else(|| "Untitled".to_string());
        let notes = decrypt_cipher_string(c.get("notes").and_then(|v| v.as_str()), &cipher_key);

        // Decrypt login details if present
        let mut login_val: Option<Value> = None;
        if let Some(login_obj) = c.get("login") {
            let user = decrypt_cipher_string(
                login_obj.get("username").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let pwd = decrypt_cipher_string(
                login_obj.get("password").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let totp =
                decrypt_cipher_string(login_obj.get("totp").and_then(|v| v.as_str()), &cipher_key);

            let mut uris_decrypted = Vec::new();
            if let Some(uris_arr) = login_obj.get("uris").and_then(|v| v.as_array()) {
                for u in uris_arr {
                    let uri_str =
                        decrypt_cipher_string(u.get("uri").and_then(|v| v.as_str()), &cipher_key);
                    uris_decrypted.push(json!({ "uri": uri_str }));
                }
            }

            login_val = Some(json!({
                "username": user,
                "password": pwd,
                "totp": totp,
                "uris": uris_decrypted,
            }));
        }

        // Decrypt card details if present
        let mut card_val: Option<Value> = None;
        if let Some(card_obj) = c.get("card") {
            let cardholder_name = decrypt_cipher_string(
                card_obj.get("cardholderName").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let brand =
                decrypt_cipher_string(card_obj.get("brand").and_then(|v| v.as_str()), &cipher_key);
            let number =
                decrypt_cipher_string(card_obj.get("number").and_then(|v| v.as_str()), &cipher_key);
            let exp_month = decrypt_cipher_string(
                card_obj.get("expMonth").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let exp_year = decrypt_cipher_string(
                card_obj.get("expYear").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let code =
                decrypt_cipher_string(card_obj.get("code").and_then(|v| v.as_str()), &cipher_key);

            card_val = Some(json!({
                "cardholderName": cardholder_name,
                "brand": brand,
                "number": number,
                "expMonth": exp_month,
                "expYear": exp_year,
                "code": code,
            }));
        }

        // Decrypt identity details if present
        let mut identity_val: Option<Value> = None;
        if let Some(id_obj) = c.get("identity") {
            let title =
                decrypt_cipher_string(id_obj.get("title").and_then(|v| v.as_str()), &cipher_key);
            let first_name = decrypt_cipher_string(
                id_obj.get("firstName").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let middle_name = decrypt_cipher_string(
                id_obj.get("middleName").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let last_name =
                decrypt_cipher_string(id_obj.get("lastName").and_then(|v| v.as_str()), &cipher_key);
            let address1 =
                decrypt_cipher_string(id_obj.get("address1").and_then(|v| v.as_str()), &cipher_key);
            let address2 =
                decrypt_cipher_string(id_obj.get("address2").and_then(|v| v.as_str()), &cipher_key);
            let city =
                decrypt_cipher_string(id_obj.get("city").and_then(|v| v.as_str()), &cipher_key);
            let state =
                decrypt_cipher_string(id_obj.get("state").and_then(|v| v.as_str()), &cipher_key);
            let postal_code = decrypt_cipher_string(
                id_obj.get("postalCode").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let country =
                decrypt_cipher_string(id_obj.get("country").and_then(|v| v.as_str()), &cipher_key);
            let company =
                decrypt_cipher_string(id_obj.get("company").and_then(|v| v.as_str()), &cipher_key);
            let email =
                decrypt_cipher_string(id_obj.get("email").and_then(|v| v.as_str()), &cipher_key);
            let phone =
                decrypt_cipher_string(id_obj.get("phone").and_then(|v| v.as_str()), &cipher_key);
            let ssn =
                decrypt_cipher_string(id_obj.get("ssn").and_then(|v| v.as_str()), &cipher_key);
            let username =
                decrypt_cipher_string(id_obj.get("username").and_then(|v| v.as_str()), &cipher_key);
            let passport_number = decrypt_cipher_string(
                id_obj.get("passportNumber").and_then(|v| v.as_str()),
                &cipher_key,
            );
            let license_number = decrypt_cipher_string(
                id_obj.get("licenseNumber").and_then(|v| v.as_str()),
                &cipher_key,
            );

            identity_val = Some(json!({
                "title": title,
                "firstName": first_name,
                "middleName": middle_name,
                "lastName": last_name,
                "address1": address1,
                "address2": address2,
                "city": city,
                "state": state,
                "postalCode": postal_code,
                "country": country,
                "company": company,
                "email": email,
                "phone": phone,
                "ssn": ssn,
                "username": username,
                "passportNumber": passport_number,
                "licenseNumber": license_number,
            }));
        }

        // Decrypt fields if present
        let mut fields_decrypted = Vec::new();
        if let Some(fields_arr) = c.get("fields").and_then(|v| v.as_array()) {
            for f in fields_arr {
                let fname =
                    decrypt_cipher_string(f.get("name").and_then(|v| v.as_str()), &cipher_key)
                        .unwrap_or_default();
                let fval =
                    decrypt_cipher_string(f.get("value").and_then(|v| v.as_str()), &cipher_key)
                        .unwrap_or_default();
                let ftype = f.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
                fields_decrypted.push(json!({
                    "name": fname,
                    "value": fval,
                    "type": ftype,
                }));
            }
        }

        // Attachments metadata
        let mut attachments_decrypted = Vec::new();
        if let Some(att_arr) = c.get("attachments").and_then(|v| v.as_array()) {
            for att in att_arr {
                let fname = decrypt_cipher_string(
                    att.get("fileName").and_then(|v| v.as_str()),
                    &cipher_key,
                )
                .unwrap_or_default();
                let att_id = att
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = att
                    .get("size")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();
                let url = att
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                attachments_decrypted.push(json!({
                    "id": att_id,
                    "fileName": fname,
                    "size": size,
                    "url": url,
                }));
            }
        }

        // Build raw JSON representation to feed into SSH heuristic scanner
        let raw_item_json = json!({
            "id": id,
            "name": name,
            "type": item_type,
            "notes": notes,
            "favorite": favorite,
            "login": login_val,
            "card": card_val,
            "identity": identity_val,
            "fields": fields_decrypted,
            "attachments": attachments_decrypted,
        });

        if let Some(ssh_meta) = detect_ssh_key_metadata(&raw_item_json) {
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
            for att in &attachments_decrypted {
                if let Some(fn_str) = att.get("fileName").and_then(|v| v.as_str()) {
                    search_tokens.push(fn_str.to_lowercase());
                }
            }
            let search_text = search_tokens.join(" ");

            items.push(VaultItem {
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
                fields: fields_decrypted,
                attachments: attachments_decrypted,
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

        let sub_title = match item_type {
            1 => {
                if let Some(ref l) = login_val {
                    l.get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                } else {
                    String::new()
                }
            }
            2 => "Secure Note".to_string(),
            3 => {
                if let Some(ref c) = card_val {
                    let num = c.get("number").and_then(|v| v.as_str()).unwrap_or("");
                    let brand = c.get("brand").and_then(|v| v.as_str()).unwrap_or("Card");
                    if num.len() >= 4 {
                        let last4 = &num[num.len() - 4..];
                        if !brand.is_empty() && brand != "Card" {
                            format!("{} •••• {}", brand, last4)
                        } else {
                            format!("•••• {}", last4)
                        }
                    } else if !brand.is_empty() {
                        brand.to_string()
                    } else {
                        "Payment Card".to_string()
                    }
                } else {
                    "Payment Card".to_string()
                }
            }
            4 => {
                if let Some(ref id) = identity_val {
                    let full_name = format!(
                        "{} {} {} {}",
                        id.get("title").and_then(|v| v.as_str()).unwrap_or(""),
                        id.get("firstName").and_then(|v| v.as_str()).unwrap_or(""),
                        id.get("middleName").and_then(|v| v.as_str()).unwrap_or(""),
                        id.get("lastName").and_then(|v| v.as_str()).unwrap_or("")
                    )
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");

                    if !full_name.is_empty() {
                        full_name
                    } else if let Some(em) = id.get("email").and_then(|v| v.as_str()) {
                        if !em.is_empty() {
                            em.to_string()
                        } else {
                            "Identity".to_string()
                        }
                    } else if let Some(un) = id.get("username").and_then(|v| v.as_str()) {
                        if !un.is_empty() {
                            un.to_string()
                        } else {
                            "Identity".to_string()
                        }
                    } else {
                        "Identity".to_string()
                    }
                } else {
                    "Identity".to_string()
                }
            }
            _ => {
                if let Some(ref l) = login_val {
                    l.get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                } else {
                    String::new()
                }
            }
        };

        let mut search_tokens = vec![
            name.to_lowercase(),
            notes.clone().unwrap_or_default().to_lowercase(),
        ];
        if !sub_title.is_empty() {
            search_tokens.push(sub_title.to_lowercase());
        }
        if let Some(ref l) = login_val {
            if let Some(u) = l.get("username").and_then(|v| v.as_str()) {
                search_tokens.push(u.to_lowercase());
            }
            if let Some(uris) = l.get("uris").and_then(|v| v.as_array()) {
                for u in uris {
                    if let Some(u_str) = u.get("uri").and_then(|v| v.as_str()) {
                        search_tokens.push(u_str.to_lowercase());
                    }
                }
            }
        }
        if let Some(ref c) = card_val {
            if let Some(b) = c.get("brand").and_then(|v| v.as_str()) {
                search_tokens.push(b.to_lowercase());
            }
            if let Some(num) = c.get("number").and_then(|v| v.as_str()) {
                search_tokens.push(num.to_lowercase());
            }
            if let Some(ch) = c.get("cardholderName").and_then(|v| v.as_str()) {
                search_tokens.push(ch.to_lowercase());
            }
        }
        if let Some(ref id) = identity_val {
            for k in [
                "firstName",
                "lastName",
                "email",
                "phone",
                "username",
                "company",
                "address1",
                "city",
                "ssn",
            ] {
                if let Some(val) = id.get(k).and_then(|v| v.as_str()) {
                    search_tokens.push(val.to_lowercase());
                }
            }
        }
        for f in &fields_decrypted {
            if let Some(fn_str) = f.get("name").and_then(|v| v.as_str()) {
                search_tokens.push(fn_str.to_lowercase());
            }
            if let Some(fv_str) = f.get("value").and_then(|v| v.as_str()) {
                search_tokens.push(fv_str.to_lowercase());
            }
        }
        for att in &attachments_decrypted {
            if let Some(fn_str) = att.get("fileName").and_then(|v| v.as_str()) {
                search_tokens.push(fn_str.to_lowercase());
            }
        }

        let search_text = search_tokens.join(" ");

        items.push(VaultItem {
            id,
            name,
            item_type,
            type_name,
            sub_title,
            notes,
            favorite,
            login: login_val,
            card: card_val,
            identity: identity_val,
            ssh_key: None,
            fields: fields_decrypted,
            attachments: attachments_decrypted,
            search_text,
        });
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    type HmacSha256 = Hmac<Sha256>;

    fn encrypt_test_string(plaintext: &str, key: &SymmetricCryptoKey) -> String {
        let iv = [2u8; 16];
        let enc = Aes256CbcEnc::new_from_slices(&key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; plaintext.len() + 32];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext.as_bytes(), &mut buf)
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac = HmacSha256::new_from_slice(key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        )
    }

    #[test]
    fn test_decrypt_sync_ciphers() {
        let raw_user_key = [5u8; 64];
        let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();

        let enc_name = encrypt_test_string("GitHub Enterprise", &user_key);
        let enc_user = encrypt_test_string("octocat_native", &user_key);
        let enc_pwd = encrypt_test_string("P@ssw0rd123!", &user_key);
        let enc_notes = encrypt_test_string("Production SSH server access", &user_key);

        let ciphers = vec![json!({
            "id": "cipher-1",
            "type": 1,
            "favorite": true,
            "name": enc_name,
            "notes": enc_notes,
            "login": {
                "username": enc_user,
                "password": enc_pwd,
                "uris": [{ "uri": encrypt_test_string("https://github.com/login", &user_key) }]
            }
        })];

        let items = decrypt_sync_ciphers(&ciphers, &user_key);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "GitHub Enterprise");
        assert_eq!(items[0].sub_title, "octocat_native");
        assert_eq!(
            items[0].notes.as_deref(),
            Some("Production SSH server access")
        );
        assert!(items[0].favorite);
    }

    #[test]
    fn test_decrypt_card_and_identity_ciphers() {
        let raw_user_key = [7u8; 64];
        let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();

        let ciphers = vec![
            json!({
                "id": "card-1",
                "type": 3,
                "name": encrypt_test_string("Corporate Visa", &user_key),
                "card": {
                    "cardholderName": encrypt_test_string("Alice Doe", &user_key),
                    "brand": encrypt_test_string("Visa", &user_key),
                    "number": encrypt_test_string("4111222233334444", &user_key),
                    "expMonth": encrypt_test_string("12", &user_key),
                    "expYear": encrypt_test_string("2028", &user_key),
                    "code": encrypt_test_string("987", &user_key),
                }
            }),
            json!({
                "id": "id-1",
                "type": 4,
                "name": encrypt_test_string("Personal Identity", &user_key),
                "identity": {
                    "firstName": encrypt_test_string("Alice", &user_key),
                    "lastName": encrypt_test_string("Doe", &user_key),
                    "email": encrypt_test_string("alice@example.com", &user_key),
                    "phone": encrypt_test_string("+1-555-0199", &user_key),
                    "company": encrypt_test_string("Acme Corp", &user_key),
                    "address1": encrypt_test_string("123 Tech Lane", &user_key),
                    "city": encrypt_test_string("San Francisco", &user_key),
                    "state": encrypt_test_string("CA", &user_key),
                    "postalCode": encrypt_test_string("94105", &user_key),
                    "country": encrypt_test_string("US", &user_key),
                    "ssn": encrypt_test_string("123-45-6789", &user_key),
                }
            }),
            json!({
                "id": "note-1",
                "type": 2,
                "name": encrypt_test_string("Server Recovery Keys", &user_key),
                "notes": encrypt_test_string("Mnemonic: alpha beta gamma delta", &user_key),
            }),
        ];

        let items = decrypt_sync_ciphers(&ciphers, &user_key);
        assert_eq!(items.len(), 3);

        // Card assertions
        assert_eq!(items[0].name, "Corporate Visa");
        assert_eq!(items[0].type_name, "card");
        assert_eq!(items[0].sub_title, "Visa •••• 4444");
        let card = items[0].card.as_ref().unwrap();
        assert_eq!(card.get("cardholderName").unwrap(), "Alice Doe");
        assert_eq!(card.get("brand").unwrap(), "Visa");
        assert_eq!(card.get("number").unwrap(), "4111222233334444");
        assert_eq!(card.get("code").unwrap(), "987");

        // Identity assertions
        assert_eq!(items[1].name, "Personal Identity");
        assert_eq!(items[1].type_name, "identity");
        assert_eq!(items[1].sub_title, "Alice Doe");
        let id_val = items[1].identity.as_ref().unwrap();
        assert_eq!(id_val.get("firstName").unwrap(), "Alice");
        assert_eq!(id_val.get("lastName").unwrap(), "Doe");
        assert_eq!(id_val.get("email").unwrap(), "alice@example.com");
        assert_eq!(id_val.get("phone").unwrap(), "+1-555-0199");
        assert_eq!(id_val.get("company").unwrap(), "Acme Corp");
        assert_eq!(id_val.get("city").unwrap(), "San Francisco");

        // Note assertions
        assert_eq!(items[2].name, "Server Recovery Keys");
        assert_eq!(items[2].type_name, "note");
        assert_eq!(items[2].sub_title, "Secure Note");
        assert_eq!(
            items[2].notes.as_deref(),
            Some("Mnemonic: alpha beta gamma delta")
        );
    }
}
