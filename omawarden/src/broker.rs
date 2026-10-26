use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::vault::{VaultItem, VaultManager};

/// Placeholder text substituted in place of detected secret tokens.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED:VAULT_SECRET]";

/// A single destination binding whitelist rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationRule {
    /// Cipher / secret reference (e.g., "OpenAI" or "*" for any item)
    pub cipher_ref: String,
    /// Absolute or normalized path to the authorized binary (e.g. "/usr/bin/python3")
    pub binary_path: String,
    /// Optional argument prefix restrictions (e.g. ["-m", "my_agent"])
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// Whitelist policy managing destination bindings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrokerPolicy {
    #[serde(default)]
    pub rules: Vec<DestinationRule>,
}

impl BrokerPolicy {
    /// Adds or updates an allowed destination binding rule.
    pub fn allow_rule(&mut self, cipher_ref: &str, binary_path: &str, args: &[String]) {
        self.rules.retain(|r| {
            !(r.cipher_ref.eq_ignore_ascii_case(cipher_ref)
                && r.binary_path == binary_path
                && r.args == args)
        });

        self.rules.push(DestinationRule {
            cipher_ref: cipher_ref.to_string(),
            binary_path: binary_path.to_string(),
            args: args.to_vec(),
        });
    }

    /// Checks whether an execution with the given cipher reference and command is permitted.
    pub fn is_allowed(&self, cipher_ref: &str, cmd: &[String]) -> bool {
        if cmd.is_empty() {
            return false;
        }

        let binary = &cmd[0];
        let args = &cmd[1..];

        for rule in &self.rules {
            let cipher_matches =
                rule.cipher_ref == "*" || rule.cipher_ref.eq_ignore_ascii_case(cipher_ref);
            if !cipher_matches {
                continue;
            }

            let binary_matches =
                rule.binary_path == *binary || Path::new(&rule.binary_path) == Path::new(binary);

            if !binary_matches {
                continue;
            }

            if !rule.args.is_empty() {
                if args.len() < rule.args.len() {
                    continue;
                }
                if &args[..rule.args.len()] != rule.args.as_slice() {
                    continue;
                }
            }

            return true;
        }

        false
    }

    /// Resolves the policy file path (`broker_policy.json`).
    pub fn default_policy_path() -> PathBuf {
        let storage_path = crate::storage::resolve_default_storage_path();
        let parent = storage_path.parent().unwrap_or_else(|| Path::new("."));
        parent.join("broker_policy.json")
    }

    /// Loads broker policy from disk. Returns default empty policy if file does not exist.
    pub fn load_from_file(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Saves broker policy atomically to disk with permissions 0o600.
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        crate::fs_util::atomic_write_str(path, &content, 0o600)
    }
}

/// Inspects the caller process that executed the broker command.
pub fn get_caller_exe(pid: u32) -> Option<String> {
    let proc_path = PathBuf::from(format!("/proc/{}/exe", pid));
    std::fs::read_link(proc_path).ok().map(|p| {
        p.to_string_lossy()
            .trim_end_matches(" (deleted)")
            .to_string()
    })
}

/// Resolves the invoking application for a caller PID by traversing parent process lineage.
pub fn get_caller_app_from_pid(pid: u32) -> String {
    let peer = crate::ssh_agent::Peer::from_pid(pid as i32);
    let app = peer.find_app();
    if !app.is_empty() {
        app
    } else if !peer.exe.is_empty() {
        peer.exe
    } else {
        "unknown".to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerDecision {
    #[default]
    Deny,
    AllowOnce,
    AllowAlways,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerPrompt {
    pub id: u64,
    pub title: String,
    pub cipher_ref: String,
    pub command: String,
    pub binary_path: String,
    pub caller_app: String,
    pub caller_pid: u32,
    #[serde(default)]
    pub args: Vec<String>,
}

pub struct PendingBrokerApproval {
    pub prompt: BrokerPrompt,
    pub decision: Option<BrokerDecision>,
}

pub struct BrokerApprovalState {
    pub next_id: std::sync::atomic::AtomicU64,
    pub pending: std::sync::Mutex<HashMap<u64, PendingBrokerApproval>>,
    pub answered: std::sync::Condvar,
    pub prompt_timeout: std::time::Duration,
    pub policy: std::sync::RwLock<BrokerPolicy>,
    pub policy_path: PathBuf,
}

impl Default for BrokerApprovalState {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerApprovalState {
    pub fn new() -> Self {
        let policy_path = BrokerPolicy::default_policy_path();
        let policy = BrokerPolicy::load_from_file(&policy_path);
        Self {
            next_id: std::sync::atomic::AtomicU64::new(1),
            pending: std::sync::Mutex::new(HashMap::new()),
            answered: std::sync::Condvar::new(),
            prompt_timeout: std::time::Duration::from_secs(60),
            policy: std::sync::RwLock::new(policy),
            policy_path,
        }
    }

    pub fn list_pending(&self) -> Vec<BrokerPrompt> {
        let Ok(pending) = self.pending.lock() else {
            return Vec::new();
        };
        let mut list: Vec<BrokerPrompt> = pending.values().map(|p| p.prompt.clone()).collect();
        list.sort_by_key(|p| p.id);
        list
    }

    pub fn reply(&self, id: u64, decision: BrokerDecision) -> bool {
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };

        match pending.get_mut(&id) {
            Some(p) if p.decision.is_none() => {
                p.decision = Some(decision);
                if decision == BrokerDecision::AllowAlways {
                    let mut pol = self.policy.write().unwrap();
                    pol.allow_rule(&p.prompt.cipher_ref, &p.prompt.binary_path, &p.prompt.args);
                    let _ = pol.save_to_file(&self.policy_path);
                }
                self.answered.notify_all();
                true
            }
            _ => false,
        }
    }

    pub fn ask<F>(&self, mut prompt: BrokerPrompt, summon_fn: F) -> BrokerDecision
    where
        F: FnOnce(&serde_json::Value) -> bool,
    {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        prompt.id = id;

        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(
                id,
                PendingBrokerApproval {
                    prompt: prompt.clone(),
                    decision: None,
                },
            );
        }

        let payload = serde_json::json!({
            "view": "broker-approval",
            "id": id,
            "cipher_ref": prompt.cipher_ref,
            "binary_path": prompt.binary_path,
            "caller_app": prompt.caller_app,
        });

        if !summon_fn(&payload) {
            // Summon failed; clean up and deny
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(&id);
            }
            return BrokerDecision::Deny;
        }

        let deadline = std::time::Instant::now() + self.prompt_timeout;
        let Ok(mut pending) = self.pending.lock() else {
            return BrokerDecision::Deny;
        };

        let decision = loop {
            if let Some(d) = pending.get(&id).and_then(|p| p.decision) {
                break d;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                break BrokerDecision::Deny;
            }
            match self.answered.wait_timeout(pending, deadline - now) {
                Ok((guard, _)) => pending = guard,
                Err(_) => return BrokerDecision::Deny,
            }
        };

        pending.remove(&id);
        decision
    }
}

/// Prohibited environment variable names that must not be injected to prevent hijacking.
pub const PROHIBITED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PATH",
    "IFS",
    "SHELLOPTS",
    "BASH_ENV",
    "ENV",
];

/// Validates whether a string is a valid POSIX environment variable identifier:
/// starts with `[A-Za-z_]` followed by `[A-Za-z0-9_]*`.
pub fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Checks if an environment variable name is prohibited for security reasons.
pub fn is_prohibited_env_var(name: &str) -> bool {
    PROHIBITED_ENV_VARS
        .iter()
        .any(|b| b.eq_ignore_ascii_case(name))
}

/// File name for project secrets manifest.
pub const MANIFEST_FILENAME: &str = ".omawarden.toml";

/// Optional [project] section in .omawarden.toml.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProjectSection {
    #[serde(default)]
    pub items: Vec<String>,
}

/// Project secrets manifest (`.omawarden.toml`) containing zero plaintext secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProjectManifest {
    /// Explicit environment variable mappings: `KEY = "cipher_ref"` or `KEY = "cipher_ref#field"`
    #[serde(default)]
    pub env: BTreeMap<String, String>,

    /// Items to auto-infer and inject environment variables from (using provider patterns or custom fields)
    #[serde(default)]
    pub items: Vec<String>,

    /// Optional [project] section containing metadata and items
    #[serde(default)]
    pub project: Option<ProjectSection>,
}

impl ProjectManifest {
    /// Loads and parses a project manifest from a file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read manifest file '{}': {}", path.display(), e))?;
        let mut manifest: ProjectManifest = toml::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse manifest TOML in '{}': {}",
                path.display(),
                e
            )
        })?;

        if let Some(proj) = manifest.project.take() {
            for itm in proj.items {
                if !manifest.items.contains(&itm) {
                    manifest.items.push(itm);
                }
            }
        }

        Ok(manifest)
    }

    /// Finds `.omawarden.toml` in `start_dir` or any of its parent directories.
    pub fn find_in_ancestors(start_dir: &Path) -> Option<PathBuf> {
        let abs_dir = if start_dir.is_absolute() {
            start_dir.to_path_buf()
        } else {
            start_dir.canonicalize().unwrap_or_else(|_| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("/"))
                    .join(start_dir)
            })
        };
        let mut curr = Some(abs_dir.as_path());
        while let Some(dir) = curr {
            let candidate = dir.join(MANIFEST_FILENAME);
            if candidate.is_file() {
                return Some(candidate);
            }
            curr = dir.parent();
        }
        None
    }
}

/// A mapping rule between provider name patterns and its standard canonical environment variable.
#[derive(Debug, Clone, Copy)]
pub struct ProviderPattern {
    pub patterns: &'static [&'static str],
    pub canonical_env: &'static str,
}

pub static PROVIDER_PATTERNS: &[ProviderPattern] = &[
    // AI / LLM Providers (checked with highest precedence)
    ProviderPattern {
        patterns: &["azure_openai", "azureopenai", "azure-openai"],
        canonical_env: "AZURE_OPENAI_API_KEY",
    },
    ProviderPattern {
        patterns: &["openai", "chatgpt"],
        canonical_env: "OPENAI_API_KEY",
    },
    ProviderPattern {
        patterns: &["anthropic", "claude"],
        canonical_env: "ANTHROPIC_API_KEY",
    },
    ProviderPattern {
        patterns: &[
            "gemini",
            "google_ai",
            "googleai",
            "google_gemini",
            "google-gemini",
        ],
        canonical_env: "GEMINI_API_KEY",
    },
    ProviderPattern {
        patterns: &["deepseek"],
        canonical_env: "DEEPSEEK_API_KEY",
    },
    ProviderPattern {
        patterns: &["groq"],
        canonical_env: "GROQ_API_KEY",
    },
    ProviderPattern {
        patterns: &["mistral"],
        canonical_env: "MISTRAL_API_KEY",
    },
    ProviderPattern {
        patterns: &["cohere"],
        canonical_env: "CO_API_KEY",
    },
    ProviderPattern {
        patterns: &["perplexity"],
        canonical_env: "PERPLEXITY_API_KEY",
    },
    ProviderPattern {
        patterns: &["together", "together_ai", "togetherai"],
        canonical_env: "TOGETHER_API_KEY",
    },
    ProviderPattern {
        patterns: &["replicate"],
        canonical_env: "REPLICATE_API_TOKEN",
    },
    ProviderPattern {
        patterns: &["huggingface", "hugging_face", "hf"],
        canonical_env: "HF_TOKEN",
    },
    // Developer & Git Platforms
    ProviderPattern {
        patterns: &["github", "gh"],
        canonical_env: "GITHUB_TOKEN",
    },
    ProviderPattern {
        patterns: &["gitlab"],
        canonical_env: "GITLAB_TOKEN",
    },
    ProviderPattern {
        patterns: &["bitbucket"],
        canonical_env: "BITBUCKET_TOKEN",
    },
    // Cloud & Infrastructure
    ProviderPattern {
        patterns: &["aws", "amazon_web_services"],
        canonical_env: "AWS_SECRET_ACCESS_KEY",
    },
    ProviderPattern {
        patterns: &["cloudflare"],
        canonical_env: "CLOUDFLARE_API_TOKEN",
    },
    ProviderPattern {
        patterns: &["digitalocean", "digital_ocean"],
        canonical_env: "DIGITALOCEAN_TOKEN",
    },
    ProviderPattern {
        patterns: &["flyio", "fly.io", "fly_io"],
        canonical_env: "FLY_API_TOKEN",
    },
    ProviderPattern {
        patterns: &["render"],
        canonical_env: "RENDER_API_KEY",
    },
    ProviderPattern {
        patterns: &["railway"],
        canonical_env: "RAILWAY_TOKEN",
    },
    ProviderPattern {
        patterns: &["vercel"],
        canonical_env: "VERCEL_TOKEN",
    },
    ProviderPattern {
        patterns: &["netlify"],
        canonical_env: "NETLIFY_AUTH_TOKEN",
    },
    ProviderPattern {
        patterns: &["gcp", "google_cloud", "googlecloud"],
        canonical_env: "GOOGLE_APPLICATION_CREDENTIALS",
    },
    // Databases & Vector Stores
    ProviderPattern {
        patterns: &["supabase"],
        canonical_env: "SUPABASE_KEY",
    },
    ProviderPattern {
        patterns: &["neon"],
        canonical_env: "NEON_API_KEY",
    },
    ProviderPattern {
        patterns: &["pinecone"],
        canonical_env: "PINECONE_API_KEY",
    },
    ProviderPattern {
        patterns: &["qdrant"],
        canonical_env: "QDRANT_API_KEY",
    },
    ProviderPattern {
        patterns: &["weaviate"],
        canonical_env: "WEAVIATE_API_KEY",
    },
    // Payments & Commerce
    ProviderPattern {
        patterns: &["stripe"],
        canonical_env: "STRIPE_SECRET_KEY",
    },
    ProviderPattern {
        patterns: &["shopify"],
        canonical_env: "SHOPIFY_API_KEY",
    },
    // Messaging & Communications
    ProviderPattern {
        patterns: &["resend"],
        canonical_env: "RESEND_API_KEY",
    },
    ProviderPattern {
        patterns: &["sendgrid"],
        canonical_env: "SENDGRID_API_KEY",
    },
    ProviderPattern {
        patterns: &["twilio"],
        canonical_env: "TWILIO_AUTH_TOKEN",
    },
    ProviderPattern {
        patterns: &["mailgun"],
        canonical_env: "MAILGUN_API_KEY",
    },
    ProviderPattern {
        patterns: &["slack"],
        canonical_env: "SLACK_BOT_TOKEN",
    },
    ProviderPattern {
        patterns: &["discord"],
        canonical_env: "DISCORD_BOT_TOKEN",
    },
    ProviderPattern {
        patterns: &["telegram"],
        canonical_env: "TELEGRAM_BOT_TOKEN",
    },
    // Monitoring & Observability
    ProviderPattern {
        patterns: &["sentry"],
        canonical_env: "SENTRY_AUTH_TOKEN",
    },
    ProviderPattern {
        patterns: &["datadog", "dd"],
        canonical_env: "DD_API_KEY",
    },
    ProviderPattern {
        patterns: &["newrelic", "new_relic"],
        canonical_env: "NEW_RELIC_API_KEY",
    },
    ProviderPattern {
        patterns: &["posthog"],
        canonical_env: "POSTHOG_API_KEY",
    },
    // Package Registries & Tooling
    ProviderPattern {
        patterns: &["npm"],
        canonical_env: "NPM_TOKEN",
    },
    ProviderPattern {
        patterns: &["pypi"],
        canonical_env: "PYPI_TOKEN",
    },
    ProviderPattern {
        patterns: &["docker", "dockerhub"],
        canonical_env: "DOCKER_PASSWORD",
    },
    ProviderPattern {
        patterns: &["postman"],
        canonical_env: "POSTMAN_API_KEY",
    },
    ProviderPattern {
        patterns: &["linear"],
        canonical_env: "LINEAR_API_KEY",
    },
    ProviderPattern {
        patterns: &["jira", "atlassian"],
        canonical_env: "JIRA_API_TOKEN",
    },
    ProviderPattern {
        patterns: &["notion"],
        canonical_env: "NOTION_API_KEY",
    },
    ProviderPattern {
        patterns: &["algolia"],
        canonical_env: "ALGOLIA_API_KEY",
    },
];

/// Infers canonical environment variable name for a given provider or item name.
pub fn infer_provider_env_var(item_name: &str) -> Option<&'static str> {
    let lower = item_name.to_lowercase();
    let clean_name = lower.replace(['-', '_', ' ', '.'], "");
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();

    for rule in PROVIDER_PATTERNS {
        for &pattern in rule.patterns {
            let clean_pattern = pattern.replace(['-', '_', ' ', '.'], "");
            let is_short_pattern = clean_pattern.len() <= 3;

            // 1. Exact token match in parsed words (e.g. "openai", "aws", "gh") or exact normalized match
            if words.contains(&pattern) || lower == pattern || clean_name == clean_pattern {
                return Some(rule.canonical_env);
            }

            // 2. Phrase or compound match for longer patterns (len >= 4 only)
            if !is_short_pattern {
                if pattern.contains([' ', '_', '-']) && lower.contains(pattern) {
                    return Some(rule.canonical_env);
                }
                if clean_name.starts_with(&clean_pattern) || clean_name.ends_with(&clean_pattern) {
                    return Some(rule.canonical_env);
                }
            }
        }
    }

    None
}

/// Returns standard display name for a provider pattern.
pub fn get_provider_display_name(pattern: &str) -> &'static str {
    match pattern {
        "azure_openai" | "azureopenai" | "azure-openai" => "Azure OpenAI",
        "openai" | "chatgpt" => "OpenAI",
        "anthropic" | "claude" => "Anthropic",
        "gemini" | "google_ai" | "googleai" | "google_gemini" | "google-gemini" => "Google Gemini",
        "mistral" => "Mistral",
        "cohere" => "Cohere",
        "perplexity" => "Perplexity",
        "together" | "together_ai" | "togetherai" => "Together AI",
        "replicate" => "Replicate",
        "huggingface" | "hugging_face" | "hf" => "Hugging Face",
        "github" | "gh" => "GitHub",
        "gitlab" => "GitLab",
        "bitbucket" => "BitBucket",
        "aws" | "amazon_web_services" => "AWS",
        "cloudflare" => "Cloudflare",
        "digitalocean" | "digital_ocean" => "DigitalOcean",
        "flyio" | "fly.io" | "fly_io" => "Fly.io",
        "vercel" => "Vercel",
        "netlify" => "Netlify",
        "heroku" => "Heroku",
        "render" => "Render",
        "supabase" => "Supabase",
        "firebase" => "Firebase",
        "neon" => "Neon",
        "upstash" => "Upstash",
        "planetscale" => "PlanetScale",
        "pinecone" => "Pinecone",
        "qdrant" => "Qdrant",
        "weaviate" => "Weaviate",
        "stripe" => "Stripe",
        "shopify" => "Shopify",
        "resend" => "Resend",
        "sendgrid" => "SendGrid",
        "twilio" => "Twilio",
        "mailgun" => "Mailgun",
        "slack" => "Slack",
        "discord" => "Discord",
        "telegram" => "Telegram",
        "sentry" => "Sentry",
        "datadog" | "dd" => "Datadog",
        "newrelic" | "new_relic" => "New Relic",
        "posthog" => "PostHog",
        "npm" | "npmjs" => "npm",
        "cargo" | "cratesio" => "Cargo",
        "pypi" => "PyPI",
        "docker" | "dockerhub" => "Docker",
        "jira" | "atlassian" => "Jira",
        "notion" => "Notion",
        "algolia" => "Algolia",
        "groq" => "Groq",
        "deepseek" => "DeepSeek",
        "ollama" => "Ollama",
        "voyage" => "Voyage AI",
        _ => "Provider",
    }
}

/// Infers the provider category / display name for an environment variable key name.
pub fn infer_provider_from_env_key(key: &str) -> Option<&'static str> {
    let upper = key.to_ascii_uppercase();

    // 1. Direct canonical match against known providers
    for rule in PROVIDER_PATTERNS {
        if upper == rule.canonical_env {
            return Some(get_provider_display_name(rule.patterns[0]));
        }
    }

    // 2. Database and storage patterns
    if upper == "DATABASE_URL"
        || upper.starts_with("POSTGRES_")
        || upper.starts_with("POSTGRESQL_")
        || upper.starts_with("PG_")
        || upper.starts_with("MYSQL_")
        || upper.starts_with("REDIS_")
        || upper.starts_with("MONGODB_")
        || upper.starts_with("MONGO_")
    {
        return Some("Database");
    }

    // 3. Known AI and Cloud specialized prefixes
    if upper.starts_with("AZURE_OPENAI") {
        return Some("Azure OpenAI");
    }
    if upper.starts_with("OPENAI") || upper.starts_with("CHATGPT") {
        return Some("OpenAI");
    }
    if upper.starts_with("ANTHROPIC") || upper.starts_with("CLAUDE") {
        return Some("Anthropic");
    }
    if upper.starts_with("GEMINI")
        || upper.starts_with("GOOGLE_AI")
        || upper.starts_with("GOOGLE_GEMINI")
    {
        return Some("Google Gemini");
    }
    if upper.starts_with("GROQ") {
        return Some("Groq");
    }
    if upper.starts_with("DEEPSEEK") {
        return Some("DeepSeek");
    }
    if upper.starts_with("OLLAMA") {
        return Some("Ollama");
    }
    if upper.starts_with("VOYAGE") {
        return Some("Voyage AI");
    }

    // 4. Prefix matching against registered pattern stems
    for rule in PROVIDER_PATTERNS {
        for &pattern in rule.patterns {
            let pat_upper = pattern.to_ascii_uppercase();
            let pat_with_underscore = format!("{}_", pat_upper);

            if pattern.len() <= 3 {
                // Short pattern (e.g. "gh", "dd", "aws", "hf"): require exact prefix with underscore
                if upper.starts_with(&pat_with_underscore) {
                    return Some(get_provider_display_name(rule.patterns[0]));
                }
            } else {
                // Longer pattern: prefix or compound segment match
                if upper.starts_with(&pat_upper)
                    || upper.starts_with(&pat_with_underscore)
                    || upper.contains(&format!("_{}_", pat_upper))
                {
                    return Some(get_provider_display_name(rule.patterns[0]));
                }
            }
        }
    }

    None
}

/// Parses the contents of a legacy `.env` file into key-value pairs.
///
/// Strips comments, handles single and double quotes, unescapes strings,
/// skips invalid or prohibited environment variable names, and preserves in-file ordering.
pub fn parse_env_file_content(content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();

    for raw_line in content.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(stripped) = line.strip_prefix("export ") {
            line = stripped.trim();
        }

        let Some(eq_idx) = line.find('=') else {
            continue;
        };

        let key = line[..eq_idx].trim();
        if !is_valid_env_var_name(key) || is_prohibited_env_var(key) {
            continue;
        }

        let raw_val = line[eq_idx + 1..].trim();
        let value = if let Some(stripped) = raw_val.strip_prefix('\'') {
            // Single quoted string: find closing quote or trim
            if let Some(end_idx) = stripped.find('\'') {
                stripped[..end_idx].to_string()
            } else {
                stripped.trim_end_matches('\'').to_string()
            }
        } else if let Some(stripped) = raw_val.strip_prefix('"') {
            // Double quoted string: handle escapes and closing quote
            let val_chars = stripped.chars();
            let mut unescaped = String::new();
            let mut in_escape = false;
            let mut closed = false;

            for ch in val_chars {
                if in_escape {
                    match ch {
                        'n' => unescaped.push('\n'),
                        'r' => unescaped.push('\r'),
                        't' => unescaped.push('\t'),
                        '\\' => unescaped.push('\\'),
                        '"' => unescaped.push('"'),
                        '$' => unescaped.push('$'),
                        other => {
                            unescaped.push('\\');
                            unescaped.push(other);
                        }
                    }
                    in_escape = false;
                } else if ch == '\\' {
                    in_escape = true;
                } else if ch == '"' {
                    closed = true;
                    break;
                } else {
                    unescaped.push(ch);
                }
            }
            if !closed && raw_val.ends_with('"') && raw_val.len() > 1 {
                raw_val[1..raw_val.len() - 1].to_string()
            } else {
                unescaped
            }
        } else {
            // Unquoted string: strip trailing comment if any
            let val_without_comment = if let Some(comment_idx) = raw_val.find(" #") {
                &raw_val[..comment_idx]
            } else {
                raw_val
            };
            val_without_comment.trim().to_string()
        };

        vars.push((key.to_string(), value));
    }

    vars
}

/// Scans a directory for legacy environment files (e.g. `.env`, `.env.local`, `.env.development`).
/// Excludes examples, templates, distributions, and backup files.
pub fn scan_legacy_env_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };

        if !name.starts_with(".env") {
            continue;
        }

        let lower = name.to_lowercase();
        if lower.ends_with(".example")
            || lower.ends_with(".sample")
            || lower.ends_with(".template")
            || lower.ends_with(".dist")
            || lower.ends_with(".bak")
            || lower.ends_with(".backup")
            || lower.ends_with('~')
        {
            continue;
        }

        files.push(path);
    }

    files.sort_by(|a, b| {
        let name_a = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let name_b = b.file_name().and_then(|s| s.to_str()).unwrap_or("");

        let rank = |name: &str| match name {
            ".env" => 0,
            ".env.local" => 1,
            ".env.development" => 2,
            ".env.development.local" => 3,
            ".env.test" => 4,
            ".env.test.local" => 5,
            ".env.production" => 6,
            ".env.production.local" => 7,
            _ => 10,
        };

        let rank_a = rank(name_a);
        let rank_b = rank(name_b);

        if rank_a != rank_b {
            rank_a.cmp(&rank_b)
        } else {
            name_a.cmp(name_b)
        }
    });

    files
}

/// Groups environment variable key-value pairs by provider or project fallback name.
/// Deduplicates keys across multiple files, preserving the latest assigned value.
pub fn group_env_vars_by_provider(
    vars: &[(String, String)],
    project_fallback: &str,
) -> BTreeMap<String, Vec<(String, String)>> {
    let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for (k, v) in vars {
        let group_name = infer_provider_from_env_key(k)
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                if project_fallback.is_empty() {
                    "Project".to_string()
                } else {
                    project_fallback.to_string()
                }
            });

        groups
            .entry(group_name)
            .or_default()
            .insert(k.clone(), v.clone());
    }

    let mut result: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (group_name, key_map) in groups {
        let list: Vec<(String, String)> = key_map.into_iter().collect();
        result.insert(group_name, list);
    }
    result
}

/// Scaffolds a `ProjectManifest` from categorized provider groups.
pub fn scaffold_manifest_from_groups(
    groups: &BTreeMap<String, Vec<(String, String)>>,
) -> ProjectManifest {
    let mut manifest = ProjectManifest::default();
    for group_name in groups.keys() {
        if !manifest.items.contains(group_name) {
            manifest.items.push(group_name.clone());
        }
    }
    manifest
}

/// Securely wipes a file on disk by overwriting with zeros, flushing to disk, and removing it.
pub fn secure_wipe_file(path: &Path) -> Result<(), std::io::Error> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = std::fs::metadata(path)?;
    let len = metadata.len() as usize;
    if len > 0 {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        let mut zeros = vec![0u8; len];
        file.write_all(&zeros)?;
        file.sync_all()?;
        zeros.zeroize();
    }
    std::fs::remove_file(path)?;
    Ok(())
}

/// Appends a pattern to `.gitignore` in `project_dir` if not already present.
pub fn ensure_in_gitignore(project_dir: &Path, pattern: &str) -> Result<bool, std::io::Error> {
    let gitignore_path = project_dir.join(".gitignore");
    let existing = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == pattern || (pattern == ".env*" && (trimmed == ".env" || trimmed == ".env*")) {
            return Ok(false);
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)?;

    let prefix = if !existing.is_empty() && !existing.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    file.write_all(format!("{}{}\n", prefix, pattern).as_bytes())?;
    file.sync_all()?;
    Ok(true)
}

/// Resolves environment variables from a single VaultItem.
///
/// Injects all custom fields where field name becomes the environment variable name.
/// If the item is a Login with a password, it checks the provider pattern registry to
/// auto-infer standard environment variables (e.g. OpenAI -> OPENAI_API_KEY).
/// If no provider matches, it falls back to API_KEY (for sk-/ghp- tokens) or PASSWORD.
pub fn resolve_item_env(item: &VaultItem) -> HashMap<String, String> {
    let mut env = HashMap::new();

    for field in &item.fields {
        let name = field
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let value = field
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        if !name.is_empty()
            && !value.is_empty()
            && is_valid_env_var_name(name)
            && !is_prohibited_env_var(name)
        {
            env.insert(name.to_string(), value.to_string());
        }
    }

    if let Some(ref login) = item.login {
        if let Some(password) = login.get("password").and_then(|v| v.as_str()) {
            if !password.is_empty() {
                if let Some(inferred) = infer_provider_env_var(&item.name) {
                    if !env.contains_key(inferred) {
                        env.insert(inferred.to_string(), password.to_string());
                    }
                } else if !env.contains_key("PASSWORD") && !env.contains_key("API_KEY") {
                    if password.starts_with("sk-") || password.starts_with("ghp_") {
                        env.insert("API_KEY".to_string(), password.to_string());
                    } else {
                        env.insert("PASSWORD".to_string(), password.to_string());
                    }
                }
            }
        }
    }

    env
}

/// Resolves requested environment variables from the vault according to item and explicit mappings.
pub fn resolve_broker_env(
    vault_mgr: &VaultManager,
    item_query: Option<&str>,
    env_mappings: &[String],
) -> Result<HashMap<String, String>, String> {
    resolve_broker_env_ext(vault_mgr, item_query, env_mappings, &[])
}

/// Resolves requested environment variables from the vault according to item queries, declared items, and explicit mappings.
pub fn resolve_broker_env_ext(
    vault_mgr: &VaultManager,
    item_query: Option<&str>,
    env_mappings: &[String],
    items: &[String],
) -> Result<HashMap<String, String>, String> {
    let mut resolved = HashMap::new();

    if let Some(query) = item_query {
        let item = vault_mgr
            .find_item(query, None)
            .ok_or_else(|| format!("Vault item '{}' not found", query))?;
        let item_env = resolve_item_env(&item);
        resolved.extend(item_env);
    }

    for itm in items {
        let item = vault_mgr
            .find_item(itm, None)
            .ok_or_else(|| format!("Vault item '{}' not found", itm))?;
        let item_env = resolve_item_env(&item);
        resolved.extend(item_env);
    }

    for mapping in env_mappings {
        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid env mapping '{}': expected format VAR=item or VAR=item#field",
                mapping
            ));
        }

        let var_name = parts[0].trim();
        let target = parts[1].trim();

        if !is_valid_env_var_name(var_name) {
            return Err(format!(
                "Invalid environment variable name '{}' in mapping '{}'",
                var_name, mapping
            ));
        }
        if is_prohibited_env_var(var_name) {
            return Err(format!(
                "Prohibited environment variable name '{}' in mapping '{}'",
                var_name, mapping
            ));
        }

        let (item_name, field_name) = if let Some(idx) = target.find('#') {
            (&target[..idx], Some(&target[idx + 1..]))
        } else {
            (target, None)
        };

        let item = vault_mgr.find_item(item_name, None).ok_or_else(|| {
            format!(
                "Vault item '{}' not found for mapping '{}'",
                item_name, mapping
            )
        })?;

        let val = if let Some(field) = field_name {
            if field.eq_ignore_ascii_case("password") {
                item.login
                    .as_ref()
                    .and_then(|l| l.get("password").and_then(|p| p.as_str()))
                    .ok_or_else(|| format!("Item '{}' has no password", item_name))?
                    .to_string()
            } else if field.eq_ignore_ascii_case("username") {
                item.login
                    .as_ref()
                    .and_then(|l| l.get("username").and_then(|u| u.as_str()))
                    .ok_or_else(|| format!("Item '{}' has no username", item_name))?
                    .to_string()
            } else {
                item.fields
                    .iter()
                    .find(|f| {
                        f.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.eq_ignore_ascii_case(field))
                            .unwrap_or(false)
                    })
                    .and_then(|f| f.get("value").and_then(|v| v.as_str()))
                    .ok_or_else(|| format!("Field '{}' not found in item '{}'", field, item_name))?
                    .to_string()
            }
        } else {
            // No field specified: check fields or password
            let item_env = resolve_item_env(&item);
            if let Some(v) = item_env.get(var_name) {
                v.clone()
            } else if item_env.len() == 1 {
                item_env.into_values().next().unwrap()
            } else if item_env.is_empty() {
                return Err(format!(
                    "Item '{}' has no fields or secret value",
                    item_name
                ));
            } else {
                return Err(format!(
                    "Item '{}' has multiple fields; please specify the field using format {}=item#field",
                    item_name, var_name
                ));
            }
        };

        resolved.insert(var_name.to_string(), val);
    }

    Ok(resolved)
}

/// Builds an Aho-Corasick automaton from secret values and all their substrings of length >= 6.
pub fn build_redaction_filter(secrets: &[&str]) -> Option<(aho_corasick::AhoCorasick, usize)> {
    let mut patterns = std::collections::HashSet::new();
    let mut max_len = 0;

    for &secret in secrets {
        let trimmed = secret.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Always include the full secret value
        patterns.insert(trimmed.to_string());
        if trimmed.len() > max_len {
            max_len = trimmed.len();
        }

        // For secrets of length >= 6, generate all substrings with length >= 6
        if trimmed.len() >= 6 {
            let bytes = trimmed.as_bytes();
            let limit = bytes.len().min(128);
            for len in 6..=limit {
                for window in bytes.windows(len) {
                    if let Ok(s) = std::str::from_utf8(window) {
                        if !s.trim().is_empty() {
                            patterns.insert(s.to_string());
                        }
                    }
                }
            }
        }
    }

    if patterns.is_empty() {
        return None;
    }

    let mut pattern_list: Vec<String> = patterns.into_iter().collect();
    // Sort longest first to guarantee optimal leftmost longest match preference
    pattern_list.sort_by_key(|a| std::cmp::Reverse(a.len()));

    aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(pattern_list)
        .ok()
        .map(|ac| (ac, max_len))
}

/// Streams data from `reader` to `writer`, replacing matched secrets with `REDACTION_PLACEHOLDER`.
pub fn stream_redacted<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    filter: &aho_corasick::AhoCorasick,
    max_pattern_len: usize,
) -> std::io::Result<()> {
    let replacement = REDACTION_PLACEHOLDER.as_bytes();
    let replacements = vec![replacement; filter.patterns_len()];
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            // EOF: scrub any remaining pending bytes and flush
            if !pending.is_empty() {
                let redacted = filter.replace_all_bytes(&pending, &replacements);
                writer.write_all(&redacted)?;
                writer.flush()?;
            }
            break;
        }

        pending.extend_from_slice(&buf[..n]);

        if let Some(last_nl) = pending.iter().rposition(|&b| b == b'\n') {
            let chunk = &pending[..=last_nl];
            let redacted = filter.replace_all_bytes(chunk, &replacements);
            writer.write_all(&redacted)?;
            writer.flush()?;
            pending.drain(..=last_nl);
        } else if pending.len() >= 8192 {
            let split_at = pending.len().saturating_sub(max_pattern_len);
            if split_at > 0 {
                let chunk = &pending[..split_at];
                let redacted = filter.replace_all_bytes(chunk, &replacements);
                writer.write_all(&redacted)?;
                writer.flush()?;
                pending.drain(..split_at);
            }
        }
    }

    Ok(())
}

/// Spawns the child command with injected environment variables, zeroes out in-memory secrets,
/// streams and redacts stdout and stderr in real-time (unless `redact == false`), and waits for completion.
pub fn execute_child_process(
    cmd: &[String],
    mut env_vars: HashMap<String, String>,
    redact: bool,
    no_network: bool,
) -> Result<ExitStatus, std::io::Error> {
    if cmd.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No command provided",
        ));
    }

    let filter_opt = if redact {
        let secret_values: Vec<&str> = env_vars.values().map(|s| s.as_str()).collect();
        build_redaction_filter(&secret_values)
    } else {
        None
    };

    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }

    for (k, v) in &env_vars {
        command.env(k, v);
    }

    #[cfg(target_os = "linux")]
    if no_network {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWNET) != 0
                    && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    if no_network {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "--no-network network namespace isolation is only supported on Linux",
        ));
    }

    if filter_opt.is_some() {
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
    }

    let mut child = command.spawn()?;

    // Scrub secret strings in memory immediately after child process spawn
    for v in env_vars.values_mut() {
        v.zeroize();
    }
    drop(env_vars);

    if let Some((filter, max_pattern_len)) = filter_opt {
        let filter_arc = Arc::new(filter);
        let mut child_stdout = child.stdout.take().expect("Piped child stdout");
        let mut child_stderr = child.stderr.take().expect("Piped child stderr");

        let filter_out = Arc::clone(&filter_arc);
        let t_out = std::thread::spawn(move || {
            let mut out = std::io::stdout();
            let _ = stream_redacted(&mut child_stdout, &mut out, &filter_out, max_pattern_len);
        });

        let filter_err = Arc::clone(&filter_arc);
        let t_err = std::thread::spawn(move || {
            let mut err = std::io::stderr();
            let _ = stream_redacted(&mut child_stderr, &mut err, &filter_err, max_pattern_len);
        });

        let status = child.wait()?;
        let _ = t_out.join();
        let _ = t_err.join();
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        Ok(status)
    } else {
        child.wait()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Spawns the child command with injected environment variables, zeroes out in-memory secrets,
/// captures and redacts stdout and stderr, and returns the exit code and captured streams.
pub fn execute_child_process_capture(
    cmd: &[String],
    mut env_vars: HashMap<String, String>,
    redact: bool,
    no_network: bool,
) -> Result<ChildOutput, std::io::Error> {
    if cmd.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No command provided",
        ));
    }

    let filter_opt = if redact {
        let secret_values: Vec<&str> = env_vars.values().map(|s| s.as_str()).collect();
        build_redaction_filter(&secret_values)
    } else {
        None
    };

    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }

    for (k, v) in &env_vars {
        command.env(k, v);
    }

    #[cfg(target_os = "linux")]
    if no_network {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWNET) != 0
                    && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    if no_network {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "--no-network network namespace isolation is only supported on Linux",
        ));
    }

    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;

    // Scrub secret strings in memory immediately after child process spawn
    for v in env_vars.values_mut() {
        v.zeroize();
    }
    drop(env_vars);

    let mut child_stdout = child.stdout.take().expect("Piped child stdout");
    let mut child_stderr = child.stderr.take().expect("Piped child stderr");

    let (t_out, t_err) = if let Some((filter, max_pattern_len)) = filter_opt {
        let filter_arc = Arc::new(filter);
        let filter_out = Arc::clone(&filter_arc);
        let t_out = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stream_redacted(&mut child_stdout, &mut out, &filter_out, max_pattern_len);
            out
        });

        let filter_err = Arc::clone(&filter_arc);
        let t_err = std::thread::spawn(move || {
            let mut err = Vec::new();
            let _ = stream_redacted(&mut child_stderr, &mut err, &filter_err, max_pattern_len);
            err
        });
        (t_out, t_err)
    } else {
        let t_out = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = child_stdout.read_to_end(&mut out);
            out
        });
        let t_err = std::thread::spawn(move || {
            let mut err = Vec::new();
            let _ = child_stderr.read_to_end(&mut err);
            err
        });
        (t_out, t_err)
    };

    let status = child.wait()?;
    let out_bytes = t_out.join().unwrap_or_default();
    let err_bytes = t_err.join().unwrap_or_default();

    #[cfg(target_os = "linux")]
    let code = status.code().or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|s| 128 + s)
    });
    #[cfg(not(target_os = "linux"))]
    let code = status.code();

    Ok(ChildOutput {
        code,
        stdout: String::from_utf8_lossy(&out_bytes).to_string(),
        stderr: String::from_utf8_lossy(&err_bytes).to_string(),
    })
}

fn json_rpc_error(id: Option<serde_json::Value>, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(serde_json::Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Handles a single MCP JSON-RPC message string and returns an optional JSON-RPC response.
pub fn handle_mcp_request(
    line: &str,
    daemon_sender: &dyn Fn(&serde_json::Value) -> Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Some(json_rpc_error(None, -32700, "Parse error")),
    };

    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

    match method {
        "initialize" => Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "omawarden-broker",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })),
        "notifications/initialized" => None,
        "ping" => Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "tools/list" => Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": "list_available_tokens",
                        "description": "List available credential names and provider tokens in the Bitwarden vault without exposing secret values.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "category": {
                                    "type": "string",
                                    "description": "Optional category or provider filter"
                                }
                            }
                        }
                    },
                    {
                        "name": "exec_with_token",
                        "description": "Execute a command with secrets from vault ciphers injected directly into subprocess environment variables. Output is scrubbed in real-time to redact secrets. Network isolation (--no-network) is optionally supported.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Command and arguments to execute as an array of strings (e.g. [\"python3\", \"script.py\"])"
                                },
                                "items": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Vault item names or references to inject (e.g. [\"OpenAI\", \"GitHub\"])"
                                },
                                "env": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Explicit environment mappings in format VAR=item or VAR=item#field"
                                },
                                "no_network": {
                                    "type": "boolean",
                                    "description": "Disable outbound network access via Linux network namespace jailing"
                                },
                                "no_redact": {
                                    "type": "boolean",
                                    "description": "Disable automatic streaming output redaction (not recommended)"
                                }
                            },
                            "required": ["command"]
                        }
                    }
                ]
            }
        })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(serde_json::json!({}));
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            match tool_name {
                "list_available_tokens" => {
                    let list_req = serde_json::json!({ "action": "list" });
                    let resp = daemon_sender(&list_req);

                    let Some(items_val) = resp else {
                        return Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Error: Failed to communicate with omawarden daemon."
                                    }
                                ],
                                "isError": true
                            }
                        }));
                    };

                    if let Some(err) = items_val.get("error").and_then(|v| v.as_str()) {
                        return Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Error: {}", err)
                                    }
                                ],
                                "isError": true
                            }
                        }));
                    }

                    let items = items_val.as_array();
                    let mut out = String::from("Available vault credentials:\n");
                    if let Some(arr) = items {
                        if arr.is_empty() {
                            out.push_str("  (No vault items found)\n");
                        } else {
                            for item in arr {
                                let name = item
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Unnamed");
                                out.push_str(&format!("- Item: {}\n", name));
                                if let Some(inferred) = infer_provider_env_var(name) {
                                    out.push_str(&format!("    Inferred Env: {}\n", inferred));
                                }
                                if let Some(fields) = item.get("fields").and_then(|v| v.as_array())
                                {
                                    let field_names: Vec<&str> = fields
                                        .iter()
                                        .filter_map(|f| f.get("name").and_then(|v| v.as_str()))
                                        .filter(|n| !n.is_empty())
                                        .collect();
                                    if !field_names.is_empty() {
                                        out.push_str(&format!(
                                            "    Fields: {}\n",
                                            field_names.join(", ")
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        out.push_str("  (No vault items found)\n");
                    }

                    Some(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": out.trim_end().to_string()
                                }
                            ],
                            "isError": false
                        }
                    }))
                }
                "exec_with_token" => {
                    let cmd_arr = arguments.get("command").and_then(|v| v.as_array());
                    let Some(cmd_raw) = cmd_arr else {
                        return Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Error: Missing required parameter 'command'"
                                    }
                                ],
                                "isError": true
                            }
                        }));
                    };

                    let command: Vec<String> = cmd_raw
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect();

                    if command.is_empty() {
                        return Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Error: 'command' array cannot be empty"
                                    }
                                ],
                                "isError": true
                            }
                        }));
                    }

                    let mut effective_items = Vec::new();
                    let mut effective_env = Vec::new();

                    // Read .omawarden.toml in ancestors if present
                    let curr_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                    if let Some(manifest_path) = ProjectManifest::find_in_ancestors(&curr_dir) {
                        if let Ok(manifest) = ProjectManifest::load_from_file(&manifest_path) {
                            for (k, v) in manifest.env {
                                effective_env.push(format!("{}={}", k, v));
                            }
                            effective_items = manifest.items;
                        }
                    }

                    if let Some(items) = arguments.get("items").and_then(|v| v.as_array()) {
                        for itm in items.iter().filter_map(|v| v.as_str()) {
                            if !effective_items.contains(&itm.to_string()) {
                                effective_items.push(itm.to_string());
                            }
                        }
                    }

                    if let Some(env_arr) = arguments.get("env").and_then(|v| v.as_array()) {
                        for e in env_arr.iter().filter_map(|v| v.as_str()) {
                            effective_env.push(e.to_string());
                        }
                    }

                    let no_network = arguments
                        .get("no_network")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let no_redact = arguments
                        .get("no_redact")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let mut env_map = HashMap::new();
                    if !effective_items.is_empty() || !effective_env.is_empty() {
                        let resolve_req = serde_json::json!({
                            "action": "broker_resolve",
                            "items": effective_items,
                            "env": effective_env,
                            "command": command,
                            "interactive": false,
                            "caller_pid": std::process::id(),
                        });

                        let resp = daemon_sender(&resolve_req);
                        let Some(resolve_resp) = resp else {
                            return Some(serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Error: Failed to communicate with omawarden daemon."
                                        }
                                    ],
                                    "isError": true
                                }
                            }));
                        };

                        if let Some(err) = resolve_resp.get("error").and_then(|v| v.as_str()) {
                            return Some(serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("Broker authorization failed: {}", err)
                                        }
                                    ],
                                    "isError": true
                                }
                            }));
                        }

                        if let Some(env_obj) = resolve_resp.get("env").and_then(|v| v.as_object()) {
                            for (k, v) in env_obj {
                                if let Some(val_str) = v.as_str() {
                                    env_map.insert(k.clone(), val_str.to_string());
                                }
                            }
                        }
                    }

                    match execute_child_process_capture(&command, env_map, !no_redact, no_network) {
                        Ok(child_out) => {
                            let exit_code = child_out.code.unwrap_or(-1);
                            let formatted = format!(
                                "Exit code: {}\n\n--- stdout ---\n{}\n--- stderr ---\n{}",
                                exit_code, child_out.stdout, child_out.stderr
                            );
                            Some(serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": formatted
                                        }
                                    ],
                                    "isError": exit_code != 0
                                }
                            }))
                        }
                        Err(e) => Some(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": format!("Execution error: {}", e)
                                    }
                                ],
                                "isError": true
                            }
                        })),
                    }
                }
                _ => Some(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Unknown tool '{}'", tool_name)
                            }
                        ],
                        "isError": true
                    }
                })),
            }
        }
        _ => Some(json_rpc_error(id, -32601, "Method not found")),
    }
}

/// Runs the MCP server reading line-delimited JSON-RPC from `reader` and writing responses to `writer`.
pub fn run_mcp_server<R: std::io::BufRead, W: std::io::Write>(
    reader: R,
    mut writer: W,
    daemon_sender: &dyn Fn(&serde_json::Value) -> Option<serde_json::Value>,
) -> Result<(), std::io::Error> {
    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = handle_mcp_request(trimmed, daemon_sender) {
            let s = serde_json::to_string(&resp)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            writeln!(writer, "{}", s)?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Generates machine-readable Markdown instructions for AI coding assistants and autonomous agents.
pub fn generate_agent_skills_guide(version: &str) -> String {
    format!(
        r#"# Omawarden VaultBroker Agent Guide (v{version})

VaultBroker provides zero-plaintext secret brokering and credential injection for AI coding assistants, autonomous agents, and terminal workflows on Omarchy Linux.

## 1. Core Invariants (Zero-Exposure Contract)

- **No-Read Invariant**: You (the AI assistant) NEVER need to see or handle plaintext secrets (API keys, tokens, passwords). Do NOT attempt to read credentials from the vault or request them from the user.
- **Zero Disk Fallback**: Credentials are NEVER saved to plaintext disk files or `.env` files.
- **Streaming Output Redaction**: All subprocess output on stdout and stderr is scrubbed in real-time. Any occurrences of resolved secret strings are automatically masked with `[REDACTED:VAULT_SECRET]`.
- **Destination Binding**: Subprocess invocations are verified against executable path bindings. Unknown destinations trigger user approval via Wayland overlay cards.

## 2. Command Execution (`omawarden broker exec`)

Execute commands through `omawarden broker exec`. The broker transparently populates environment variables inside the child process without exposing them to your agent context or logs.

```bash
# Auto-inject from project manifest (.omawarden.toml)
omawarden broker exec -- pytest

# Inject specific vault cipher (auto-infers provider variables, e.g. OPENAI_API_KEY)
omawarden broker exec --item OpenAI -- python3 agent.py

# Inject explicit environment variable mapping
omawarden broker exec -e GITHUB_TOKEN=GitHub#token -- gh release create

# Offline execution with Linux network namespace jailing (outbound connections blocked)
omawarden broker exec --no-network -- npm test
```

## 3. Project Manifest (`.omawarden.toml`)

Projects define their required credentials in `.omawarden.toml`. This file contains zero secrets and is safe to commit to version control.

```toml
# Auto-inject standard provider variables (e.g. OPENAI_API_KEY, ANTHROPIC_API_KEY)
items = [
    "OpenAI",
    "Anthropic",
    "Database",
]

# Optional explicit environment variable mappings
[env]
CUSTOM_API_TOKEN = "MyService#api_token"
```

## 4. Legacy Migration (`omawarden broker import`)

When entering a repository containing legacy plaintext `.env` files, run:

```bash
# Preview legacy secrets and planned .omawarden.toml scaffold
omawarden broker import --dry-run

# Import detected keys into Bitwarden vault, scaffold .omawarden.toml, and securely wipe plaintext files
omawarden broker import --yes
```

## 5. Model Context Protocol (MCP) Integration

When running in an MCP-capable environment (Cursor, Claude Code, Windsurf), register the omawarden broker stdio server:

```bash
omawarden broker mcp
```

### Available MCP Tools:
- `list_available_tokens`: Inspect available credential names and field names without exposing secret values.
- `exec_with_token`: Safely execute a command array with credentials injected and streaming output redaction applied.
"#,
        version = version
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_resolve_item_env_from_fields() {
        let item = VaultItem {
            id: "test-id".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-12345", "type": 1 }),
                json!({ "name": "BASE_URL", "value": "https://api.openai.com", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        let env = resolve_item_env(&item);
        assert_eq!(env.get("OPENAI_API_KEY"), Some(&"sk-12345".to_string()));
        assert_eq!(
            env.get("BASE_URL"),
            Some(&"https://api.openai.com".to_string())
        );
    }

    #[test]
    fn test_resolve_broker_env_multi_item_and_explicit_mappings() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-proj-test", "type": 1 }),
                json!({ "name": "ORG_ID", "value": "org-999", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        let login = VaultItem {
            id: "login-1".into(),
            name: "GitHub".into(),
            item_type: 1,
            type_name: "login".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(json!({
                "username": "octocat",
                "password": "ghp_super_secret_token"
            })),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note, login];

        let mappings = vec![
            "GH_TOKEN=GitHub#password".to_string(),
            "GH_USER=GitHub#username".to_string(),
        ];
        let resolved = resolve_broker_env(&vault_mgr, Some("OpenAI"), &mappings).unwrap();

        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"sk-proj-test".to_string())
        );
        assert_eq!(resolved.get("ORG_ID"), Some(&"org-999".to_string()));
        assert_eq!(
            resolved.get("GH_TOKEN"),
            Some(&"ghp_super_secret_token".to_string())
        );
        assert_eq!(resolved.get("GH_USER"), Some(&"octocat".to_string()));
    }

    #[test]
    fn test_execute_child_process_injection_and_exit_code() {
        let mut env = HashMap::new();
        env.insert(
            "INJECTED_TEST_VAR".to_string(),
            "MAGIC_VALUE_42".to_string(),
        );

        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"if [ "$INJECTED_TEST_VAR" = "MAGIC_VALUE_42" ]; then exit 42; else exit 1; fi"#
                .to_string(),
        ];

        let status = execute_child_process(&cmd, env, false, false).unwrap();
        assert_eq!(status.code(), Some(42));
    }

    #[test]
    fn test_execute_child_process_with_redaction() {
        let mut env = HashMap::new();
        env.insert(
            "API_SECRET_KEY".to_string(),
            "sk-proj-secret-99999".to_string(),
        );

        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo "KEY is $API_SECRET_KEY""#.to_string(),
        ];

        let status = execute_child_process(&cmd, env, true, false).unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_stream_redacted_full_and_substring() {
        use aho_corasick::{AhoCorasick, MatchKind};
        let secret = "sk-proj-1234567890abcdef";
        // Build patterns with full secret and substrings >= 6
        let mut patterns = std::collections::HashSet::new();
        patterns.insert(secret.to_string());
        let bytes = secret.as_bytes();
        for len in 6..=bytes.len().min(64) {
            for window in bytes.windows(len) {
                if let Ok(s) = std::str::from_utf8(window) {
                    patterns.insert(s.to_string());
                }
            }
        }
        let mut pattern_list: Vec<String> = patterns.into_iter().collect();
        pattern_list.sort_by_key(|a| std::cmp::Reverse(a.len()));

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&pattern_list)
            .unwrap();

        // Test 1: Full secret
        let input1 = b"LOG: token=sk-proj-1234567890abcdef\n";
        let mut out1 = Vec::new();
        stream_redacted(&input1[..], &mut out1, &ac, 64).unwrap();
        assert_eq!(
            String::from_utf8(out1).unwrap(),
            "LOG: token=[REDACTED:VAULT_SECRET]\n"
        );

        // Test 2: Substring >= 6
        let input2 = b"DEBUG: prefix=sk-proj suffix=0abcdef\n";
        let mut out2 = Vec::new();
        stream_redacted(&input2[..], &mut out2, &ac, 64).unwrap();
        assert_eq!(
            String::from_utf8(out2).unwrap(),
            "DEBUG: prefix=[REDACTED:VAULT_SECRET] suffix=[REDACTED:VAULT_SECRET]\n"
        );

        // Test 3: Substring < 6 (should NOT be redacted)
        let input3 = b"INFO: small=sk-\n";
        let mut out3 = Vec::new();
        stream_redacted(&input3[..], &mut out3, &ac, 64).unwrap();
        assert_eq!(String::from_utf8(out3).unwrap(), "INFO: small=sk-\n");
    }

    #[test]
    fn test_build_redaction_filter_and_heavy_streaming() {
        let secrets = ["sk-proj-heavy-secret-token-123456"];
        let (filter, max_len) = build_redaction_filter(&secrets).expect("Build filter");
        assert_eq!(max_len, "sk-proj-heavy-secret-token-123456".len());

        // Generate 2MB of streaming chunks mixing secrets and padding
        let mut large_input = Vec::new();
        for i in 0..1000 {
            large_input.extend_from_slice(
                format!(
                    "chunk {} containing sk-proj-heavy-secret-token-123456 and padding {:01000}\n",
                    i, 0
                )
                .as_bytes(),
            );
        }

        let mut output = Vec::new();
        stream_redacted(&large_input[..], &mut output, &filter, max_len)
            .expect("Stream redacts without error");

        let out_str = String::from_utf8(output).expect("Valid utf8 output");
        assert!(!out_str.contains("sk-proj-heavy-secret-token-123456"));
        assert!(out_str.contains("[REDACTED:VAULT_SECRET]"));
    }

    #[test]
    fn test_execute_child_process_heavy_streaming_no_deadlock() {
        let mut env = HashMap::new();
        env.insert(
            "MY_HEAVY_SECRET".to_string(),
            "sk-proj-secret-token-xyz".to_string(),
        );

        // Child process outputs 500 lines to stdout and stderr concurrently
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "for i in $(seq 1 500); do echo stdout $i $MY_HEAVY_SECRET; echo stderr $i $MY_HEAVY_SECRET >&2; done".to_string(),
        ];

        let status = execute_child_process(&cmd, env, true, false).unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_execute_child_process_no_network_isolation() {
        // 1. Local execution inside isolated namespace succeeds
        let local_cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo local_ok".to_string(),
        ];
        let status = execute_child_process(&local_cmd, HashMap::new(), false, true).unwrap();
        assert_eq!(status.code(), Some(0));

        // 2. Outbound socket connection inside isolated namespace fails immediately with network unreachable
        let net_cmd = vec![
            "python3".to_string(),
            "-c".to_string(),
            "import socket; socket.create_connection(('1.1.1.1', 80), timeout=1)".to_string(),
        ];
        let net_status = execute_child_process(&net_cmd, HashMap::new(), false, true).unwrap();
        assert!(!net_status.success());
    }

    #[test]
    fn test_destination_policy_matching() {
        let mut policy = BrokerPolicy::default();
        policy.allow_rule(
            "OpenAI",
            "/usr/bin/python3",
            &["-m".to_string(), "my_agent".to_string()],
        );
        policy.allow_rule("*", "/usr/bin/cargo", &[]);

        // Exact match with prefix args
        let cmd1 = vec![
            "/usr/bin/python3".to_string(),
            "-m".to_string(),
            "my_agent".to_string(),
            "--run".to_string(),
        ];
        assert!(policy.is_allowed("OpenAI", &cmd1));

        // Different args: not allowed
        let cmd2 = vec![
            "/usr/bin/python3".to_string(),
            "-c".to_string(),
            "print(1)".to_string(),
        ];
        assert!(!policy.is_allowed("OpenAI", &cmd2));

        // Different cipher: not allowed for python3
        assert!(!policy.is_allowed("GitHub", &cmd1));

        // Wildcard cipher: allowed for cargo
        let cmd3 = vec!["/usr/bin/cargo".to_string(), "test".to_string()];
        assert!(policy.is_allowed("AnySecret", &cmd3));

        // Unregistered binary: not allowed
        let cmd4 = vec![
            "/usr/bin/curl".to_string(),
            "https://example.com".to_string(),
        ];
        assert!(!policy.is_allowed("OpenAI", &cmd4));
    }

    #[test]
    fn test_broker_policy_persistence_and_caller_inspection() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("broker_policy.json");

        let mut policy = BrokerPolicy::default();
        policy.allow_rule("GitHub", "/usr/bin/git", &["push".to_string()]);
        policy.save_to_file(&policy_path).unwrap();

        let loaded = BrokerPolicy::load_from_file(&policy_path);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].cipher_ref, "GitHub");
        assert_eq!(loaded.rules[0].binary_path, "/usr/bin/git");
        assert_eq!(loaded.rules[0].args, vec!["push".to_string()]);

        // Current process caller inspection
        let current_pid = std::process::id();
        let exe = get_caller_exe(current_pid);
        assert!(exe.is_some());
    }

    #[test]
    fn test_broker_approval_state_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("broker_policy.json");

        let state = Arc::new(BrokerApprovalState {
            next_id: std::sync::atomic::AtomicU64::new(1),
            pending: std::sync::Mutex::new(HashMap::new()),
            answered: std::sync::Condvar::new(),
            prompt_timeout: std::time::Duration::from_millis(500),
            policy: std::sync::RwLock::new(BrokerPolicy::default()),
            policy_path: policy_path.clone(),
        });

        let prompt = BrokerPrompt {
            id: 0,
            title: "Authorize Vault Secret".to_string(),
            cipher_ref: "Stripe".to_string(),
            command: "python3 agent.py".to_string(),
            binary_path: "/usr/bin/python3".to_string(),
            caller_app: "alacritty".to_string(),
            caller_pid: 1234,
            args: vec!["agent.py".to_string()],
        };

        // Thread simulating overlay user approval with AllowAlways
        let state_clone = Arc::clone(&state);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let list = state_clone.list_pending();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].cipher_ref, "Stripe");
            let ok = state_clone.reply(list[0].id, BrokerDecision::AllowAlways);
            assert!(ok);
        });

        let decision = state.ask(prompt, |_payload| true);
        assert_eq!(decision, BrokerDecision::AllowAlways);

        // Verify AllowAlways persisted the rule
        let policy = state.policy.read().unwrap();
        assert!(policy.is_allowed(
            "Stripe",
            &["/usr/bin/python3".to_string(), "agent.py".to_string()]
        ));
    }

    #[test]
    fn test_valid_and_prohibited_env_vars() {
        assert!(is_valid_env_var_name("MY_KEY"));
        assert!(is_valid_env_var_name("_SECRET_123"));
        assert!(!is_valid_env_var_name("123_KEY"));
        assert!(!is_valid_env_var_name("KEY=VAL"));
        assert!(!is_valid_env_var_name("KEY-WITH-DASH"));
        assert!(!is_valid_env_var_name(""));

        assert!(is_prohibited_env_var("LD_PRELOAD"));
        assert!(is_prohibited_env_var("ld_preload"));
        assert!(is_prohibited_env_var("PATH"));
        assert!(!is_prohibited_env_var("OPENAI_API_KEY"));
    }

    #[test]
    fn test_resolve_broker_env_rejects_dangerous_and_invalid_names() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-proj-test", "type": 1 }),
                json!({ "name": "LD_PRELOAD", "value": "/tmp/evil.so", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note];

        // 1. Prohibited field in item is filtered out automatically by resolve_item_env
        let resolved = resolve_broker_env(&vault_mgr, Some("OpenAI"), &[]).unwrap();
        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"sk-proj-test".to_string())
        );
        assert!(!resolved.contains_key("LD_PRELOAD"));

        // 2. Explicit mapping trying to inject LD_PRELOAD should error
        let err = resolve_broker_env(
            &vault_mgr,
            None,
            &["LD_PRELOAD=OpenAI#OPENAI_API_KEY".to_string()],
        )
        .unwrap_err();
        assert!(err.contains("Prohibited environment variable name"));

        // 3. Explicit mapping with invalid identifier should error
        let err2 = resolve_broker_env(
            &vault_mgr,
            None,
            &["INVALID-NAME=OpenAI#OPENAI_API_KEY".to_string()],
        )
        .unwrap_err();
        assert!(err2.contains("Invalid environment variable name"));
    }

    #[test]
    fn test_resolve_broker_env_multi_field_requires_field_specifier() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "MultiField".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "FIELD_A", "value": "val-a", "type": 0 }),
                json!({ "name": "FIELD_B", "value": "val-b", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note];

        // Mapping to MultiField with non-matching var_name must fail closed
        let err =
            resolve_broker_env(&vault_mgr, None, &["MY_VAR=MultiField".to_string()]).unwrap_err();
        assert!(err.contains("has multiple fields; please specify the field"));

        // If var_name matches one of the fields, it resolves cleanly
        let resolved =
            resolve_broker_env(&vault_mgr, None, &["FIELD_A=MultiField".to_string()]).unwrap();
        assert_eq!(resolved.get("FIELD_A"), Some(&"val-a".to_string()));
    }

    #[test]
    fn test_provider_pattern_auto_inference() {
        assert_eq!(infer_provider_env_var("OpenAI"), Some("OPENAI_API_KEY"));
        assert_eq!(infer_provider_env_var("openai-dev"), Some("OPENAI_API_KEY"));
        assert_eq!(
            infer_provider_env_var("ChatGPT Pro"),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            infer_provider_env_var("Anthropic Claude"),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(
            infer_provider_env_var("Google Gemini 1.5"),
            Some("GEMINI_API_KEY")
        );
        assert_eq!(infer_provider_env_var("DeepSeek"), Some("DEEPSEEK_API_KEY"));
        assert_eq!(infer_provider_env_var("Groq Cloud"), Some("GROQ_API_KEY"));
        assert_eq!(
            infer_provider_env_var("Mistral AI"),
            Some("MISTRAL_API_KEY")
        );
        assert_eq!(infer_provider_env_var("GitHub Token"), Some("GITHUB_TOKEN"));
        assert_eq!(
            infer_provider_env_var("AWS Root"),
            Some("AWS_SECRET_ACCESS_KEY")
        );
        assert_eq!(
            infer_provider_env_var("Stripe Live"),
            Some("STRIPE_SECRET_KEY")
        );
        assert_eq!(
            infer_provider_env_var("Cloudflare API"),
            Some("CLOUDFLARE_API_TOKEN")
        );
        assert_eq!(
            infer_provider_env_var("Supabase Prod"),
            Some("SUPABASE_KEY")
        );
        assert_eq!(
            infer_provider_env_var("Azure OpenAI"),
            Some("AZURE_OPENAI_API_KEY")
        );
        assert_eq!(
            infer_provider_env_var("PostHog Analytics"),
            Some("POSTHOG_API_KEY")
        );
        assert_eq!(infer_provider_env_var("UnknownCustomItem"), None);

        // Negative tests: words that contain short pattern substrings must NOT false-positive
        assert_eq!(infer_provider_env_var("Reddit"), None);
        assert_eq!(infer_provider_env_var("Lightroom"), None);
        assert_eq!(infer_provider_env_var("Flight Booking"), None);
        assert_eq!(infer_provider_env_var("Lawsuit"), None);
        assert_eq!(infer_provider_env_var("Shift"), None);
        assert_eq!(infer_provider_env_var("Address"), None);
        assert_eq!(infer_provider_env_var("Middle"), None);
        assert_eq!(infer_provider_env_var("Pudding"), None);
    }

    #[test]
    fn test_resolve_item_env_with_provider_auto_inference() {
        let mut login = serde_json::Map::new();
        login.insert("password".into(), json!("sk-proj-test12345678"));

        let item = VaultItem {
            id: "item-openai".into(),
            name: "OpenAI Production".into(),
            item_type: 1,
            type_name: "login".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(json!(login)),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![json!({ "name": "ORG_ID", "value": "org-999", "type": 0 })],
            attachments: vec![],
            search_text: "".into(),
        };

        let env = resolve_item_env(&item);
        assert_eq!(
            env.get("OPENAI_API_KEY"),
            Some(&"sk-proj-test12345678".to_string())
        );
        assert_eq!(env.get("ORG_ID"), Some(&"org-999".to_string()));
    }

    #[test]
    fn test_project_manifest_parse_and_ancestor_search() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project_root = temp_dir.path().join("my_project");
        let sub_dir = project_root.join("src").join("nested");
        std::fs::create_dir_all(&sub_dir).unwrap();

        let manifest_content = r#"
items = ["DeepSeek", "Stripe"]

[env]
OPENAI_API_KEY = "OpenAI"
DATABASE_URL = "ProductionDB#url"
"#;
        let manifest_path = project_root.join(MANIFEST_FILENAME);
        std::fs::write(&manifest_path, manifest_content).unwrap();

        // 1. Test parsing
        let manifest = ProjectManifest::load_from_file(&manifest_path).unwrap();
        assert_eq!(
            manifest.env.get("OPENAI_API_KEY"),
            Some(&"OpenAI".to_string())
        );
        assert_eq!(
            manifest.env.get("DATABASE_URL"),
            Some(&"ProductionDB#url".to_string())
        );
        assert_eq!(
            manifest.items,
            vec!["DeepSeek".to_string(), "Stripe".to_string()]
        );

        // 2. Test ancestor search from deep nested directory
        let found = ProjectManifest::find_in_ancestors(&sub_dir);
        assert_eq!(found, Some(manifest_path));

        // 3. Test [project] section parsing
        let manifest_with_project_section = r#"
[project]
items = ["Anthropic", "Cloudflare"]

[env]
CUSTOM_KEY = "CustomItem"
"#;
        let manifest_path2 = project_root.join("test2.toml");
        std::fs::write(&manifest_path2, manifest_with_project_section).unwrap();
        let manifest2 = ProjectManifest::load_from_file(&manifest_path2).unwrap();
        assert_eq!(
            manifest2.items,
            vec!["Anthropic".to_string(), "Cloudflare".to_string()]
        );
    }

    #[test]
    fn test_resolve_broker_env_ext_manifest_overrides() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let mut login1 = serde_json::Map::new();
        login1.insert("password".into(), json!("inferred-openai-key"));
        let item1 = VaultItem {
            id: "item-1".into(),
            name: "OpenAI".into(),
            item_type: 1,
            type_name: "login".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(json!(login1)),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: "".into(),
        };

        let mut login2 = serde_json::Map::new();
        login2.insert("password".into(), json!("deepseek-key-123"));
        let item2 = VaultItem {
            id: "item-2".into(),
            name: "DeepSeek".into(),
            item_type: 1,
            type_name: "login".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(json!(login2)),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![json!({ "name": "CUSTOM_FIELD", "value": "custom-val", "type": 0 })],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![item1, item2];

        // Explicit override: OPENAI_API_KEY maps to explicit value, overriding inferred
        let explicit = vec!["OPENAI_API_KEY=DeepSeek#CUSTOM_FIELD".to_string()];
        let items = vec!["OpenAI".to_string(), "DeepSeek".to_string()];

        let resolved = resolve_broker_env_ext(&vault_mgr, None, &explicit, &items).unwrap();

        // Inferred from DeepSeek
        assert_eq!(
            resolved.get("DEEPSEEK_API_KEY"),
            Some(&"deepseek-key-123".to_string())
        );
        // Custom field from DeepSeek
        assert_eq!(
            resolved.get("CUSTOM_FIELD"),
            Some(&"custom-val".to_string())
        );
        // Explicit mapping took precedence over OpenAI inferred key!
        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"custom-val".to_string())
        );
    }

    #[test]
    fn test_parse_env_file_content() {
        let content = r#"
# Comment at start
export OPENAI_API_KEY=sk-test123456
ANTHROPIC_API_KEY='sk-ant-abc' # single quote with inline comment
GITHUB_TOKEN="ghp_quoted # with hash"
DATABASE_URL=postgres://user:pass@localhost:5432/mydb # unquoted inline comment
MULTILINE_ESCAPE="line1\nline2\ttab"
EMPTY_VAL=
123_INVALID=ignored
LD_PRELOAD=/evil.so
"#;
        let parsed = parse_env_file_content(content);
        let map: HashMap<String, String> = parsed.into_iter().collect();

        assert_eq!(
            map.get("OPENAI_API_KEY"),
            Some(&"sk-test123456".to_string())
        );
        assert_eq!(
            map.get("ANTHROPIC_API_KEY"),
            Some(&"sk-ant-abc".to_string())
        );
        assert_eq!(
            map.get("GITHUB_TOKEN"),
            Some(&"ghp_quoted # with hash".to_string())
        );
        assert_eq!(
            map.get("DATABASE_URL"),
            Some(&"postgres://user:pass@localhost:5432/mydb".to_string())
        );
        assert_eq!(
            map.get("MULTILINE_ESCAPE"),
            Some(&"line1\nline2\ttab".to_string())
        );
        assert_eq!(map.get("EMPTY_VAL"), Some(&"".to_string()));
        assert!(!map.contains_key("123_INVALID"));
        assert!(!map.contains_key("LD_PRELOAD"));
    }

    #[test]
    fn test_infer_provider_from_env_key() {
        assert_eq!(
            infer_provider_from_env_key("OPENAI_API_KEY"),
            Some("OpenAI")
        );
        assert_eq!(
            infer_provider_from_env_key("ANTHROPIC_API_KEY"),
            Some("Anthropic")
        );
        assert_eq!(infer_provider_from_env_key("GITHUB_TOKEN"), Some("GitHub"));
        assert_eq!(infer_provider_from_env_key("GH_TOKEN"), Some("GitHub"));
        assert_eq!(
            infer_provider_from_env_key("AWS_SECRET_ACCESS_KEY"),
            Some("AWS")
        );
        assert_eq!(
            infer_provider_from_env_key("AWS_ACCESS_KEY_ID"),
            Some("AWS")
        );
        assert_eq!(
            infer_provider_from_env_key("DATABASE_URL"),
            Some("Database")
        );
        assert_eq!(
            infer_provider_from_env_key("POSTGRES_PASSWORD"),
            Some("Database")
        );
        assert_eq!(
            infer_provider_from_env_key("STRIPE_SECRET_KEY"),
            Some("Stripe")
        );
        assert_eq!(
            infer_provider_from_env_key("SENTRY_AUTH_TOKEN"),
            Some("Sentry")
        );
        assert_eq!(infer_provider_from_env_key("DD_API_KEY"), Some("Datadog"));
        assert_eq!(
            infer_provider_from_env_key("DEEPSEEK_API_KEY"),
            Some("DeepSeek")
        );
        assert_eq!(infer_provider_from_env_key("GROQ_API_KEY"), Some("Groq"));
        assert_eq!(infer_provider_from_env_key("CUSTOM_SECRET_APP_KEY"), None);
    }

    #[test]
    fn test_scan_legacy_env_files_and_grouping() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let env_path = root.join(".env");
        let env_local_path = root.join(".env.local");
        let example_path = root.join(".env.example");
        let backup_path = root.join(".env.bak");

        std::fs::write(&env_path, "OPENAI_API_KEY=sk-1\nPORT=3000\n").unwrap();
        std::fs::write(&env_local_path, "PORT=8080\nDATABASE_URL=postgres://\n").unwrap();
        std::fs::write(&example_path, "OPENAI_API_KEY=your_key\n").unwrap();
        std::fs::write(&backup_path, "OLD_KEY=val\n").unwrap();

        let scanned = scan_legacy_env_files(root);
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0].file_name().unwrap(), ".env");
        assert_eq!(scanned[1].file_name().unwrap(), ".env.local");

        let mut all_vars = Vec::new();
        for file in &scanned {
            let content = std::fs::read_to_string(file).unwrap();
            all_vars.extend(parse_env_file_content(&content));
        }

        let groups = group_env_vars_by_provider(&all_vars, "MyService");
        assert!(groups.contains_key("OpenAI"));
        assert!(groups.contains_key("Database"));
        assert!(groups.contains_key("MyService"));

        // PORT was overridden by .env.local to 8080
        let my_service_vars = groups.get("MyService").unwrap();
        let port_tuple = my_service_vars.iter().find(|(k, _)| k == "PORT").unwrap();
        assert_eq!(port_tuple.1, "8080");

        let manifest = scaffold_manifest_from_groups(&groups);
        assert!(manifest.items.contains(&"OpenAI".to_string()));
        assert!(manifest.items.contains(&"Database".to_string()));
        assert!(manifest.items.contains(&"MyService".to_string()));
    }

    #[test]
    fn test_secure_wipe_file_and_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join(".env.secret");
        std::fs::write(&file_path, "SECRET_DATA=top_secret_12345").unwrap();
        assert!(file_path.exists());

        secure_wipe_file(&file_path).unwrap();
        assert!(!file_path.exists());

        // Test ensure_in_gitignore
        let appended = ensure_in_gitignore(tmp.path(), ".env*").unwrap();
        assert!(appended);
        let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
        assert!(gitignore.contains(".env*"));

        // Second time should not duplicate
        let appended_again = ensure_in_gitignore(tmp.path(), ".env*").unwrap();
        assert!(!appended_again);
    }

    #[test]
    fn test_execute_child_process_capture_with_redaction() {
        let mut env = HashMap::new();
        env.insert(
            "API_SECRET_KEY".to_string(),
            "super-secret-capture-token-12345".to_string(),
        );

        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo "OUT is $API_SECRET_KEY"; echo "ERR is $API_SECRET_KEY" >&2"#.to_string(),
        ];

        let out = execute_child_process_capture(&cmd, env, true, false).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.stdout.contains("OUT is [REDACTED:VAULT_SECRET]"));
        assert!(out.stderr.contains("ERR is [REDACTED:VAULT_SECRET]"));
        assert!(!out.stdout.contains("super-secret-capture-token"));
        assert!(!out.stderr.contains("super-secret-capture-token"));
    }

    #[test]
    fn test_mcp_initialize_and_ping() {
        let mock_daemon = |_req: &serde_json::Value| None;

        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = handle_mcp_request(init_req, &mock_daemon).unwrap();
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "omawarden-broker");

        let init_notif = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let resp_notif = handle_mcp_request(init_notif, &mock_daemon);
        assert!(resp_notif.is_none());

        let ping_req = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let resp_ping = handle_mcp_request(ping_req, &mock_daemon).unwrap();
        assert_eq!(resp_ping["id"], 2);
    }

    #[test]
    fn test_mcp_tools_list_strict_no_read_invariant() {
        let mock_daemon = |_req: &serde_json::Value| None;

        let list_req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#;
        let resp = handle_mcp_request(list_req, &mock_daemon).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();

        let tool_names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
            .collect();

        assert!(tool_names.contains(&"list_available_tokens"));
        assert!(tool_names.contains(&"exec_with_token"));

        // Strict No-Read Invariant: no tool exists to extract or read raw secret strings!
        assert!(!tool_names.contains(&"read_secret"));
        assert!(!tool_names.contains(&"get_token"));
        assert!(!tool_names.contains(&"read_token"));
        assert!(!tool_names.contains(&"export_secrets"));
    }

    #[test]
    fn test_mcp_list_available_tokens_does_not_leak_secrets() {
        let raw_password = "super-secret-password-123456";
        let raw_field_val = "super-secret-field-val-654321";

        let mock_daemon = move |req: &serde_json::Value| {
            let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
            if action == "list" {
                Some(serde_json::json!([
                    {
                        "name": "OpenAI",
                        "fields": [],
                        "login": { "password": raw_password }
                    },
                    {
                        "name": "Database",
                        "fields": [
                            { "name": "DATABASE_URL", "value": raw_field_val, "type": 1 }
                        ]
                    }
                ]))
            } else {
                None
            }
        };

        let call_req = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_available_tokens","arguments":{}}}"#;
        let resp = handle_mcp_request(call_req, &mock_daemon).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();

        assert!(text.contains("OpenAI"));
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(text.contains("Database"));
        assert!(text.contains("DATABASE_URL"));

        // Critical security assertion: values MUST NOT appear in the response!
        assert!(!text.contains(raw_password));
        assert!(!text.contains(raw_field_val));
    }

    #[test]
    fn test_mcp_exec_with_token_execution_and_redaction() {
        let secret = "very-confidential-mcp-key-777";
        let mock_daemon = move |req: &serde_json::Value| {
            let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
            if action == "broker_resolve" {
                Some(serde_json::json!({
                    "ok": true,
                    "env": {
                        "CONF_KEY": secret,
                    }
                }))
            } else {
                None
            }
        };

        let call_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "exec_with_token",
                "arguments": {
                    "command": ["sh", "-c", "echo CONF_KEY_IS=$CONF_KEY"],
                    "items": ["ConfItem"],
                }
            }
        })
        .to_string();

        let resp = handle_mcp_request(&call_req, &mock_daemon).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("CONF_KEY_IS=[REDACTED:VAULT_SECRET]"));
        assert!(!text.contains(secret));
    }

    #[test]
    fn test_mcp_run_mcp_server_roundtrip() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}\n";
        let mut output = Vec::new();
        let mock_daemon = |_req: &serde_json::Value| None;

        run_mcp_server(std::io::Cursor::new(input), &mut output, &mock_daemon).unwrap();
        let out_str = String::from_utf8(output).unwrap();
        assert!(out_str.contains("\"id\":10"));
        assert!(out_str.contains("\"result\":{}"));
    }

    #[test]
    fn test_generate_agent_skills_guide() {
        let guide = generate_agent_skills_guide("0.10.1");
        assert!(guide.contains("Omawarden VaultBroker Agent Guide (v0.10.1)"));
        assert!(guide.contains("No-Read Invariant"));
        assert!(guide.contains("omawarden broker exec"));
        assert!(guide.contains(".omawarden.toml"));
        assert!(guide.contains("omawarden broker import"));
        assert!(guide.contains("omawarden broker mcp"));
        assert!(guide.contains("list_available_tokens"));
        assert!(guide.contains("exec_with_token"));
    }
}
