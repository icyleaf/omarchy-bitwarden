use crate::config::ConfigManager;
use chrono::Utc;
use regex::Regex;
use std::env;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl LogLevel {
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        }
    }
}

pub fn sanitize_log_message(msg: &str) -> String {
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    static PWD_RE: OnceLock<Regex> = OnceLock::new();
    static SECRET_RE: OnceLock<Regex> = OnceLock::new();

    let token_re = TOKEN_RE.get_or_init(|| Regex::new(r"(?i)bearer\s+[a-z0-9_\-\.]+").unwrap());
    let pwd_re = PWD_RE.get_or_init(|| {
        Regex::new(r#"(?i)("password"|"masterPasswordHash"|"master_password_hash")\s*:\s*"[^"]*""#)
            .unwrap()
    });
    let secret_re = SECRET_RE.get_or_init(|| {
        Regex::new(r#"(?i)("client_secret"|"clientSecret"|"userKey"|"privateKey")\s*:\s*"[^"]*""#)
            .unwrap()
    });

    let s1 = token_re.replace_all(msg, "Bearer <REDACTED>");
    let s2 = pwd_re.replace_all(&s1, r#"$1:"<REDACTED>""#);
    let s3 = secret_re.replace_all(&s2, r#"$1:"<REDACTED>""#);
    s3.into_owned()
}

pub fn get_active_log_level() -> LogLevel {
    if let Ok(env_lvl) = env::var("OMA_LOG_LEVEL").or_else(|_| env::var("RUST_LOG")) {
        return LogLevel::from_str_loose(&env_lvl);
    }
    let cfg = ConfigManager::new(None).load();
    LogLevel::from_str_loose(&cfg.log_level)
}

pub fn emit_log(level: LogLevel, target: &str, msg: &str) {
    let current_level = get_active_log_level();
    if level <= current_level {
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let sanitized = sanitize_log_message(msg);
        eprintln!("[{}] [{}] [{}] {}", ts, level.as_str(), target, sanitized);
    }
}

#[macro_export]
macro_rules! log_error {
    ($target:expr, $($arg:tt)+) => {
        $crate::logging::emit_log($crate::logging::LogLevel::Error, $target, &format!($($arg)+))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($target:expr, $($arg:tt)+) => {
        $crate::logging::emit_log($crate::logging::LogLevel::Warn, $target, &format!($($arg)+))
    };
}

#[macro_export]
macro_rules! log_info {
    ($target:expr, $($arg:tt)+) => {
        $crate::logging::emit_log($crate::logging::LogLevel::Info, $target, &format!($($arg)+))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($target:expr, $($arg:tt)+) => {
        $crate::logging::emit_log($crate::logging::LogLevel::Debug, $target, &format!($($arg)+))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(LogLevel::from_str_loose("DEBUG"), LogLevel::Debug);
        assert_eq!(LogLevel::from_str_loose("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str_loose("warning"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str_loose("info"), LogLevel::Info);
        assert_eq!(LogLevel::from_str_loose("trace"), LogLevel::Trace);
        assert_eq!(LogLevel::from_str_loose("invalid"), LogLevel::Error);
    }

    #[test]
    fn test_sanitize_log_message() {
        let raw = "Login failed with Bearer eyJhbGciOiJIUzI1NiJ9.test and {\"password\":\"supersecret123\"}";
        let sanitized = sanitize_log_message(raw);
        assert!(!sanitized.contains("supersecret123"));
        assert!(!sanitized.contains("eyJhbGciOiJIUzI1NiJ9.test"));
        assert!(sanitized.contains("Bearer <REDACTED>"));
        assert!(sanitized.contains("\"password\":\"<REDACTED>\""));
    }
}
