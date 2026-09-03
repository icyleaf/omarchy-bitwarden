use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::ValueEnum;
use rand_core::OsRng;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum SshAlgorithm {
    #[default]
    #[value(name = "ed25519", alias = "ED25519")]
    Ed25519,
    #[value(name = "rsa-2048", alias = "rsa2048", alias = "RSA-2048")]
    Rsa2048,
    #[value(name = "rsa-4096", alias = "rsa4096", alias = "RSA-4096")]
    Rsa4096,
    #[value(
        name = "ecdsa-p256",
        alias = "ecdsa256",
        alias = "p256",
        alias = "P-256"
    )]
    EcdsaP256,
    #[value(
        name = "ecdsa-p384",
        alias = "ecdsa384",
        alias = "p384",
        alias = "P-384"
    )]
    EcdsaP384,
}

impl fmt::Display for SshAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "ED25519"),
            Self::Rsa2048 => write!(f, "RSA-2048"),
            Self::Rsa4096 => write!(f, "RSA-4096"),
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::EcdsaP384 => write!(f, "ECDSA-P384"),
        }
    }
}

impl FromStr for SshAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "rsa-2048" | "rsa2048" | "2048" => Ok(Self::Rsa2048),
            "rsa-4096" | "rsa4096" | "4096" | "rsa" => Ok(Self::Rsa4096),
            "ecdsa-p256" | "ecdsa256" | "p256" | "p-256" => Ok(Self::EcdsaP256),
            "ecdsa-p384" | "ecdsa384" | "p384" | "p-384" => Ok(Self::EcdsaP384),
            other => Err(format!(
                "Unknown SSH algorithm '{}'. Supported: ed25519, rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384",
                other
            )),
        }
    }
}

impl SshAlgorithm {
    pub fn default_filename_prefix(&self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::Rsa2048 | Self::Rsa4096 => "id_rsa",
            Self::EcdsaP256 => "id_ecdsa_p256",
            Self::EcdsaP384 => "id_ecdsa_p384",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedSshKey {
    pub algorithm_name: String,
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
}

/// Generates a new SSH keypair with the specified algorithm and optional comment.
pub fn generate_keypair(
    algorithm: SshAlgorithm,
    comment: Option<&str>,
) -> Result<GeneratedSshKey, String> {
    let mut rng = OsRng;

    let mut key = match algorithm {
        SshAlgorithm::Ed25519 => PrivateKey::from(Ed25519Keypair::random(&mut rng)),
        SshAlgorithm::EcdsaP256 => {
            let keypair = EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256)
                .map_err(|e| format!("Failed to generate ECDSA P-256 key: {}", e))?;
            PrivateKey::from(keypair)
        }
        SshAlgorithm::EcdsaP384 => {
            let keypair = EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP384)
                .map_err(|e| format!("Failed to generate ECDSA P-384 key: {}", e))?;
            PrivateKey::from(keypair)
        }
        SshAlgorithm::Rsa2048 => {
            let rsa_key = RsaKeypair::random(&mut rng, 2048)
                .map_err(|e| format!("Failed to generate RSA-2048 key: {}", e))?;
            PrivateKey::from(rsa_key)
        }
        SshAlgorithm::Rsa4096 => {
            let rsa_key = RsaKeypair::random(&mut rng, 4096)
                .map_err(|e| format!("Failed to generate RSA-4096 key: {}", e))?;
            PrivateKey::from(rsa_key)
        }
    };

    if let Some(c) = comment {
        key.set_comment(c);
    }

    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("Failed to format public key: {}", e))?;

    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();

    let private_pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("Failed to format OpenSSH private key: {}", e))?
        .to_string();

    Ok(GeneratedSshKey {
        algorithm_name: algorithm.to_string(),
        private_key: private_pem,
        public_key,
        fingerprint,
    })
}

/// Parses an OpenSSH private key string, deriving the public key and SHA256 fingerprint.
pub fn parse_private_key(raw_pem: &str) -> Result<GeneratedSshKey, String> {
    let trimmed = raw_pem.trim();
    if trimmed.is_empty() {
        return Err("Private key data is empty".to_string());
    }

    let key = PrivateKey::from_openssh(trimmed)
        .map_err(|e| format!("Unable to parse OpenSSH private key: {}", e))?;

    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("Failed to derive public key: {}", e))?;

    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();

    let algo_name = match key.algorithm() {
        Algorithm::Ed25519 => "ED25519".to_string(),
        Algorithm::Rsa { .. } => "RSA".to_string(),
        Algorithm::Ecdsa { curve } => format!(
            "ECDSA-{}",
            match curve {
                EcdsaCurve::NistP256 => "P256",
                EcdsaCurve::NistP384 => "P384",
                EcdsaCurve::NistP521 => "P521",
            }
        ),
        Algorithm::Dsa => "DSA".to_string(),
        _ => "SSH-KEY".to_string(),
    };

    Ok(GeneratedSshKey {
        algorithm_name: algo_name,
        private_key: trimmed.to_string(),
        public_key,
        fingerprint,
    })
}

/// Atomically writes named private key (0600) and public key (0644) files to target directory.
pub fn write_keypair_files_named(
    out_dir: &Path,
    priv_filename: &str,
    pub_filename: &str,
    private_key: &str,
    public_key: &str,
) -> std::io::Result<(PathBuf, PathBuf)> {
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)?;
    }

    let priv_path = out_dir.join(priv_filename);
    let pub_path = out_dir.join(pub_filename);

    // Write private key with strict 0600 permissions
    let mut priv_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&priv_path)?;
    priv_file.write_all(private_key.as_bytes())?;
    if !private_key.ends_with('\n') {
        priv_file.write_all(b"\n")?;
    }
    priv_file.flush()?;

    // Write public key with 0644 permissions
    let mut pub_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&pub_path)?;
    pub_file.write_all(public_key.as_bytes())?;
    if !public_key.ends_with('\n') {
        pub_file.write_all(b"\n")?;
    }
    pub_file.flush()?;

    Ok((priv_path, pub_path))
}

/// Atomically writes private key (0600) and public key (0644) files to target directory using a base name.
pub fn write_keypair_files(
    out_dir: &Path,
    filename_base: &str,
    private_key: &str,
    public_key: &str,
) -> std::io::Result<(PathBuf, PathBuf)> {
    write_keypair_files_named(
        out_dir,
        filename_base,
        &format!("{}.pub", filename_base),
        private_key,
        public_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn test_generate_ed25519_keypair() {
        let res = generate_keypair(SshAlgorithm::Ed25519, Some("user@test")).unwrap();
        assert_eq!(res.algorithm_name, "ED25519");
        assert!(res
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(res.public_key.starts_with("ssh-ed25519 AAA"));
        assert!(res.public_key.contains("user@test"));
        assert!(res.fingerprint.starts_with("SHA256:"));

        // Parse it back
        let parsed = parse_private_key(&res.private_key).unwrap();
        assert_eq!(parsed.fingerprint, res.fingerprint);
        assert_eq!(parsed.public_key, res.public_key);
    }

    #[test]
    fn test_generate_rsa_2048_keypair() {
        let res = generate_keypair(SshAlgorithm::Rsa2048, None).unwrap();
        assert_eq!(res.algorithm_name, "RSA-2048");
        assert!(res
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(res.public_key.starts_with("ssh-rsa AAA"));
        assert!(res.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_generate_ecdsa_p256_keypair() {
        let res = generate_keypair(SshAlgorithm::EcdsaP256, None).unwrap();
        assert_eq!(res.algorithm_name, "ECDSA-P256");
        assert!(res
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(res.public_key.starts_with("ecdsa-sha2-nistp256 AAA"));
        assert!(res.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_write_keypair_files_permissions() {
        let dir = tempdir().unwrap();
        let priv_content =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----";
        let pub_content = "ssh-ed25519 AAAAC3 test@host";

        let (priv_path, pub_path) =
            write_keypair_files(dir.path(), "id_ed25519", priv_content, pub_content).unwrap();

        assert!(priv_path.exists());
        assert!(pub_path.exists());

        let priv_meta = fs::metadata(&priv_path).unwrap();
        let pub_meta = fs::metadata(&pub_path).unwrap();

        let priv_mode = priv_meta.permissions().mode() & 0o777;
        let pub_mode = pub_meta.permissions().mode() & 0o777;

        assert_eq!(priv_mode, 0o600, "Private key must have 0600 permissions");
        assert_eq!(pub_mode, 0o644, "Public key must have 0644 permissions");
    }
}
