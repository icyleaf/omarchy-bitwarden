import pytest
from bitwarden_helper.vault import VaultManager, VaultItem, detect_ssh_key_metadata

MOCK_OPENSSH_NOTE = {
    "id": "ssh-item-1",
    "type": 2,
    "name": "Prod Server SSH Key",
    "notes": """# Production deployment key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD1234567890abcdef...
-----END OPENSSH PRIVATE KEY-----

# Corresponding public key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@prod
""",
    "favorite": True,
    "fields": [
        {"name": "passphrase", "value": "mykeypassword"}
    ]
}

MOCK_RSA_LOGIN = {
    "id": "ssh-item-2",
    "type": 1,
    "name": "GitHub Deploy Key",
    "notes": "Deploy key for backend repo",
    "favorite": False,
    "login": {
        "username": "git",
        "password": ""
    },
    "fields": [
        {"name": "private-key", "value": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"},
        {"name": "public-key", "value": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... deploy@server"}
    ]
}

MOCK_ECDSA_NOTE = {
    "id": "ssh-item-3",
    "type": 2,
    "name": "Cloudflare Tunnel Key",
    "notes": """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBmZ...
-----END EC PRIVATE KEY-----
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY... tunnel@cloud
""",
    "favorite": False,
    "fields": []
}

MOCK_PKCS8_NOTE = {
    "id": "ssh-item-4",
    "type": 2,
    "name": "Generic PKCS8 Key",
    "notes": """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...
-----END PRIVATE KEY-----""",
    "favorite": False,
    "fields": []
}

MOCK_STANDALONE_PUBKEY_NOTE = {
    "id": "ssh-item-5",
    "type": 2,
    "name": "My Work Public Key",
    "notes": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUBKEY123 work@laptop",
    "favorite": False,
    "fields": []
}

MOCK_REGULAR_NOTE = {
    "id": "note-item-1",
    "type": 2,
    "name": "Shopping List",
    "notes": "Apples, Oranges, Bananas",
    "favorite": False,
    "fields": []
}

def test_detect_ssh_key_openssh_multiline_note():
    meta = detect_ssh_key_metadata(MOCK_OPENSSH_NOTE)
    assert meta is not None
    assert meta["is_ssh_key"] is True
    assert "BEGIN OPENSSH PRIVATE KEY" in meta["private_key"]
    assert meta["public_key"] == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@prod"
    assert meta["passphrase"] == "mykeypassword"
    assert meta["key_type"] == "ED25519"

def test_detect_ssh_key_rsa_login():
    meta = detect_ssh_key_metadata(MOCK_RSA_LOGIN)
    assert meta is not None
    assert meta["is_ssh_key"] is True
    assert "BEGIN RSA PRIVATE KEY" in meta["private_key"]
    assert "ssh-rsa" in meta["public_key"]
    assert meta["key_type"] == "RSA"

def test_detect_ssh_key_ecdsa_note():
    meta = detect_ssh_key_metadata(MOCK_ECDSA_NOTE)
    assert meta is not None
    assert meta["is_ssh_key"] is True
    assert "BEGIN EC PRIVATE KEY" in meta["private_key"]
    assert "ecdsa-sha2-nistp256" in meta["public_key"]
    assert meta["key_type"] == "ECDSA"

def test_detect_ssh_key_pkcs8_note():
    meta = detect_ssh_key_metadata(MOCK_PKCS8_NOTE)
    assert meta is not None
    assert meta["is_ssh_key"] is True
    assert "BEGIN PRIVATE KEY" in meta["private_key"]
    assert meta["key_type"] == "PKCS8"

def test_detect_ssh_key_standalone_pubkey():
    meta = detect_ssh_key_metadata(MOCK_STANDALONE_PUBKEY_NOTE)
    assert meta is not None
    assert meta["is_ssh_key"] is True
    assert "ssh-ed25519" in meta["public_key"]
    assert meta["private_key"] is None
    assert meta["key_type"] == "ED25519"

def test_detect_non_ssh_note():
    meta = detect_ssh_key_metadata(MOCK_REGULAR_NOTE)
    assert meta is None

def test_vault_manager_parses_ssh_keys():
    vm = VaultManager(bw_path="bw")
    items = vm.parse_raw_items([
        MOCK_OPENSSH_NOTE,
        MOCK_RSA_LOGIN,
        MOCK_ECDSA_NOTE,
        MOCK_PKCS8_NOTE,
        MOCK_STANDALONE_PUBKEY_NOTE,
        MOCK_REGULAR_NOTE
    ])
    
    ssh_items = [i for i in items if i.type_name == "ssh_key"]
    assert len(ssh_items) == 5
    
    prod_key = next(i for i in items if i.id == "ssh-item-1")
    assert prod_key.type_name == "ssh_key"
    assert "SSH Key" in prod_key.sub_title
    assert prod_key.ssh_key is not None
    assert prod_key.ssh_key["passphrase"] == "mykeypassword"
    
    regular = next(i for i in items if i.id == "note-item-1")
    assert regular.type_name == "note"
