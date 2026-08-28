import pytest
from bitwarden_helper.vault import VaultItem

def get_primary_action(item: VaultItem) -> dict:
    """Helper to determine primary action payload based on item type."""
    if item.type_name == "login":
        if item.login and item.login.get("password"):
            return {"action": "copy_password", "value": item.login["password"], "sensitive": True}
        elif item.login and item.login.get("username"):
            return {"action": "copy_username", "value": item.login["username"], "sensitive": False}
    elif item.type_name == "card":
        if item.card and item.card.get("number"):
            return {"action": "copy_card_number", "value": item.card["number"], "sensitive": True}
    elif item.type_name == "ssh_key":
        if item.ssh_key and item.ssh_key.get("private_key"):
            return {"action": "copy_private_key", "value": item.ssh_key["private_key"], "sensitive": True}
        elif item.ssh_key and item.ssh_key.get("public_key"):
            return {"action": "copy_public_key", "value": item.ssh_key["public_key"], "sensitive": False}
    elif item.type_name == "note":
        return {"action": "copy_notes", "value": item.notes or "", "sensitive": False}
    elif item.type_name == "identity":
        if item.identity and item.identity.get("email"):
            return {"action": "copy_email", "value": item.identity["email"], "sensitive": False}
    return {"action": "none", "value": None, "sensitive": False}

def test_primary_action_login():
    item = VaultItem(
        id="1", name="GitHub", type=1, type_name="login", sub_title="user1",
        login={"username": "user1", "password": "pass123"}
    )
    act = get_primary_action(item)
    assert act["action"] == "copy_password"
    assert act["value"] == "pass123"
    assert act["sensitive"] is True

def test_primary_action_card():
    item = VaultItem(
        id="2", name="Visa Card", type=3, type_name="card", sub_title="Visa",
        card={"number": "4111222233334444", "code": "123"}
    )
    act = get_primary_action(item)
    assert act["action"] == "copy_card_number"
    assert act["value"] == "4111222233334444"
    assert act["sensitive"] is True

def test_primary_action_ssh_key():
    item = VaultItem(
        id="3", name="SSH Deploy", type=5, type_name="ssh_key", sub_title="SSH Key",
        ssh_key={"private_key": "PRIV_KEY_BLOCK", "public_key": "PUB_KEY_BLOCK"}
    )
    act = get_primary_action(item)
    assert act["action"] == "copy_private_key"
    assert act["value"] == "PRIV_KEY_BLOCK"
    assert act["sensitive"] is True
