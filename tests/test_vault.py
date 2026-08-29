import json
from unittest.mock import patch, MagicMock
import pytest
from bitwarden_helper.vault import VaultManager, VaultItem

MOCK_VAULT_ITEMS = [
    {
        "id": "item-1",
        "type": 1,
        "name": "GitHub Account",
        "notes": "Developer portal",
        "favorite": True,
        "login": {
            "username": "icyleaf",
            "password": "secretpassword1",
            "uris": [{"uri": "https://github.com"}]
        },
        "fields": []
    },
    {
        "id": "item-2",
        "type": 1,
        "name": "Google Workspace",
        "notes": "Work email",
        "favorite": False,
        "login": {
            "username": "icyleaf@google.com",
            "password": "secretpassword2",
            "uris": [{"uri": "https://accounts.google.com"}]
        },
        "fields": []
    },
    {
        "id": "item-3",
        "type": 3,
        "name": "Personal Visa",
        "notes": "Bank card",
        "favorite": False,
        "card": {
            "cardholderName": "Icyleaf",
            "brand": "Visa",
            "number": "4111111111111234",
            "expMonth": "08",
            "expYear": "2028",
            "code": "999"
        },
        "fields": []
    },
    {
        "id": "item-4",
        "type": 2,
        "name": "Server Recovery Keys",
        "notes": "Backup codes for production servers: 1234-5678-9012",
        "favorite": True,
        "fields": []
    },
    {
        "id": "item-5",
        "type": 4,
        "name": "Tax Identity",
        "notes": "Personal identification",
        "favorite": False,
        "identity": {
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com",
            "phone": "+1-555-0199"
        },
        "fields": []
    }
]

def test_parse_vault_items():
    vm = VaultManager(bw_path="bw")
    parsed = vm.parse_raw_items(MOCK_VAULT_ITEMS)
    assert len(parsed) == 5
    
    # Login item
    github = next(i for i in parsed if i.id == "item-1")
    assert github.type_name == "login"
    assert github.sub_title == "icyleaf"
    assert github.favorite is True
    
    # Card item
    card = next(i for i in parsed if i.id == "item-3")
    assert card.type_name == "card"
    assert "1234" in card.sub_title
    
    # Identity item
    ident = next(i for i in parsed if i.id == "item-5")
    assert ident.type_name == "identity"
    assert "john.doe@example.com" in ident.sub_title

def test_search_by_keyword():
    vm = VaultManager(bw_path="bw")
    items = vm.parse_raw_items(MOCK_VAULT_ITEMS)
    
    # Search by name
    results = vm.search(items, query="github")
    assert len(results) == 1
    assert results[0].id == "item-1"
    
    # Search by subtitle (username/email)
    results = vm.search(items, query="john.doe")
    assert len(results) == 1
    assert results[0].id == "item-5"
    
    # Search by notes
    results = vm.search(items, query="recovery")
    assert len(results) == 1
    assert results[0].id == "item-4"

def test_search_with_category_filter():
    vm = VaultManager(bw_path="bw")
    items = vm.parse_raw_items(MOCK_VAULT_ITEMS)
    
    # Category filter: card
    card_results = vm.search(items, query="", category="card")
    assert len(card_results) == 1
    assert card_results[0].type_name == "card"
    
    # Category filter: login
    login_results = vm.search(items, query="", category="login")
    assert len(login_results) == 2

def test_search_ranking_exact_match_and_favorite():
    vm = VaultManager(bw_path="bw")
    items = vm.parse_raw_items(MOCK_VAULT_ITEMS)
    
    # When query is empty, favorites should appear first
    all_items = vm.search(items, query="")
    assert all_items[0].favorite is True
    assert all_items[1].favorite is True
    assert all_items[2].favorite is False

def test_vault_sync_execution():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Syncing complete.", stderr="")
        vm = VaultManager(bw_path="bw")
        ok = vm.sync(session="test_session_123")
        assert ok is True
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert "sync" in args[0]
        assert "--session" not in args[0]
        assert "test_session_123" not in args[0]
        assert kwargs.get("env", {}).get("BW_SESSION") == "test_session_123"

def test_vault_fetch_items_env_isolation():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='[{"id": "item1", "name": "Item 1", "type": 1}]', stderr="")
        vm = VaultManager(bw_path="bw", max_output_bytes=1024)
        items = vm.fetch_items(session="secret_vault_session")
        assert len(items) == 1
        assert items[0].id == "item1"
        args, kwargs = mock_run.call_args
        assert "list" in args[0] and "items" in args[0]
        assert "--session" not in args[0]
        assert "secret_vault_session" not in args[0]
        assert kwargs.get("env", {}).get("BW_SESSION") == "secret_vault_session"
