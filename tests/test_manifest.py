import json
from pathlib import Path

def test_manifest_structure():
    manifest_path = Path(__file__).parent.parent / "manifest.json"
    assert manifest_path.exists()
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    assert data["schemaVersion"] == 1
    assert data["id"] == "icyleaf.bitwarden"
    assert "overlay" in data["kinds"]
    assert data["activation"] == "on-demand"
    assert data["entryPoints"]["overlay"] == "OmarchyBitwarden.qml"
