import QtQuick
import QtQuick.Controls
import "../components"

ApplicationWindow {
  id: testRunner
  visible: true
  width: 400
  height: 300

  VaultItemList {
    id: itemList
  }

  ItemInspector {
    id: itemInspector
  }

  EmptyInspector {
    id: emptyInspector
  }

  function assert(condition, message) {
    if (!condition) {
      console.error("ASSERTION FAILED: " + message)
      Qt.quit()
      throw new Error("Assertion failed: " + message)
    } else {
      console.log("PASS: " + message)
    }
  }

  Timer {
    id: testTimer
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Item Category Subtitle Automated Tests...")

      var loginItem = {
        name: "GitHub",
        type_name: "login",
        login: { username: "octocat" },
        sub_title: "octocat"
      }
      var cardItem = {
        name: "Bank Card",
        type_name: "card",
        card: { brand: "Visa" },
        sub_title: "Visa •••• 4444"
      }
      var identityItem = {
        name: "Passport",
        type_name: "identity",
        identity: { email: "user@example.com" },
        sub_title: "user@example.com"
      }
      var noteItem = {
        name: "Secret Recipe",
        type_name: "note",
        sub_title: "Secure Note"
      }
      var sshKeyItem = {
        name: "Deploy Key",
        type_name: "ssh_key",
        ssh_key: { key_type: "ED25519" },
        sub_title: "SSH Key (ED25519)"
      }
      var customItem = {
        name: "Custom Data",
        type_name: "custom_type",
        sub_title: "Custom Subtitle"
      }

      // 1. VaultItemList.getSubtitle tests (kept as username / brand / email in list)
      assert(itemList.getSubtitle(loginItem) === "octocat", "VaultItemList: login item subtitle is username")
      assert(itemList.getSubtitle(cardItem) === "Visa", "VaultItemList: card item subtitle is card brand")
      assert(itemList.getSubtitle(identityItem) === "user@example.com", "VaultItemList: identity item subtitle is email")
      assert(itemList.getSubtitle(noteItem) === "Secure Note", "VaultItemList: note item subtitle is sub_title")
      assert(itemList.getSubtitle(sshKeyItem) === "ED25519", "VaultItemList: ssh_key item subtitle is key_type")
      assert(itemList.getSubtitle(customItem) === "Custom Subtitle", "VaultItemList: custom item falls back to sub_title")
      assert(itemList.getSubtitle(null) === "", "VaultItemList: null item subtitle is empty string")

      // 2. ItemInspector.getItemCategoryLabel tests (displays category in inspector header)
      assert(itemInspector.getItemCategoryLabel(loginItem) === "Login", "ItemInspector: login item label is 'Login'")
      assert(itemInspector.getItemCategoryLabel(cardItem) === "Card", "ItemInspector: card item label is 'Card'")
      assert(itemInspector.getItemCategoryLabel(identityItem) === "Identity", "ItemInspector: identity item label is 'Identity'")
      assert(itemInspector.getItemCategoryLabel(noteItem) === "Secure Note", "ItemInspector: note item label is 'Secure Note'")
      assert(itemInspector.getItemCategoryLabel(sshKeyItem) === "SSH Key", "ItemInspector: ssh_key item label is 'SSH Key'")
      assert(itemInspector.getItemCategoryLabel(customItem) === "Custom Subtitle", "ItemInspector: custom item falls back to sub_title")
      assert(itemInspector.getItemCategoryLabel(null) === "", "ItemInspector: null item label is empty string")

      // 3. EmptyInspector instantiation test
      assert(emptyInspector !== null, "EmptyInspector: instantiated successfully")

      console.log("ALL ITEM CATEGORY SUBTITLE TESTS PASSED!")
      Qt.quit()
    }
  }
}
