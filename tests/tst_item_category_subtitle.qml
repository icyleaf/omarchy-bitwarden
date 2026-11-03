import QtQuick
import QtQuick.Controls
import "../components"
import "lib"

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
      Assert.check(itemList.getSubtitle(loginItem) === "octocat", "VaultItemList: login item subtitle is username")
      Assert.check(itemList.getSubtitle(cardItem) === "Visa", "VaultItemList: card item subtitle is card brand")
      Assert.check(itemList.getSubtitle(identityItem) === "user@example.com", "VaultItemList: identity item subtitle is email")
      Assert.check(itemList.getSubtitle(noteItem) === "Secure Note", "VaultItemList: note item subtitle is sub_title")
      Assert.check(itemList.getSubtitle(sshKeyItem) === "ED25519", "VaultItemList: ssh_key item subtitle is key_type")
      Assert.check(itemList.getSubtitle(customItem) === "Custom Subtitle", "VaultItemList: custom item falls back to sub_title")
      Assert.check(itemList.getSubtitle(null) === "", "VaultItemList: null item subtitle is empty string")

      // 2. ItemInspector.getItemCategoryLabel tests (displays category in inspector header)
      Assert.check(itemInspector.getItemCategoryLabel(loginItem) === "Login", "ItemInspector: login item label is 'Login'")
      Assert.check(itemInspector.getItemCategoryLabel(cardItem) === "Card", "ItemInspector: card item label is 'Card'")
      Assert.check(itemInspector.getItemCategoryLabel(identityItem) === "Identity", "ItemInspector: identity item label is 'Identity'")
      Assert.check(itemInspector.getItemCategoryLabel(noteItem) === "Secure Note", "ItemInspector: note item label is 'Secure Note'")
      Assert.check(itemInspector.getItemCategoryLabel(sshKeyItem) === "SSH Key", "ItemInspector: ssh_key item label is 'SSH Key'")
      Assert.check(itemInspector.getItemCategoryLabel(customItem) === "Custom Subtitle", "ItemInspector: custom item falls back to sub_title")
      Assert.check(itemInspector.getItemCategoryLabel(null) === "", "ItemInspector: null item label is empty string")

      // 3. EmptyInspector instantiation test
      Assert.check(emptyInspector !== null, "EmptyInspector: instantiated successfully")

      if (Assert.failures === 0)
        console.log("ALL ITEM CATEGORY SUBTITLE TESTS PASSED!")
      Qt.exit(Assert.exitCode())
    }
  }
}
