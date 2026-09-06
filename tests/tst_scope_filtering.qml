import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner
  width: 400
  height: 300

  property var mockItems: [
    {
      id: "item-1",
      name: "GitHub Personal",
      type_name: "login",
      organization_id: null,
      organization_name: null,
      folder_id: "dev-folder",
      folder_name: "Development",
      login: { username: "octocat" }
    },
    {
      id: "item-2",
      name: "AWS Work",
      type_name: "login",
      organization_id: "org-1",
      organization_name: "Acme Corp",
      folder_id: "cloud-folder",
      folder_name: "Cloud",
      login: { username: "workuser" }
    },
    {
      id: "item-3",
      name: "Personal Credit Card",
      type_name: "card",
      organization_id: null,
      organization_name: null,
      folder_id: null,
      folder_name: null
    },
    {
      id: "item-4",
      name: "Work Server SSH Key",
      type_name: "ssh_key",
      organization_id: "org-1",
      organization_name: "Acme Corp",
      folder_id: "dev-folder",
      folder_name: "Development"
    },
    {
      id: "item-5",
      name: "Family Vault Streaming",
      type_name: "login",
      organization_id: "org-2",
      organization_name: "Family",
      folder_id: null,
      folder_name: null
    }
  ]

  property string searchQuery: ""
  property string activeCategory: "all"
  property string activeVaultScope: "all"
  property string activeFolderScope: "all"

  function filterItems() {
    var q = searchQuery.trim().toLowerCase()
    var cat = activeCategory
    var vs = activeVaultScope
    var fs = activeFolderScope

    return mockItems.filter(function(item) {
      // 1. Vault Scope Filter
      if (vs === "personal") {
        if (item.organization_id) return false
      } else if (vs !== "all") {
        if (item.organization_id !== vs && item.organization_name !== vs) return false
      }

      // 2. Folder Scope Filter
      if (fs === "none") {
        if (item.folder_id || item.folder_name) return false
      } else if (fs !== "all") {
        if (item.folder_id !== fs && item.folder_name !== fs) return false
      }

      // 3. Category Filter
      if (cat !== "all" && item.type_name !== cat && !(cat === "ssh_key" && item.category === "ssh_key")) return false

      // 4. Query Filter
      if (q === "") return true

      var nameMatch = item.name && item.name.toLowerCase().indexOf(q) !== -1
      var userMatch = item.login && item.login.username && item.login.username.toLowerCase().indexOf(q) !== -1
      return nameMatch || userMatch
    })
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

  Component.onCompleted: {
    console.log("Running Scope Filtering Automated Tests...")

    // Test 1: Default (all scopes) -> all 5 items
    var resAll = filterItems()
    assert(resAll.length === 5, "Default filter returns all items (5)")

    // Test 2: Vault Scope = personal -> item-1 and item-3 (2 items)
    activeVaultScope = "personal"
    var resPersonal = filterItems()
    assert(resPersonal.length === 2, "Personal vault scope returns 2 items")
    assert(resPersonal[0].id === "item-1" && resPersonal[1].id === "item-3", "Personal vault scope returned correct items")

    // Test 3: Vault Scope = Acme Corp (org-1) -> item-2 and item-4 (2 items)
    activeVaultScope = "org-1"
    var resOrg1 = filterItems()
    assert(resOrg1.length === 2, "Acme Corp org returns 2 items")
    assert(resOrg1[0].id === "item-2" && resOrg1[1].id === "item-4", "Acme Corp org returned correct items")

    // Test 4: Reset Vault Scope back to all
    activeVaultScope = "all"
    assert(filterItems().length === 5, "Resetting Vault Scope restores 5 items")

    // Test 5: Folder Scope = Development (dev-folder) -> item-1 and item-4 (2 items)
    activeFolderScope = "dev-folder"
    var resDevFolder = filterItems()
    assert(resDevFolder.length === 2, "Development folder returns 2 items")
    assert(resDevFolder[0].id === "item-1" && resDevFolder[1].id === "item-4", "Development folder returned correct items")

    // Test 6: Folder Scope = none -> item-3 and item-5 (2 items)
    activeFolderScope = "none"
    var resNoFolder = filterItems()
    assert(resNoFolder.length === 2, "No folder returns 2 items")
    assert(resNoFolder[0].id === "item-3" && resNoFolder[1].id === "item-5", "No folder returned correct items")

    // Test 7: 4-Way Conjunction:
    // Vault Scope = org-1 (Acme Corp)
    // Folder Scope = dev-folder (Development)
    // Category = ssh_key
    // Query = "server"
    activeVaultScope = "org-1"
    activeFolderScope = "dev-folder"
    activeCategory = "ssh_key"
    searchQuery = "server"
    var resConjunction = filterItems()
    assert(resConjunction.length === 1, "4-way conjunction returns 1 item")
    assert(resConjunction[0].id === "item-4", "4-way conjunction correctly matched Work Server SSH Key")

    // Test 8: 4-Way Conjunction mismatch (Category mismatch)
    activeCategory = "login"
    assert(filterItems().length === 0, "4-way conjunction with mismatch returns 0 items")

    // Test 9: Reset filters
    searchQuery = ""
    activeCategory = "all"
    activeVaultScope = "all"
    activeFolderScope = "all"
    assert(filterItems().length === 5, "Full reset restores all 5 items")

    console.log("All Scope Filtering tests passed successfully!")
    Qt.quit()
  }
}
