import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons as Commons
import "../components" as Components

Item {
  id: testRunner
  width: 800
  height: 600

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  // Light theme colors (Catppuccin Latte)
  readonly property color latteBg: "#eff1f5"
  readonly property color latteFg: "#4c4f69"
  readonly property color latteAccent: "#1e66f5"
  readonly property color latteMuted: "#acb0be"

  Components.VaultItemList {
    id: itemList
    width: 320
    height: 400
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    selectedBackground: Qt.rgba(latteFg.r, latteFg.g, latteFg.b, 0.08)
    selectedText: latteAccent
    items: [
      { id: "1", name: "GitHub", username: "octocat", type_name: "login" },
      { id: "2", name: "AWS", username: "admin", type_name: "login" }
    ]
    selectedIndex: 0
  }

  Components.CategoryTabBar {
    id: catBar
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
  }

  Components.SearchHeader {
    id: searchHeader
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
  }

  Components.FooterBar {
    id: footerBar
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
  }

  function findText(item, text) {
    if (!item) return null
    if (item.children) {
      for (var i = 0; i < item.children.length; i++) {
        var child = item.children[i]
        if (child.hasOwnProperty("text") && child.text === text) {
          return child
        }
        var found = findText(child, text)
        if (found) return found
      }
    }
    return null
  }

  Component.onCompleted: {
    console.log("Running Vault Item List & Search Header Theming Tests...")

    // 1. VaultItemList property contracts
    check(itemList.hasOwnProperty("muted"), "VaultItemList should declare a 'muted' property")
    check(itemList.hasOwnProperty("selectedText"), "VaultItemList should declare a 'selectedText' property")

    // 2. Selected item text must not be hardcoded white (#ffffff)
    var ghText = findText(itemList, "GitHub")
    check(ghText !== null, "Found selected item title text")
    if (ghText) {
      var isWhite = (ghText.color == "#ffffff" || (ghText.color.r === 1 && ghText.color.g === 1 && ghText.color.b === 1))
      check(!isWhite, "Selected item title must not be white (#ffffff) in light theme")
      check(ghText.color == latteAccent, "Selected item title should match selectedText / accent")
    }

    // 3. CategoryTabBar properties
    check(catBar.hasOwnProperty("muted"), "CategoryTabBar should declare a 'muted' property")

    // 4. SearchHeader properties
    check(searchHeader.hasOwnProperty("muted"), "SearchHeader should declare a 'muted' property")

    // 5. FooterBar properties
    check(footerBar.hasOwnProperty("muted"), "FooterBar should declare a 'muted' property")

    if (failures > 0) {
      console.error("TOTAL FAILURES:", failures)
      Qt.exit(1)
    } else {
      console.log("ALL VAULT ITEM LIST & SEARCH HEADER THEMING TESTS PASSED!")
      Qt.exit(0)
    }
  }
}
