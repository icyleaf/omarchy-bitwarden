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
  readonly property color lattePopupBg: "#e6e9ef"

  Components.ItemInspector {
    id: inspector
    width: 400
    height: 600
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    item: ({
      id: "test-login",
      name: "GitHub",
      type_name: "login",
      login: {
        username: "octocat",
        password: "secretpassword",
        totp: "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP",
        has_totp: true,
        uris: [{ uri: "https://github.com" }]
      },
      notes: "Some private notes",
      fields: [{ name: "Pin", value: "1234", type: 1 }],
      attachments: [{ fileName: "key.txt", size: 1024 }],
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-02T00:00:00Z"
    })
  }

  Components.EmptyInspector {
    id: emptyInspector
    width: 400
    height: 600
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
  }

  function findTextByContent(item, text) {
    if (!item) return null
    if (item.children) {
      for (var i = 0; i < item.children.length; i++) {
        var child = item.children[i]
        if (child.hasOwnProperty("text") && child.text === text) {
          return child
        }
        var found = findTextByContent(child, text)
        if (found) return found
      }
    }
    return null
  }

  Component.onCompleted: {
    console.log("Running ItemInspector & EmptyInspector Theming Tests...")

    // 1. Property contract checks
    check(inspector.hasOwnProperty("muted"), "ItemInspector should declare a 'muted' property")
    check(emptyInspector.hasOwnProperty("muted"), "EmptyInspector should declare a 'muted' property")

    // 2. Field labels in ItemInspector should match muted
    var userLabel = findTextByContent(inspector, "Username")
    check(userLabel !== null, "Found 'Username' field label")
    if (userLabel) {
      check(userLabel.color == latteMuted, "'Username' label color should match muted token (latteMuted)")
    }

    var passLabel = findTextByContent(inspector, "Password")
    check(passLabel !== null, "Found 'Password' field label")
    if (passLabel) {
      check(passLabel.color == latteMuted, "'Password' label color should match muted token (latteMuted)")
    }

    var notesLabel = findTextByContent(inspector, "Notes")
    check(notesLabel !== null, "Found 'Notes' field label")
    if (notesLabel) {
      check(notesLabel.color == latteMuted, "'Notes' label color should match muted token (latteMuted)")
    }

    // 3. EmptyInspector shortcuts header and descriptions
    var shortcutsHeader = findTextByContent(emptyInspector, "KEYBOARD SHORTCUTS")
    check(shortcutsHeader !== null, "Found 'KEYBOARD SHORTCUTS' header")
    if (shortcutsHeader) {
      check(shortcutsHeader.color == latteMuted, "Shortcuts header color should match muted token")
    }

    var tabDesc = findTextByContent(emptyInspector, "Switch Category Filter (Logins, Cards, Secure Note, SSH)")
    check(tabDesc !== null, "Found shortcut description text")
    if (tabDesc) {
      check(tabDesc.color == latteMuted, "Shortcut description text should match muted token")
    }

    if (failures > 0) {
      console.error("TOTAL FAILURES:", failures)
      Qt.exit(1)
    } else {
      console.log("ALL ITEM INSPECTOR THEMING TESTS PASSED!")
      Qt.exit(0)
    }
  }
}
