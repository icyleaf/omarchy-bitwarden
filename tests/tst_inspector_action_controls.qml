import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components" as Components

// Regression coverage for the Inspector header action controls and the
// CipherFormModal custom-field add buttons:
//  - exactly one favorite indicator (the interactive star, no passive badge)
//  - the delete control uses the same trash glyph as Settings
//  - Edit is an icon button, not a text button
//  - the add Text/Hidden/Boolean buttons are wide enough for their contents
Item {
  id: testRunner
  width: 800
  height: 700

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  readonly property color latteFg: "#4c4f69"
  readonly property color latteAccent: "#1e66f5"
  readonly property color latteMuted: "#acb0be"

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
      favorite: true,
      login: {
        username: "octocat",
        password: "secretpassword",
        uris: [{ uri: "https://github.com" }]
      },
      fields: [],
      attachments: []
    })
  }

  Components.CipherFormModal {
    id: form
    active: true
    cipherType: "login"
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
  }

  function findChildByName(parentItem, name) {
    if (!parentItem || !parentItem.children) return null
    for (var i = 0; i < parentItem.children.length; i++) {
      var child = parentItem.children[i]
      if (child.objectName === name) return child
      var found = findChildByName(child, name)
      if (found) return found
    }
    return null
  }

  function collectTexts(parentItem, out) {
    if (!parentItem || !parentItem.children) return out
    for (var i = 0; i < parentItem.children.length; i++) {
      var child = parentItem.children[i]
      if (child.hasOwnProperty("text")) out.push(child)
      collectTexts(child, out)
    }
    return out
  }

  function countText(parentItem, value) {
    var texts = collectTexts(parentItem, [])
    var count = 0
    for (var i = 0; i < texts.length; i++) {
      if (texts[i].text === value) count++
    }
    return count
  }

  Timer {
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Inspector Action Controls & Custom Field Layout Tests...")

      // 1. One favorite indicator only: the interactive star.
      var favoriteButton = findChildByName(inspector, "favoriteButton")
      check(favoriteButton !== null, "Inspector exposes a favoriteButton control")
      check(countText(inspector, "Favorite") === 0,
            "no passive 'Favorite' badge duplicates the star")
      check(countText(inspector, "\uf005") === 1,
            "a favorited cipher shows exactly one filled star")
      if (favoriteButton) {
        check(favoriteButton.iconText === "\uf005", "favoriteButton renders the filled star when favorited")
      }

      // 2. Delete uses the widely available FA4 trash glyph.
      var deleteButton = findChildByName(inspector, "deleteButton")
      check(deleteButton !== null, "Inspector exposes a deleteButton control")
      if (deleteButton) {
        check(deleteButton.iconText === "\uf1f8", "deleteButton uses the trash glyph")
      }

      // 3. Edit is an icon button, not a text button.
      var editButton = findChildByName(inspector, "editButton")
      check(editButton !== null, "Inspector exposes an editButton control")
      if (editButton) {
        check(editButton.iconText === "\uf044", "editButton uses the pencil glyph")
        check(editButton.tooltip.indexOf("Edit") !== -1, "editButton has an Edit tooltip")
      }
      check(countText(inspector, "Edit") === 0, "no text 'Edit' button remains")

      // 4. Custom-field add buttons must contain their icon + label.
      for (var type = 0; type < 3; type++) {
        var button = findChildByName(form, "addFieldButton_" + type)
        var row = findChildByName(form, "addFieldRow_" + type)
        check(button !== null, "custom field add button " + type + " exists")
        check(row !== null, "custom field add row " + type + " exists")
        if (button && row) {
          check(button.implicitWidth + 0.5 >= row.implicitWidth + 12,
                "custom field add button " + type + " reserves padding around its icon and label (" +
                button.implicitWidth + " >= " + (row.implicitWidth + 12) + ")")
        }
      }

      if (failures > 0) {
        console.error("TOTAL FAILURES:", failures)
        Qt.exit(1)
      } else {
        console.log("ALL INSPECTOR ACTION CONTROL TESTS PASSED!")
        Qt.exit(0)
      }
    }
  }
}
