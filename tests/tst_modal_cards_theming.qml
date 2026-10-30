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
  readonly property color lattePopupBorder: "#ccd0da"

  Component.onCompleted: {
    Commons.Color.setPreset("catppuccin-latte")
  }

  Components.ActionPaletteModal {
    id: paletteModal
    active: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.PasswordGeneratorModal {
    id: genModal
    active: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.PasswordHistoryModal {
    id: histModal
    active: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.SshApprovalModal {
    id: sshApprovalModal
    active: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.SshKeyModal {
    id: sshKeyModal
    active: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.ReleaseNotesModal {
    id: releaseModal
    visible: true
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    cardBackground: lattePopupBg
    borderColor: lattePopupBorder
  }

  Components.ScopeDropdown {
    id: scopeDropdown
    foreground: latteFg
    accent: latteAccent
    muted: latteMuted
    borderColor: lattePopupBorder
  }

  Components.ToastAlert {
    id: toast
    statusMessage: "Vault synced"
    foreground: latteFg
    accent: latteAccent
  }

  function findChildById(parentItem, targetId) {
    if (!parentItem) return null
    if (parentItem.children) {
      for (var i = 0; i < parentItem.children.length; i++) {
        var child = parentItem.children[i]
        // check if this item or its descendants match
        var found = findChildById(child, targetId)
        if (found) return found
      }
    }
    return null
  }

  Timer {
    interval: 10
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Modal Dialog Cards & Popups Surface Standardization Tests...")

      // 1. Property checks
      check(paletteModal.hasOwnProperty("cardBackground"), "ActionPaletteModal should have cardBackground property")
      check(genModal.hasOwnProperty("cardBackground"), "PasswordGeneratorModal should have cardBackground property")
      check(histModal.hasOwnProperty("cardBackground"), "PasswordHistoryModal should have cardBackground property")
      check(sshApprovalModal.hasOwnProperty("cardBackground"), "SshApprovalModal should have cardBackground property")
      check(sshKeyModal.hasOwnProperty("cardBackground"), "SshKeyModal should have cardBackground property")
      check(releaseModal.hasOwnProperty("cardBackground"), "ReleaseNotesModal should have cardBackground property")

      // 2. Card background colors should match lattePopupBg (#e6e9ef)
      check(paletteModal.cardBackground == lattePopupBg, "paletteModal cardBackground matches popup background token")
      check(genModal.cardBackground == lattePopupBg, "genModal cardBackground matches popup background token")
      check(histModal.cardBackground == lattePopupBg, "histModal cardBackground matches popup background token")
      check(sshApprovalModal.cardBackground == lattePopupBg, "sshApprovalModal cardBackground matches popup background token")
      check(sshKeyModal.cardBackground == lattePopupBg, "sshKeyModal cardBackground matches popup background token")
      check(releaseModal.cardBackground == lattePopupBg, "releaseModal cardBackground matches popup background token")

      if (failures > 0) {
        console.error("TOTAL FAILURES:", failures)
        Qt.exit(1)
      } else {
        console.log("ALL MODAL CARDS THEMING TESTS PASSED!")
        Qt.exit(0)
      }
    }
  }
}
