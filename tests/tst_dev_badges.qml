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

  function findChildByObjectName(parent, objName) {
    if (!parent) return null
    for (var i = 0; i < parent.children.length; i++) {
      var child = parent.children[i]
      if (child.objectName === objName) return child
      var res = findChildByObjectName(child, objName)
      if (res) return res
    }
    return null
  }

  Components.FooterBar {
    id: footer
    width: 600
    height: 40
    overlayVersion: "0.14.0"
    backendVersion: "0.11.0"
    isEngineInstalled: true
    updateAvailable: false
  }

  Components.SettingsModal {
    id: settingsModal
    width: 600
    height: 500
    overlayVersion: "0.14.0"
    cliHealth: ({ installed: true, version: "0.11.0" })
  }

  Component.onCompleted: {
    console.log("Running Dev Badges Visibility Tests...")

    var footerOverlayBadge = findChildByObjectName(footer, "overlayDevBadge")
    var footerBackendBadge = findChildByObjectName(footer, "backendDevBadge")
    var settingsOverlayBadge = findChildByObjectName(settingsModal, "overlayDevBadge")
    var settingsEngineBadge = findChildByObjectName(settingsModal, "engineDevBadge")

    check(footerOverlayBadge !== null, "Footer overlayDevBadge found")
    check(footerBackendBadge !== null, "Footer backendDevBadge found")
    check(settingsOverlayBadge !== null, "SettingsModal overlayDevBadge found")
    check(settingsEngineBadge !== null, "SettingsModal engineDevBadge found")

    // 1. Initial stable versions -> no dev badges visible
    footer.overlayVersion = "0.14.0"
    footer.backendVersion = "0.11.0"
    check(footerOverlayBadge.visible === false, "Footer overlay DEV badge hidden for stable")
    check(footerBackendBadge.visible === false, "Footer backend DEV badge hidden for stable")

    // 2. Set overlayVersion to dev -> overlay badge becomes visible
    footer.overlayVersion = "0.15.0-dev"
    check(footerOverlayBadge.visible === true, "Footer overlay DEV badge visible for 0.15.0-dev")
    check(footerBackendBadge.visible === false, "Footer backend DEV badge still hidden")

    // 3. Reset overlay, set backendVersion to dev -> backend badge visible
    footer.overlayVersion = "0.14.0"
    footer.backendVersion = "0.12.0-dev"
    check(footerOverlayBadge.visible === false, "Footer overlay DEV badge hidden")
    check(footerBackendBadge.visible === true, "Footer backend DEV badge visible for 0.12.0-dev")

    // 4. Dot dev format (0.12.0.dev) -> backend badge visible
    footer.backendVersion = "0.12.0.dev"
    check(footerBackendBadge.visible === true, "Footer backend DEV badge visible for 0.12.0.dev")

    // 5. SettingsModal Header DEV badge
    settingsModal.overlayVersion = "0.14.0"
    settingsModal.cliHealth = ({ installed: true, version: "0.11.0" })
    check(settingsOverlayBadge.visible === false, "SettingsModal overlay DEV badge hidden for stable")
    check(settingsEngineBadge.visible === false, "SettingsModal engine DEV badge hidden for stable")

    settingsModal.overlayVersion = "0.15.0-dev"
    check(settingsOverlayBadge.visible === true, "SettingsModal overlay DEV badge visible for 0.15.0-dev")

    // 6. SettingsModal Engine DEV badge
    settingsModal.overlayVersion = "0.14.0"
    settingsModal.cliHealth = ({ installed: true, version: "0.12.0-dev" })
    check(settingsEngineBadge.visible === true, "SettingsModal engine DEV badge visible for 0.12.0-dev")

    settingsModal.cliHealth = ({ installed: true, version: "0.12.0.dev" })
    check(settingsEngineBadge.visible === true, "SettingsModal engine DEV badge visible for 0.12.0.dev")

    console.log("ALL DEV BADGES VISIBILITY TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
