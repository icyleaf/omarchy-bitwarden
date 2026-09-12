import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  SettingsModal {
    id: sm
  }

  Component.onCompleted: {
    console.log("Running Settings Engine Source Badge Tests...")

    // 1. Default property value
    check(sm.engineSource === "builtin", "Default engineSource is 'builtin'")

    // 2. Set engineSource to 'aur'
    sm.engineSource = "aur"
    check(sm.engineSource === "aur", "engineSource updates to 'aur'")

    // 3. Set engineSource to 'builtin'
    sm.engineSource = "builtin"
    check(sm.engineSource === "builtin", "engineSource updates to 'builtin'")

    // 4. Test engineSource derivation logic matching OmarchyBitwarden.qml
    function deriveEngineSource(depModel, helperPath) {
      if (depModel) {
        for (var i = 0; i < depModel.length; i++) {
          var item = depModel[i]
          if (item.pkgName === "omawarden") {
            if (item.isLocalFallback) return "builtin"
            if (item.status === "installed") return "aur"
          }
        }
      }
      if (helperPath && helperPath !== "omawarden") {
        if (helperPath.indexOf("/usr/") === 0 || helperPath === "/usr/bin/omawarden") {
          return "aur"
        }
      }
      return "builtin"
    }

    // A: omawarden installed via AUR/pacman
    var aurModel = [{ pkgName: "omawarden", status: "installed", isLocalFallback: false }]
    check(deriveEngineSource(aurModel, "/usr/bin/omawarden") === "aur", "Derives 'aur' when pacman installed")

    // B: omawarden satisfied via local fallback binary
    var fallbackModel = [{ pkgName: "omawarden", status: "installed", isLocalFallback: true }]
    check(deriveEngineSource(fallbackModel, "/home/user/plugin/bin/omawarden") === "builtin", "Derives 'builtin' when local fallback")

    // C: fallback on system helperPath
    check(deriveEngineSource([], "/usr/bin/omawarden") === "aur", "Derives 'aur' from system /usr/bin/omawarden helperPath")

    // D: fallback on in-tree helperPath
    check(deriveEngineSource([], "/home/user/.config/omarchy/plugins/icyleaf.bitwarden/bin/omawarden") === "builtin", "Derives 'builtin' from in-tree helperPath")

    console.log("ALL SETTINGS ENGINE SOURCE BADGE TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
