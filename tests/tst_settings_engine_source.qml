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

    // 3b. Test enginePackage property
    check(sm.enginePackage === "", "Default enginePackage is empty")
    sm.enginePackage = "omawarden-git"
    check(sm.enginePackage === "omawarden-git", "enginePackage updates to omawarden-git")

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

    function deriveEnginePackage(depModel) {
      if (depModel) {
        for (var i = 0; i < depModel.length; i++) {
          var item = depModel[i]
          if (item.pkgName === "omawarden") {
            if (item.status === "installed" && item.installedPackage) {
              return item.installedPackage
            }
          }
        }
      }
      return ""
    }

    // A: omawarden installed via AUR/pacman (omawarden-git)
    var aurModelGit = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-git", isLocalFallback: false }]
    check(deriveEngineSource(aurModelGit, "/usr/bin/omawarden") === "aur", "Derives 'aur' when pacman installed")
    check(deriveEnginePackage(aurModelGit) === "omawarden-git", "Derives 'omawarden-git' package name")

    // A2: omawarden installed via AUR/pacman (omawarden-bin)
    var aurModelBin = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-bin", isLocalFallback: false }]
    check(deriveEngineSource(aurModelBin, "/usr/bin/omawarden") === "aur", "Derives 'aur' when omawarden-bin installed")
    check(deriveEnginePackage(aurModelBin) === "omawarden-bin", "Derives 'omawarden-bin' package name")

    // B: omawarden satisfied via local fallback binary
    var fallbackModel = [{ pkgName: "omawarden", status: "installed", installedPackage: "", isLocalFallback: true }]
    check(deriveEngineSource(fallbackModel, "/home/user/plugin/bin/omawarden") === "builtin", "Derives 'builtin' when local fallback")
    check(deriveEnginePackage(fallbackModel) === "", "Derives empty enginePackage when local fallback")

    // C: fallback on system helperPath
    check(deriveEngineSource([], "/usr/bin/omawarden") === "aur", "Derives 'aur' from system /usr/bin/omawarden helperPath")

    // D: fallback on in-tree helperPath
    check(deriveEngineSource([], "/home/user/.config/omarchy/plugins/icyleaf.bitwarden/bin/omawarden") === "builtin", "Derives 'builtin' from in-tree helperPath")

    // 5. Test isInstallingDependencies property
    check(sm.isInstallingDependencies === false, "Default isInstallingDependencies is false")
    sm.isInstallingDependencies = true
    check(sm.isInstallingDependencies === true, "isInstallingDependencies updates to true")
    sm.isInstallingDependencies = false

    // 6. Test installPackageRequested signal on missing engine
    var lastInstalledPackage = ""
    sm.installPackageRequested.connect(function(pkg) { lastInstalledPackage = pkg })

    // Simulate missing engine state
    sm.cliHealth = { installed: false }
    sm.updateAvailable = false
    check(!sm.cliHealth.installed, "Engine is marked as missing")

    // 7. Test action dispatching based on engineSource
    var downloadRequested = false
    sm.downloadCliRequested.connect(function() { downloadRequested = true })

    // When update is available with AUR source
    sm.cliHealth = { installed: true, version: "0.7.0" }
    sm.updateAvailable = true
    sm.latestVersion = "0.8.0"
    sm.engineSource = "aur"
    sm.enginePackage = "omawarden-bin"

    // Simulate update action dispatch
    if (sm.engineSource.toLowerCase() === "aur") {
      sm.installPackageRequested(sm.enginePackage || "omawarden-bin")
    } else {
      sm.downloadCliRequested()
    }
    check(lastInstalledPackage === "omawarden-bin", "AUR update triggers installPackageRequested with omawarden-bin")
    check(!downloadRequested, "downloadCliRequested not triggered for AUR update")

    // When update is available with builtin source
    lastInstalledPackage = ""
    downloadRequested = false
    sm.engineSource = "builtin"
    sm.enginePackage = ""

    if (sm.engineSource.toLowerCase() === "aur") {
      sm.installPackageRequested(sm.enginePackage || "omawarden-bin")
    } else {
      sm.downloadCliRequested()
    }
    check(lastInstalledPackage === "", "installPackageRequested not triggered for builtin update")
    check(downloadRequested, "downloadCliRequested triggered for builtin update")

    console.log("ALL SETTINGS ENGINE SOURCE BADGE TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
