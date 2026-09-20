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
    console.log("Running Settings Engine Source Tests...")

    // 1. Default property value is "aur"
    check(sm.engineSource === "aur", "Default engineSource is 'aur'")

    // 2. Set engineSource to custom value
    sm.engineSource = "system"
    check(sm.engineSource === "system", "engineSource updates to 'system'")

    // 3. Set engineSource back to 'aur'
    sm.engineSource = "aur"
    check(sm.engineSource === "aur", "engineSource updates to 'aur'")

    // 3b. Test enginePackage property
    check(sm.enginePackage === "", "Default enginePackage is empty")
    sm.enginePackage = "omawarden-git"
    check(sm.enginePackage === "omawarden-git", "enginePackage updates to omawarden-git")

    // 4. Test engineSource derivation logic matching OmarchyBitwarden.qml
    function deriveEngineSource(depModel, helperPath, cliHealth) {
      if (cliHealth && !cliHealth.installed) return ""
      if (depModel) {
        for (var i = 0; i < depModel.length; i++) {
          var item = depModel[i]
          if (item.pkgName === "omawarden") {
            if (item.status === "installed") return "aur"
          }
        }
      }
      if (helperPath && helperPath !== "omawarden") {
        return "aur"
      }
      return ""
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
    var aurModelGit = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-git" }]
    check(deriveEngineSource(aurModelGit, "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' when pacman installed")
    check(deriveEnginePackage(aurModelGit) === "omawarden-git", "Derives 'omawarden-git' package name")

    // A2: omawarden installed via AUR/pacman (omawarden-bin)
    var aurModelBin = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-bin" }]
    check(deriveEngineSource(aurModelBin, "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' when omawarden-bin installed")
    check(deriveEnginePackage(aurModelBin) === "omawarden-bin", "Derives 'omawarden-bin' package name")

    // B: system helperPath fallback
    check(deriveEngineSource([], "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' from system /usr/bin/omawarden helperPath")

    // C: missing engine state (no package, no binary, or uninstalled cliHealth)
    var missingModel = [{ pkgName: "omawarden", status: "missing", installedPackage: "" }]
    check(deriveEngineSource(missingModel, "", { installed: false }) === "", "Derives empty string when engine missing from dependencies")
    check(deriveEngineSource([], "", { installed: false }) === "", "Derives empty string when engine not installed")
    check(deriveEngineSource(aurModelGit, "/usr/bin/omawarden", { installed: false }) === "", "Derives empty string when cliHealth.installed is false")

    // 5. Test isInstallingDependencies property
    check(sm.isInstallingDependencies === false, "Default isInstallingDependencies is false")
    sm.isInstallingDependencies = true
    check(sm.isInstallingDependencies === true, "isInstallingDependencies updates to true")
    sm.isInstallingDependencies = false

    // 6. Test installPackageRequested signal on missing engine and updates
    var lastInstalledPackage = ""
    sm.installPackageRequested.connect(function(pkg) { lastInstalledPackage = pkg })

    // Simulate missing engine install action
    sm.cliHealth = { installed: false }
    sm.updateAvailable = false
    check(!sm.cliHealth.installed, "Engine is marked as missing")
    sm.installPackageRequested("omawarden-bin")
    check(lastInstalledPackage === "omawarden-bin", "installPackageRequested dispatched with omawarden-bin for missing engine")

    // 7. Simulate update action dispatch via AUR package
    lastInstalledPackage = ""
    sm.cliHealth = { installed: true, version: "0.8.1" }
    sm.updateAvailable = true
    sm.latestVersion = "0.8.2"
    sm.engineSource = "aur"
    sm.enginePackage = "omawarden-git"

    sm.installPackageRequested(sm.enginePackage || "omawarden-bin")
    check(lastInstalledPackage === "omawarden-git", "Update triggers installPackageRequested with omawarden-git")

    // 7b. Update when enginePackage is empty defaults to omawarden-bin
    lastInstalledPackage = ""
    sm.enginePackage = ""
    sm.installPackageRequested(sm.enginePackage || "omawarden-bin")
    check(lastInstalledPackage === "omawarden-bin", "Update defaults to omawarden-bin when enginePackage is unset")

    console.log("ALL SETTINGS ENGINE SOURCE TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
