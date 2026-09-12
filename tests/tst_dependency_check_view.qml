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

  DependencyCheckView {
    id: depView
    anchors.fill: parent
  }

  Component.onCompleted: {
    console.log("Running DependencyCheckView Unit Tests...")

    // 1. Initial State
    check(depView.dependencyModel !== null, "dependencyModel exists")
    check(depView.dependencyModel.count === 3, "dependencyModel has 3 items")
    check(depView.dependencyModel.get(0).pkgName === "omawarden", "first pkg is omawarden")
    check(depView.dependencyModel.get(1).pkgName === "libsecret", "second pkg is libsecret")
    check(depView.dependencyModel.get(2).pkgName === "wl-clipboard", "third pkg is wl-clipboard")
    check(depView.missingPackages.length === 0, "initial missingPackages is empty")

    // 2. Reset to checking
    depView.resetToChecking()
    check(depView.dependencyModel.get(0).status === "checking", "omawarden status is checking")
    check(depView.dependencyModel.get(1).status === "checking", "libsecret status is checking")
    check(depView.dependencyModel.get(2).status === "checking", "wl-clipboard status is checking")

    // 3. Parse pacman stdout with omawarden-bin provider
    var mockStdout = "libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n"
    depView.parsePacmanStdout(mockStdout)
    check(depView.dependencyModel.get(1).status === "installed", "libsecret is installed")
    check(depView.dependencyModel.get(1).version === "0.21.7-1", "libsecret version is 0.21.7-1")
    check(depView.dependencyModel.get(2).status === "installed", "wl-clipboard is installed")
    check(depView.dependencyModel.get(2).version === "1:2.3.0-1", "wl-clipboard version is 1:2.3.0-1")
    check(depView.dependencyModel.get(0).status === "checking", "omawarden is still checking")

    // 4. Parse pacman stderr with omawarden missing
    var mockStderr = "error: package 'omawarden' was not found\nwarning: 'omawarden' is a file, you might want to use -p/--file.\n"
    depView.parsePacmanStderr(mockStderr)
    check(depView.dependencyModel.get(0).status === "missing", "omawarden status marked missing from stderr")

    // 5. Finalize check
    var missing = depView.finalizeCheck()
    check(missing.length === 1, "missing length is 1")
    check(missing[0] === "omawarden", "missing[0] is omawarden")
    check(depView.missingPackages.length === 1, "depView.missingPackages is updated")

    // 6. Get install package names maps omawarden -> omawarden-bin
    var installNames = depView.getInstallPackageNames()
    check(installNames.length === 1, "installNames length is 1")
    check(installNames[0] === "omawarden-bin", "installNames mapped omawarden to omawarden-bin")

    // 7. Parse stdout with omawarden-bin satisfying omawarden
    var mockAurStdout = "omawarden-bin 0.7.0-1\n"
    depView.parsePacmanStdout(mockAurStdout)
    check(depView.dependencyModel.get(0).status === "installed", "omawarden is satisfied by omawarden-bin")
    check(depView.dependencyModel.get(0).version === "0.7.0-1", "omawarden version set to 0.7.0-1")

    var missingAfter = depView.finalizeCheck()
    check(missingAfter.length === 0, "all dependencies satisfied, missing length is 0")
    check(depView.missingPackages.length === 0, "depView.missingPackages is empty when all installed")

    // 8. Signals test
    var recheckEmitted = false
    var installEmitted = false
    depView.recheckRequested.connect(function() { recheckEmitted = true })
    depView.installRequested.connect(function() { installEmitted = true })

    depView.recheckRequested()
    check(recheckEmitted, "recheckRequested signal emitted")

    depView.installRequested()
    check(installEmitted, "installRequested signal emitted")

    // 9. Overlay view gating test (modeled after OmarchyBitwarden.qml effectiveView logic)
    function computeEffectiveView(dependenciesMissing, currentView, authState) {
      if (dependenciesMissing && currentView !== "settings") return "dependency_check"
      if (currentView !== "auto") return currentView
      if (authState.status === "unlocked" && Boolean(authState.has_session)) return "search"
      if (authState.status === "locked" && Boolean(authState.has_session)) return "unlock"
      return "login"
    }

    var authUnlocked = { status: "unlocked", has_session: true }
    var authLocked = { status: "locked", has_session: true }
    var authUnauthenticated = { status: "unauthenticated", has_session: false }

    // When dependencies are missing, normal views must be blocked and route to "dependency_check"
    check(computeEffectiveView(true, "auto", authUnlocked) === "dependency_check", "Blocks search view when dependencies missing")
    check(computeEffectiveView(true, "auto", authLocked) === "dependency_check", "Blocks unlock view when dependencies missing")
    check(computeEffectiveView(true, "auto", authUnauthenticated) === "dependency_check", "Blocks login view when dependencies missing")

    // Settings can still be opened when user explicitly requests settings
    check(computeEffectiveView(true, "settings", authUnlocked) === "settings", "Allows settings view even when dependencies missing")

    // When dependencies are satisfied, normal views are unlocked
    check(computeEffectiveView(false, "auto", authUnlocked) === "search", "Routes to search view when dependencies satisfied and unlocked")
    check(computeEffectiveView(false, "auto", authLocked) === "unlock", "Routes to unlock view when dependencies satisfied and locked")
    check(computeEffectiveView(false, "auto", authUnauthenticated) === "login", "Routes to login view when dependencies satisfied and unauthenticated")

    // 10. Installer command generation test
    function buildInstallCommand(missingPkgs) {
      var installList = []
      for (var k = 0; k < missingPkgs.length; k++) {
        var p = missingPkgs[k]
        installList.push(p === "omawarden" ? "omawarden-bin" : p)
      }
      var pkgs = installList.join(" ")
      return "if command -v paru >/dev/null 2>&1; then paru -S --needed " + pkgs +
             "; elif command -v yay >/dev/null 2>&1; then yay -S --needed " + pkgs +
             "; else sudo pacman -S --needed " + pkgs + "; fi"
    }

    var cmd = buildInstallCommand(["omawarden", "libsecret", "wl-clipboard"])
    check(cmd.indexOf("omawarden-bin libsecret wl-clipboard") !== -1, "Install command targets omawarden-bin, libsecret, wl-clipboard")
    check(cmd.indexOf("paru -S --needed") !== -1, "Install command checks paru")
    check(cmd.indexOf("yay -S --needed") !== -1, "Install command checks yay")
    check(cmd.indexOf("sudo pacman -S --needed") !== -1, "Install command falls back to pacman")

    console.log("ALL DEPENDENCY CHECK VIEW TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
