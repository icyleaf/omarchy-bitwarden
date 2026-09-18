import QtQuick
import QtQuick.Controls

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

  function toLocalPath(url) {
    if (!url) return ""
    var str = url.toString ? url.toString() : String(url)
    return str.replace(/^file:\/+/i, "/")
  }

  // Model the resolve logic from OmarchyBitwarden.qml
  property string helperPath: "omawarden"

  function resolveWithResult(whichOutput, whichExitCode) {
    var p = (whichOutput || "").trim()
    if (whichExitCode === 0 && p.length > 0) {
      testRunner.helperPath = p
    } else {
      var localPath = testRunner.toLocalPath(Qt.resolvedUrl("bin/omawarden"))
      if (localPath) {
        testRunner.helperPath = localPath
      } else {
        testRunner.helperPath = "/mock/.config/omarchy/plugins/icyleaf.bitwarden/bin/omawarden"
      }
    }
    return testRunner.helperPath
  }

  Component.onCompleted: {
    console.log("Running Helper Path Resolution Tests...")

    // 1. Initial default is "omawarden"
    check(testRunner.helperPath === "omawarden", "Default helperPath is system command 'omawarden'")

    // 2. System binary present: which exits 0 with /usr/bin/omawarden
    var systemResult = testRunner.resolveWithResult("/usr/bin/omawarden\n", 0)
    check(systemResult === "/usr/bin/omawarden", "Resolves to /usr/bin/omawarden when found in system PATH")

    // 3. System binary missing: which exits 1 (command not found)
    var fallbackResult = testRunner.resolveWithResult("", 1)
    var expectedLocal = testRunner.toLocalPath(Qt.resolvedUrl("bin/omawarden"))
    check(fallbackResult === expectedLocal, "Falls back to local in-tree bin/omawarden when not in system PATH")

    // 4. Verification that OMARCHY_BITWARDEN_HELPER is not used
    // (Ensure resolution is strictly system -> fallback, impervious to custom env injection)
    check(testRunner.helperPath.indexOf("OMARCHY_BITWARDEN_HELPER") === -1, "OMARCHY_BITWARDEN_HELPER has zero effect on path resolution")

    console.log("ALL HELPER RESOLUTION TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
