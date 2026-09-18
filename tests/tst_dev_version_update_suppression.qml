import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  function parseSemVer(v) {
    if (!v) return [0, 0, 0]
    var clean = v.replace(/^v/, "").split("-")[0]
    var parts = clean.split(".")
    var major = parseInt(parts[0]) || 0
    var minor = parseInt(parts[1]) || 0
    var patch = parseInt(parts[2]) || 0
    return [major, minor, patch]
  }

  function compareSemVer(v1, v2) {
    var a = parseSemVer(v1)
    var b = parseSemVer(v2)
    for (var i = 0; i < 3; i++) {
      if (a[i] > b[i]) return 1
      if (a[i] < b[i]) return -1
    }
    return 0
  }

  function isUpdateAvailable(latestVersion, currentVer) {
    if (!latestVersion) return false
    if (!currentVer) return false
    if (currentVer.indexOf("-dev") !== -1 || currentVer.indexOf(".dev") !== -1) return false
    return compareSemVer(latestVersion, currentVer) > 0
  }

  Component.onCompleted: {
    console.log("Running Dev Version Update Suppression Tests...")

    // 1. Stable version older than latest -> update available
    check(isUpdateAvailable("0.7.1", "0.7.0") === true, "0.7.0 is notified for 0.7.1")
    check(isUpdateAvailable("0.8.0", "0.7.0") === true, "0.7.0 is notified for 0.8.0")

    // 2. Dev version (-dev or .dev) -> update notifications suppressed
    check(isUpdateAvailable("0.7.0", "0.8.0-dev") === false, "0.8.0-dev suppresses 0.7.0 update notification")
    check(isUpdateAvailable("0.7.1", "0.8.0-dev") === false, "0.8.0-dev suppresses 0.7.1 update notification")
    check(isUpdateAvailable("0.8.0", "0.8.0-dev") === false, "0.8.0-dev suppresses 0.8.0 update notification")
    check(isUpdateAvailable("0.7.0", "0.8.0.dev") === false, "0.8.0.dev suppresses 0.7.0 update notification")

    // 3. Stable version same or newer -> no update
    check(isUpdateAvailable("0.7.0", "0.7.0") === false, "0.7.0 does not notify for 0.7.0")
    check(isUpdateAvailable("0.6.9", "0.7.0") === false, "0.7.0 does not notify for older 0.6.9")

    console.log("ALL DEV VERSION UPDATE SUPPRESSION TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
