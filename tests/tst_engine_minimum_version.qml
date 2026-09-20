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

  // Minimum required omawarden engine version that contains CWE-400 bounded response fix
  readonly property string minimumEngineVersion: "0.8.1"

  function parseSemVer(v) {
    if (!v) return [0, 0, 0]
    var clean = String(v).replace(/^omawarden-|^v/i, "").trim()
    var parts = clean.split("-")[0].split(".")
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

  function isEngineVersionSatisfied(ver) {
    if (!ver) return false
    var clean = String(ver).trim()
    if (clean.indexOf("-dev") !== -1 || clean.indexOf(".dev") !== -1) {
      return true
    }
    return compareSemVer(clean, minimumEngineVersion) >= 0
  }

  Component.onCompleted: {
    console.log("Running Minimum Engine Version Enforcement Tests...")

    // 1. Version satisfaction checks
    check(!isEngineVersionSatisfied(""), "Empty version is rejected")
    check(!isEngineVersionSatisfied("0.7.0"), "Version 0.7.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0"), "Version 0.8.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("omawarden-0.8.0"), "omawarden-0.8.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0-1"), "Arch package version 0.8.0-1 is rejected (< 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1"), "Version 0.8.1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("omawarden-0.8.1"), "omawarden-0.8.1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1-1"), "Arch package version 0.8.1-1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("0.8.2"), "Version 0.8.2 is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("0.9.0"), "Version 0.9.0 is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("0.8.0-dev"), "Development build 0.8.0-dev is accepted")
    check(isEngineVersionSatisfied("0.8.1-dev"), "Development build 0.8.1-dev is accepted")

    // Report results
    if (failures > 0) {
      console.error("TOTAL FAILURES: " + failures)
    } else {
      console.log("ALL MINIMUM ENGINE VERSION TESTS PASSED!")
    }
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
