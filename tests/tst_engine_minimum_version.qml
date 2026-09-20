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
    if (!v || typeof v !== "string") return null
    var clean = String(v).replace(/^omawarden[\s-]+|^v/i, "").trim()
    var match = clean.match(/^(\d+)\.(\d+)(?:\.(\d+))?/)
    if (!match) return null
    var major = parseInt(match[1], 10)
    var minor = parseInt(match[2], 10)
    var patch = (match[3] !== undefined && match[3] !== "") ? parseInt(match[3], 10) : 0
    return [major, minor, patch]
  }

  function compareSemVer(v1, v2) {
    var a = parseSemVer(v1)
    var b = parseSemVer(v2)
    if (!a && !b) return 0
    if (!a) return -1
    if (!b) return 1
    for (var i = 0; i < 3; i++) {
      if (a[i] > b[i]) return 1
      if (a[i] < b[i]) return -1
    }
    return 0
  }

  function isEngineVersionSatisfied(ver) {
    if (!ver) return false
    var parsed = parseSemVer(ver)
    if (!parsed) return false
    var min = parseSemVer(minimumEngineVersion)
    if (!min) return false
    for (var i = 0; i < 3; i++) {
      if (parsed[i] > min[i]) return true
      if (parsed[i] < min[i]) return false
    }
    return true
  }

  Component.onCompleted: {
    console.log("Running Minimum Engine Version Enforcement Tests...")

    // Negative checks: older stable versions (< 0.8.1)
    check(!isEngineVersionSatisfied(""), "Empty version is rejected")
    check(!isEngineVersionSatisfied("0.7.0"), "Version 0.7.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0"), "Version 0.8.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("omawarden-0.8.0"), "omawarden-0.8.0 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0-1"), "Arch package version 0.8.0-1 is rejected (< 0.8.1)")

    // Negative checks: older development, prerelease, and VCS versions (< 0.8.1)
    check(!isEngineVersionSatisfied("0.8.0-dev"), "Development build 0.8.0-dev is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0.dev"), "Development build 0.8.0.dev is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.8.0.r45.ga1b2c3d-1"), "VCS build 0.8.0.r45.ga1b2c3d-1 is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.7.9-dev"), "Development build 0.7.9-dev is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.7.9.dev"), "Development build 0.7.9.dev is rejected (< 0.8.1)")
    check(!isEngineVersionSatisfied("0.7.0.r12.gabcdef-1"), "VCS build 0.7.0.r12.gabcdef-1 is rejected (< 0.8.1)")

    // Negative checks: malformed or unknown versions (must fail closed)
    check(!isEngineVersionSatisfied("unknown"), "Unknown version is rejected (fail closed)")
    check(!isEngineVersionSatisfied("r45.ga1b2c3d"), "VCS hash without semver prefix is rejected (fail closed)")
    check(!isEngineVersionSatisfied("dev"), "String 'dev' without semver prefix is rejected (fail closed)")
    check(!isEngineVersionSatisfied(null), "Null version is rejected (fail closed)")
    check(!isEngineVersionSatisfied(undefined), "Undefined version is rejected (fail closed)")

    // Positive checks: versions >= 0.8.1 (stable, pre-release, dev, VCS, full CLI strings)
    check(isEngineVersionSatisfied("0.8.1"), "Version 0.8.1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("omawarden-0.8.1"), "omawarden-0.8.1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1-1"), "Arch package version 0.8.1-1 is accepted (== 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1-dev"), "Development build 0.8.1-dev is accepted (>= 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1.dev"), "Development build 0.8.1.dev is accepted (>= 0.8.1)")
    check(isEngineVersionSatisfied("0.8.1.r12.g9f8e7d-1"), "VCS build 0.8.1.r12.g9f8e7d-1 is accepted (>= 0.8.1)")
    check(isEngineVersionSatisfied("0.8.2"), "Version 0.8.2 is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("0.8.2-dev"), "Development build 0.8.2-dev is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("0.9.0"), "Version 0.9.0 is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("0.9.0-dev"), "Development build 0.9.0-dev is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("1.0.0-rc1"), "Prerelease 1.0.0-rc1 is accepted (> 0.8.1)")
    check(isEngineVersionSatisfied("omawarden 0.8.1 (32cf259 2026-09-19)"), "Full omawarden CLI version string is accepted (>= 0.8.1)")

    // Report results
    if (failures > 0) {
      console.error("TOTAL FAILURES: " + failures)
    } else {
      console.log("ALL MINIMUM ENGINE VERSION TESTS PASSED!")
    }
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
