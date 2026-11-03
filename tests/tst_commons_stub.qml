import QtQuick
import qs.Commons as Commons

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

  Component.onCompleted: {
    console.log("Running Commons Stub Tests...")

    // Check Color singleton availability
    check(typeof Commons.Color !== "undefined" && Commons.Color !== null, "Commons.Color singleton must be defined")
    check(Commons.Color.foreground !== undefined, "Commons.Color.foreground must be defined")
    check(Commons.Color.background !== undefined, "Commons.Color.background must be defined")
    check(Commons.Color.accent !== undefined, "Commons.Color.accent must be defined")
    check(Commons.Color.muted !== undefined, "Commons.Color.muted must be defined")
    check(Commons.Color.popups !== undefined && Commons.Color.popups.background !== undefined, "Commons.Color.popups.background must be defined")
    check(Commons.Color.menu !== undefined && Commons.Color.menu.background !== undefined, "Commons.Color.menu.background must be defined")

    // Check preset toggle
    check(typeof Commons.Color.setPreset === "function", "Commons.Color.setPreset must be a function")
    Commons.Color.setPreset("light")
    check(Commons.Color.background == "#eff1f5", "Commons.Color.background in light mode should be #eff1f5")
    check(Commons.Color.foreground == "#4c4f69", "Commons.Color.foreground in light mode should be #4c4f69")
    check(Commons.Color.muted == "#acb0be", "Commons.Color.muted in light mode should be #acb0be")

    Commons.Color.setPreset("dark")
    check(Commons.Color.background == "#1a1b26", "Commons.Color.background in dark mode should be #1a1b26")
    check(Commons.Color.foreground == "#a9b1d6", "Commons.Color.foreground in dark mode should be #a9b1d6")

    // Check Style font/icon tokens
    check(Commons.Style.font.iconLarge !== undefined && Commons.Style.font.iconLarge > 0, "Commons.Style.font.iconLarge must be defined")
    check(Commons.Style.font.heading !== undefined && Commons.Style.font.heading > 0, "Commons.Style.font.heading must be defined")
    check(Commons.Style.font.display !== undefined && Commons.Style.font.display > 0, "Commons.Style.font.display must be defined")

    if (failures > 0) {
      console.error("TOTAL FAILURES:", failures)
      Qt.exit(1)
    } else {
      console.log("ALL COMMONS STUB TESTS PASSED!")
      Qt.exit(0)
    }
  }
}
