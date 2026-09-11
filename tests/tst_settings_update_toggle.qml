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

  SettingsModal { id: sm }

  Component.onCompleted: {
    // 1. Config load -> checkbox state
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", check_updates: false })
    check(sm.checkUpdatesChecked === false, "config check_updates:false disables the checkbox")

    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", check_updates: true })
    check(sm.checkUpdatesChecked === true, "config check_updates:true enables the checkbox")

    // 2. Upgrade path: an older engine that omits the key leaves it on
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error" })
    check(sm.checkUpdatesChecked === true, "config without check_updates leaves the checkbox on")

    // 3. Checkbox state -> save payload
    sm.checkUpdatesChecked = false
    check(sm.buildPayload().check_updates === false, "unchecked box builds check_updates:false")

    sm.checkUpdatesChecked = true
    check(sm.buildPayload().check_updates === true, "checked box builds check_updates:true")

    // 4. Regression guard: the six pre-existing keys survived the extraction
    var payload = sm.buildPayload()
    var required = ["server_url", "identity_url", "download_dir", "auto_lock_minutes", "clipboard_clear_seconds", "log_level"]
    for (var i = 0; i < required.length; i++) {
      check(payload[required[i]] !== undefined, "buildPayload still emits " + required[i])
    }

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
