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
    // 1. Config load -> max_attachment_size_mb binding & buildPayload
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", max_attachment_size_mb: 250 })
    check(sm.buildPayload().max_attachment_size_mb === 250, "config max_attachment_size_mb:250 is emitted in buildPayload")

    // 2. Upgrade path: key absent defaults to 500
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error" })
    check(sm.buildPayload().max_attachment_size_mb === 500, "missing max_attachment_size_mb defaults buildPayload to 500")

    // 3. Regression guard: required keys in buildPayload
    var payload = sm.buildPayload()
    var required = [
      "server_url", "identity_url", "download_dir",
      "auto_lock_minutes", "clipboard_clear_seconds",
      "max_attachment_size_mb", "log_level",
      "show_website_icons", "check_updates", "remember_last_search"
    ]
    for (var i = 0; i < required.length; i++) {
      check(payload[required[i]] !== undefined, "buildPayload emits " + required[i])
    }

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
