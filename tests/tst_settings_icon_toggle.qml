import QtQuick
import QtQuick.Controls
import "../components"

Item {
  property int failures: 0
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

  SettingsModal { id: sm }

  Component.onCompleted: {
    // A. Config load drives the checkbox
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", show_website_icons: false })
    check(sm.showWebsiteIconsChecked === false, "config show_website_icons:false unchecks the box")

    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", show_website_icons: true })
    check(sm.showWebsiteIconsChecked === true, "config show_website_icons:true checks the box")

    // Existing-user upgrade path: key absent leaves the last known value alone (default true)
    sm.showWebsiteIconsChecked = true
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error" })
    check(sm.showWebsiteIconsChecked === true, "config without the key leaves it true")

    // B. Payload carries the checkbox state
    sm.showWebsiteIconsChecked = false
    check(sm.buildPayload().show_website_icons === false, "payload show_website_icons is false when unchecked")

    sm.showWebsiteIconsChecked = true
    check(sm.buildPayload().show_website_icons === true, "payload show_website_icons is true when checked")

    // C. Regression guard on the extraction — all six pre-existing keys survive
    var payload = sm.buildPayload()
    var keys = ["server_url", "identity_url", "download_dir", "auto_lock_minutes",
                "clipboard_clear_seconds", "log_level"]
    for (var i = 0; i < keys.length; i++) {
      check(payload[keys[i]] !== undefined, "payload still contains " + keys[i])
    }

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
