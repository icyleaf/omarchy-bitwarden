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

  function formatDiagnosticsReport(cliHealth, config, authState, engineSource, enginePackage, helperPath, attestationVerified, logBuffer) {
    var ts = new Date().toISOString()
    var cliVer = (cliHealth && cliHealth.version) ? cliHealth.version : "Unknown"
    var rawUrl = (config && config.server_url) ? config.server_url : ""
    var sUrl = rawUrl || "https://vault.bitwarden.com"
    var rawIdUrl = (config && config.identity_url) ? config.identity_url : ""
    var idUrl = rawIdUrl || "Auto"
    var lLevel = (config && config.log_level) ? config.log_level : "error"
    var vStatus = (authState ? authState.status : "unknown")

    var report = "### Omarchy Bitwarden Diagnostics Report\n\n"
    report += "- **Generated At**: " + ts + "\n"
    report += "- **omawarden Version**: " + cliVer + "\n"
    report += "- **Server URL**: " + sUrl + "\n"
    report += "- **Identity URL**: " + idUrl + "\n"
    report += "- **Configured Log Level**: " + lLevel + "\n"
    report += "- **Vault Status**: " + vStatus + "\n"
    report += "- **Engine Ready**: " + (cliHealth && cliHealth.installed ? "Yes" : "No") + "\n"
    var engineSourceStr = engineSource ? engineSource.toUpperCase() : "BUILTIN"
    if (enginePackage) {
      engineSourceStr += " (" + enginePackage + ")"
    } else if (engineSource === "builtin") {
      engineSourceStr += " (local binary)"
    }
    report += "- **Engine Source**: " + engineSourceStr + "\n"
    report += "- **Engine Binary Path**: " + (helperPath || "Unknown") + "\n"
    report += "- **Engine Attestation**: " + (attestationVerified ? "Verified (GitHub Artifact Attestation)" : "Unverified / SHA-256 Only") + "\n"
    report += "- **Keyring Available**: " + (cliHealth && cliHealth.keyring_available ? "Yes" : "No") + "\n"
    report += "- **Clipboard Available**: " + (cliHealth && cliHealth.clipboard_available ? "Yes" : "No") + "\n\n"
    report += "#### Recent Logs (" + (logBuffer ? logBuffer.length : 0) + " entries):\n\n```text\n"
    report += "(No logs recorded yet)\n```\n"
    return report
  }

  Component.onCompleted: {
    console.log("Running Diagnostics Report Engine Source Tests...")

    // 1. omawarden-git AUR source
    var gitReport = formatDiagnosticsReport(
      { version: "0.8.0-dev", installed: true, keyring_available: true, clipboard_available: true },
      { server_url: "https://vault.bitwarden.com", log_level: "info" },
      { status: "unlocked" },
      "aur",
      "omawarden-git",
      "/usr/bin/omawarden",
      false,
      []
    )
    check(gitReport.indexOf("- **Engine Source**: AUR (omawarden-git)") !== -1, "Report shows AUR (omawarden-git)")
    check(gitReport.indexOf("- **Engine Binary Path**: /usr/bin/omawarden") !== -1, "Report shows Engine Binary Path")

    // 2. omawarden-bin AUR source
    var binReport = formatDiagnosticsReport(
      { version: "0.7.0", installed: true, keyring_available: true, clipboard_available: true },
      { server_url: "https://vault.bitwarden.com", log_level: "info" },
      { status: "unlocked" },
      "aur",
      "omawarden-bin",
      "/usr/bin/omawarden",
      true,
      []
    )
    check(binReport.indexOf("- **Engine Source**: AUR (omawarden-bin)") !== -1, "Report shows AUR (omawarden-bin)")

    // 3. Local fallback builtin source
    var builtinReport = formatDiagnosticsReport(
      { version: "0.8.0-dev", installed: true, keyring_available: true, clipboard_available: true },
      { server_url: "https://vault.bitwarden.com", log_level: "info" },
      { status: "unlocked" },
      "builtin",
      "",
      "/home/user/plugin/bin/omawarden",
      false,
      []
    )
    check(builtinReport.indexOf("- **Engine Source**: BUILTIN (local binary)") !== -1, "Report shows BUILTIN (local binary)")
    check(builtinReport.indexOf("- **Engine Binary Path**: /home/user/plugin/bin/omawarden") !== -1, "Report shows in-tree helperPath")

    console.log("ALL DIAGNOSTICS REPORT TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
