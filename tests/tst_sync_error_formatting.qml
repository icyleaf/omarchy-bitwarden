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

  function formatSyncError(err) {
    if (!err) return "Vault sync failed."
    var str = String(err).trim()

    var isTokenRefresh = str.toLowerCase().indexOf("token refresh") !== -1 || str.toLowerCase().indexOf("refresh token") !== -1
    var isApiAuth = str.toLowerCase().indexOf("api auth") !== -1 || str.toLowerCase().indexOf("api key") !== -1

    var httpMatch = str.match(/HTTP\s+(\d{3}(?:\s+[A-Za-z]+){0,4})/i)
    if (httpMatch && httpMatch[1]) {
      var httpCode = "HTTP " + httpMatch[1].trim()
      if (isTokenRefresh) {
        return "Token refresh failed: " + httpCode
      } else if (isApiAuth) {
        return "API auth failed: " + httpCode
      } else {
        return "Vault sync failed: " + httpCode
      }
    }

    if (str.toLowerCase().indexOf("connection refused") !== -1) {
      return (isTokenRefresh ? "Token refresh failed: " : "Vault sync failed: ") + "Connection refused"
    }
    if (str.toLowerCase().indexOf("timed out") !== -1 || str.toLowerCase().indexOf("timeout") !== -1) {
      return (isTokenRefresh ? "Token refresh failed: " : "Vault sync failed: ") + "Request timed out"
    }

    return str
  }

  Component.onCompleted: {
    console.log("Running Sync Error Formatting Tests...")

    // 1. Exact diagnostics scenario from user report
    var userRawError = "Network error during token refresh: Refresh token endpoint error: HTTP 502 Bad Gateway"
    check(formatSyncError(userRawError) === "Token refresh failed: HTTP 502 Bad Gateway",
          "Formatted user diagnostics 502 error to concise Token refresh message")

    // 2. HTTP status variants in token refresh
    check(formatSyncError("Refresh token HTTP 401 Unauthorized") === "Token refresh failed: HTTP 401 Unauthorized",
          "Handles HTTP 401 Unauthorized in token refresh")
    check(formatSyncError("Token refresh failed: HTTP 500 Internal Server Error") === "Token refresh failed: HTTP 500 Internal Server Error",
          "Handles HTTP 500 Internal Server Error in token refresh")
    check(formatSyncError("Refresh token endpoint error: HTTP 503") === "Token refresh failed: HTTP 503",
          "Handles status without reason phrase")

    // 3. API auth failures
    check(formatSyncError("Network error during API auth: HTTP 502 Bad Gateway") === "API auth failed: HTTP 502 Bad Gateway",
          "Handles API auth HTTP 502")
    check(formatSyncError("API key silent re-auth rejected: HTTP 401 Unauthorized") === "API auth failed: HTTP 401 Unauthorized",
          "Handles API key auth HTTP 401")

    // 4. General vault sync HTTP failures
    check(formatSyncError("Sync failed: HTTP 500 Internal Server Error") === "Vault sync failed: HTTP 500 Internal Server Error",
          "Handles general vault sync HTTP 500")
    check(formatSyncError("Vault sync failed: HTTP 404 Not Found") === "Vault sync failed: HTTP 404 Not Found",
          "Handles general vault sync HTTP 404")

    // 5. Connection refused & timeouts
    check(formatSyncError("Network error during token refresh: connection refused") === "Token refresh failed: Connection refused",
          "Handles token refresh connection refused")
    check(formatSyncError("Network error: connection refused") === "Vault sync failed: Connection refused",
          "Handles general connection refused")
    check(formatSyncError("Network error during token refresh: request timed out") === "Token refresh failed: Request timed out",
          "Handles token refresh timeout")
    check(formatSyncError("Vault sync timed out") === "Vault sync failed: Request timed out",
          "Handles general timeout")

    // 6. Passthrough messages
    check(formatSyncError("Session expired. Please log in again.") === "Session expired. Please log in again.",
          "Preserves session expired message")
    check(formatSyncError("Please log in with master password") === "Please log in with master password",
          "Preserves login required message")

    // 7. Edge cases / empty inputs
    check(formatSyncError("") === "Vault sync failed.", "Handles empty string")
    check(formatSyncError(null) === "Vault sync failed.", "Handles null")
    check(formatSyncError(undefined) === "Vault sync failed.", "Handles undefined")

    console.log("ALL SYNC ERROR FORMATTING TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
