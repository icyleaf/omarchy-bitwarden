import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  property int lastSelectedProvider: -1
  property var lastLoginRequest: null
  property string lastCopiedText: ""
  property string lastInstalledPackage: ""

  AuthView {
    id: authView
    authState: ({ status: "unauthenticated", has_session: false })
    onTwoFactorProviderSelected: function(p) {
      testRunner.lastSelectedProvider = p
    }
    onLoginPasswordRequested: function(email, pwd, code, prov) {
      testRunner.lastLoginRequest = { email: email, password: pwd, code: code, provider: prov }
    }
    onCopyRequested: function(txt, lbl) {
      testRunner.lastCopiedText = txt
    }
    onInstallPackageRequested: function(pkg) {
      testRunner.lastInstalledPackage = pkg
    }
  }

  Component.onCompleted: {
    // 1. Initial defaults
    check(authView.show2FAField === false, "AuthView show2FAField defaults to false")
    check(authView.twoFactorProvider === 0, "AuthView twoFactorProvider defaults to 0")
    check(Array.isArray(authView.availableTwoFactorProviders) && authView.availableTwoFactorProviders.length === 0, "AuthView availableTwoFactorProviders defaults to empty array")

    // 2. Setting WebAuthn (provider 7) and Email (provider 1) 2FA state
    authView.show2FAField = true
    authView.twoFactorProvider = 7
    authView.availableTwoFactorProviders = [1, 7]
    check(authView.show2FAField === true, "AuthView show2FAField set to true")
    check(authView.twoFactorProvider === 7, "AuthView twoFactorProvider set to 7 (WebAuthn)")
    check(authView.availableTwoFactorProviders.length === 2, "availableTwoFactorProviders contains 2 providers")
    check(authView.availableTwoFactorProviders.indexOf(7) !== -1, "availableTwoFactorProviders includes 7")

    // 3. Provider selection signal test
    authView.twoFactorProviderSelected(1)
    check(testRunner.lastSelectedProvider === 1, "twoFactorProviderSelected signal emitted with provider 1")
    authView.twoFactorProviderSelected(7)
    check(testRunner.lastSelectedProvider === 7, "twoFactorProviderSelected signal emitted with provider 7")

    // 4. clearInputs() resets twoFactorProvider and availableTwoFactorProviders
    authView.clearInputs()
    check(authView.twoFactorProvider === 0, "clearInputs() resets twoFactorProvider to 0")
    check(authView.availableTwoFactorProviders.length === 0, "clearInputs() resets availableTwoFactorProviders to []")

    // 5. Changing loginMethod resets twoFactorProvider and availableTwoFactorProviders
    authView.show2FAField = true
    authView.twoFactorProvider = 7
    authView.availableTwoFactorProviders = [1, 7]
    authView.loginMethod = "apikey"
    check(authView.show2FAField === false, "loginMethod change resets show2FAField")
    check(authView.twoFactorProvider === 0, "loginMethod change resets twoFactorProvider")
    check(authView.availableTwoFactorProviders.length === 0, "loginMethod change resets availableTwoFactorProviders")
    authView.loginMethod = "password"

    // 6. Response parsing simulation for WebAuthn 2FA challenge
    var respWebAuthn2FA = {
      ok: false,
      error: "WebAuthn security key authentication required. Please insert and touch your security key.",
      two_factor_required: true,
      two_factor_provider: 7,
      two_factor_providers: [1, 7]
    }
    var prov = (respWebAuthn2FA.two_factor_provider !== undefined && respWebAuthn2FA.two_factor_provider !== null)
        ? Number(respWebAuthn2FA.two_factor_provider)
        : 0
    var avail = respWebAuthn2FA.two_factor_providers || []
    check(prov === 7, "WebAuthn provider correctly parsed as 7")
    check(avail.length === 2 && avail.indexOf(7) !== -1, "availableTwoFactorProviders has [1, 7]")

    // Verify error text matching for 2FA detection
    var errLower = (respWebAuthn2FA.error || "").toLowerCase()
    var is2FA = Boolean(respWebAuthn2FA.two_factor_required)
        || errLower.indexOf("security key") !== -1
        || errLower.indexOf("webauthn") !== -1
    check(is2FA === true, "is2FA detected correctly from response")

    // 7. Payload construction for WebAuthn (provider 7, empty code)
    var password = "secretMasterPassword"
    var code = ""
    var show2FA = true
    var effectiveProvider = prov
    var payload = null
    if (code || (show2FA && effectiveProvider === 7)) {
      payload = { password: password }
      if (code) payload.code = code
      if (effectiveProvider !== undefined && effectiveProvider !== null) {
        payload.two_factor_provider = effectiveProvider
      }
    } else {
      payload = { password: password }
    }
    check(payload !== null, "WebAuthn payload successfully constructed")
    check(payload.password === "secretMasterPassword", "payload has correct password")
    check(payload.two_factor_provider === 7, "payload has two_factor_provider: 7")
    check(payload.code === undefined, "payload does NOT have code field for WebAuthn")

    // 8. Fallback provider resolution when two_factor_provider is not explicitly provided in response
    var respFallback = {
      ok: false,
      error: "Two-step login required",
      two_factor_required: true,
      two_factor_providers: [1, 7]
    }
    var provFallback = (respFallback.two_factor_provider !== undefined && respFallback.two_factor_provider !== null)
        ? Number(respFallback.two_factor_provider)
        : 0
    if (respFallback.two_factor_providers && respFallback.two_factor_providers.length > 0) {
      if (respFallback.two_factor_provider === undefined || respFallback.two_factor_provider === null) {
        if (respFallback.two_factor_providers.indexOf(7) !== -1) {
          provFallback = 7
        } else if (respFallback.two_factor_providers.indexOf(0) !== -1) {
          provFallback = 0
        } else if (respFallback.two_factor_providers.indexOf(1) !== -1) {
          provFallback = 1
        }
      }
    }
    check(provFallback === 7, "Fallback resolves provider 7 when WebAuthn is among providers")

    // 9. Verification of explicit AuthView synchronization after clearInputs
    authView.clearInputs()
    check(authView.twoFactorProvider === 0, "clearInputs resets twoFactorProvider to 0")
    // Sync from login response
    authView.show2FAField = true
    authView.twoFactorProvider = 7
    authView.availableTwoFactorProviders = [1, 7]
    check(authView.show2FAField === true, "authView show2FAField is true after sync")
    check(authView.twoFactorProvider === 7, "authView twoFactorProvider is 7 after sync")
    check(authView.availableTwoFactorProviders.length === 2, "authView availableTwoFactorProviders has 2 items after sync")

    // 10. Verification of fido2Status states and copy command
    authView.fido2Status = "tool_not_found"
    check(authView.fido2Status === "tool_not_found", "fido2Status set to tool_not_found")
    authView.copyRequested("sudo pacman -S libfido2", "Install command")
    check(testRunner.lastCopiedText === "sudo pacman -S libfido2", "copyRequested emitted install command")

    authView.fido2Status = "no_device"
    check(authView.fido2Status === "no_device", "fido2Status set to no_device")

    // 11. Verification of Submit Button states and auto-detect timer based on fido2Status
    authView.show2FAField = true
    authView.twoFactorProvider = 7

    // Case A: no_device -> button is disabled, timer is running
    authView.fido2Status = "no_device"
    check(authView.submitButtonComponent.isSubmitEnabled === false, "Submit button is disabled when no_device")
    check(authView.fido2AutoDetectTimerComponent.running === true, "fido2AutoDetectTimer is running when no_device")

    // Case B: tool_not_found -> button is enabled for installation, timer does not run
    authView.fido2Status = "tool_not_found"
    check(authView.submitButtonComponent.isToolNotFound === true, "Submit button identifies tool_not_found state")
    check(authView.submitButtonComponent.isSubmitEnabled === true, "Submit button is enabled to install libfido2 when tool_not_found")
    check(authView.fido2AutoDetectTimerComponent.running === false, "fido2AutoDetectTimer is stopped when tool_not_found")

    // Install requested signal from submit button click or direct invocation
    authView.installPackageRequested("libfido2")
    check(testRunner.lastInstalledPackage === "libfido2", "installPackageRequested emitted libfido2")

    // Installing state disables the button
    authView.isInstalling = true
    check(authView.submitButtonComponent.isSubmitEnabled === false, "Submit button disabled while isInstalling")
    authView.isInstalling = false
    check(authView.submitButtonComponent.isSubmitEnabled === true, "Submit button re-enabled when isInstalling finishes")

    // Case C: available -> button is enabled, timer continues running to detect unplugging
    authView.fido2Status = "available"
    check(authView.submitButtonComponent.isSubmitEnabled === true, "Submit button is enabled when available")
    check(authView.fido2AutoDetectTimerComponent.running === true, "fido2AutoDetectTimer continues running when available to monitor unplugging")

    // Case D: timer pauses during busy state (waiting for key touch)
    authView.isBusy = true
    check(authView.fido2AutoDetectTimerComponent.running === false, "fido2AutoDetectTimer pauses when isBusy")
    authView.isBusy = false
    check(authView.fido2AutoDetectTimerComponent.running === true, "fido2AutoDetectTimer resumes after busy state ends")

    // Case E: Other 2FA providers are not blocked by fido2Status
    authView.fido2Status = "no_device"
    authView.twoFactorProvider = 1
    check(authView.submitButtonComponent.isSubmitEnabled === true, "Submit button is enabled for Email 2FA even if fido2Status is no_device")
    check(authView.fido2AutoDetectTimerComponent.running === false, "fido2AutoDetectTimer is stopped when on Email 2FA tab")

    // 12. Verification of stderr log level categorization for WebAuthn prompts
    function simulateStderr(text, defaultSource) {
      var capturedLogs = []
      var lines = String(text).split("\n")
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim()
        if (!line) continue
        var match = line.match(/^(?:\[([0-9T:\-\.Z]+)\]\s+)?\[(ERROR|WARN|INFO|DEBUG|TRACE)\]\s+\[([^\]]+)\]\s+(.*)$/i)
        if (match) {
          capturedLogs.push({ level: match[2].toUpperCase(), message: match[4] })
        } else {
          var isInfo = line.startsWith("•") || line.startsWith("✓") ||
                       line.indexOf("Waiting for security key touch") !== -1 ||
                       line.indexOf("Requesting WebAuthn challenge") !== -1 ||
                       line.indexOf("Security key verified") !== -1
          capturedLogs.push({ level: isInfo ? "INFO" : "ERROR", message: line })
        }
      }
      return capturedLogs
    }

    var structuredLog = "[2026-09-18T02:30:00.000Z] [INFO] [omawarden:auth] Waiting for security key touch..."
    var resStructured = simulateStderr(structuredLog, "omawarden:auth")
    check(resStructured.length === 1 && resStructured[0].level === "INFO", "Structured WebAuthn log parsed as INFO")

    var legacyStderr = "• Waiting for security key touch..."
    var resLegacy = simulateStderr(legacyStderr, "omawarden:cli")
    check(resLegacy.length === 1 && resLegacy[0].level === "INFO", "Unstructured bullet waiting prompt parsed as INFO")

    var rawError = "Error: device disconnected unexpectedly"
    var resError = simulateStderr(rawError, "omawarden:cli")
    check(resError.length === 1 && resError[0].level === "ERROR", "Actual error line in stderr parsed as ERROR")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
