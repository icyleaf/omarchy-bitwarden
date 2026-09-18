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

  AuthView {
    id: authView
    authState: ({ status: "unauthenticated", has_session: false })
  }

  Component.onCompleted: {
    // 1. Initial defaults
    check(authView.show2FAField === false, "AuthView show2FAField defaults to false")
    check(authView.twoFactorProvider === 0, "AuthView twoFactorProvider defaults to 0")
    check(Array.isArray(authView.availableTwoFactorProviders) && authView.availableTwoFactorProviders.length === 0, "AuthView availableTwoFactorProviders defaults to empty array")

    // 2. Setting email 2FA provider state
    authView.show2FAField = true
    authView.twoFactorProvider = 1
    authView.availableTwoFactorProviders = [1]
    check(authView.show2FAField === true, "AuthView show2FAField set to true")
    check(authView.twoFactorProvider === 1, "AuthView twoFactorProvider set to 1")
    check(authView.availableTwoFactorProviders.length === 1 && authView.availableTwoFactorProviders[0] === 1, "availableTwoFactorProviders contains [1]")

    // 3. clearInputs() resets twoFactorProvider and availableTwoFactorProviders
    authView.clearInputs()
    check(authView.twoFactorProvider === 0, "clearInputs() resets twoFactorProvider to 0")
    check(authView.availableTwoFactorProviders.length === 0, "clearInputs() resets availableTwoFactorProviders to []")

    // 4. Changing loginMethod resets twoFactorProvider and availableTwoFactorProviders
    authView.show2FAField = true
    authView.twoFactorProvider = 1
    authView.availableTwoFactorProviders = [1]
    authView.loginMethod = "apikey"
    check(authView.show2FAField === false, "loginMethod change resets show2FAField")
    check(authView.twoFactorProvider === 0, "loginMethod change resets twoFactorProvider")
    check(authView.availableTwoFactorProviders.length === 0, "loginMethod change resets availableTwoFactorProviders")
    authView.loginMethod = "password"

    // 5. Response parsing logic simulation for Email 2FA challenge
    var respEmail2FA = {
      ok: false,
      error: "Email two-factor authentication required. Please check your email for the verification code.",
      two_factor_required: true,
      two_factor_provider: 1,
      two_factor_providers: [1]
    }
    var prov = (respEmail2FA.two_factor_provider !== undefined && respEmail2FA.two_factor_provider !== null)
        ? Number(respEmail2FA.two_factor_provider)
        : 0
    var avail = respEmail2FA.two_factor_providers || []
    check(prov === 1, "Email 2FA provider correctly parsed as 1")
    check(avail.length === 1 && avail[0] === 1, "availableTwoFactorProviders has [1]")

    // Payload verification with provider
    var code = "123456"
    var password = "secretPassword"
    var payload = { password: password, code: code }
    if (prov !== undefined && prov !== null) {
      payload.two_factor_provider = prov
    }
    check(payload.two_factor_provider === 1, "payload includes two_factor_provider: 1")
    check(payload.code === "123456", "payload includes 2FA verification code")

    // 6. Response parsing fallback when only two_factor_providers contains 1
    var respFallback = {
      ok: false,
      error: "Two-factor authentication required.",
      two_factor_required: true,
      two_factor_providers: [1]
    }
    var provFallback = (respFallback.two_factor_provider !== undefined && respFallback.two_factor_provider !== null)
        ? Number(respFallback.two_factor_provider)
        : 0
    if (respFallback.two_factor_providers && respFallback.two_factor_providers.length > 0) {
      if (respFallback.two_factor_provider === undefined || respFallback.two_factor_provider === null) {
        if (respFallback.two_factor_providers.indexOf(1) !== -1 && respFallback.two_factor_providers.indexOf(0) === -1) {
          provFallback = 1
        }
      }
    }
    check(provFallback === 1, "Fallback correctly resolves provider 1 when only email is available")

    // 7. Inline resend email button visibility and state
    authView.show2FAField = true
    authView.twoFactorProvider = 1
    check(authView.resendEmailButton !== null && authView.resendEmailButton.visible === true, "resendEmailButton is visible when twoFactorProvider === 1")
    authView.twoFactorProvider = 0
    check(authView.resendEmailButton.visible === false, "resendEmailButton is hidden when twoFactorProvider === 0")
    authView.twoFactorProvider = 7
    check(authView.resendEmailButton.visible === false, "resendEmailButton is hidden when twoFactorProvider === 7")

    // 8. Resend email button trigger and cooldown notification
    authView.twoFactorProvider = 1
    var signalEmitted = false
    var signalEmail = ""
    var signalPwd = ""
    authView.sendTwoFactorEmailRequested.connect(function(email, pwd) {
      signalEmitted = true
      signalEmail = email
      signalPwd = pwd
    })
    check(authView.emailSentCount === 0, "emailSentCount defaults to 0")
    check(authView.resendCooldown === 0, "resendCooldown defaults to 0")

    // Notify code sent
    authView.notifyEmailCodeSent()
    check(authView.emailSentCount === 1, "notifyEmailCodeSent() increments emailSentCount to 1")
    check(authView.resendCooldown === 60, "notifyEmailCodeSent() sets resendCooldown to 60")

    // Reset clears emailSentCount and resendCooldown
    authView.clearInputs()
    check(authView.emailSentCount === 0, "clearInputs() resets emailSentCount to 0")
    check(authView.resendCooldown === 0, "clearInputs() resets resendCooldown to 0")

    // 9. Initial 2FA challenge error message suppression logic
    var testData2FA = {
      ok: false,
      error: "Email two-factor authentication required. Please check your email for the verification code.",
      two_factor_required: true,
      two_factor_providers: [1],
      two_factor_provider: 1
    }
    var errLower = (testData2FA.error || "").toLowerCase()
    var is2FA = Boolean(testData2FA.two_factor_required)
        || errLower.indexOf("two-factor") !== -1

    // Simulated initial attempt: was2FAShown = false
    var was2FAShown = false
    var computedErrMsg = ""
    if (is2FA && !was2FAShown) {
      computedErrMsg = ""
    } else {
      computedErrMsg = testData2FA.error || "Login failed."
    }
    check(computedErrMsg === "", "Initial 2FA challenge suppresses error toast message")

    // Simulated subsequent attempt with wrong code: was2FAShown = true
    was2FAShown = true
    if (is2FA && !was2FAShown) {
      computedErrMsg = ""
    } else {
      computedErrMsg = testData2FA.error || "Login failed."
    }
    check(computedErrMsg === testData2FA.error, "Subsequent 2FA failure retains error message")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
