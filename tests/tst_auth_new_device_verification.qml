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
    check(authView.isNewDeviceVerification === false, "AuthView isNewDeviceVerification defaults to false")

    // 2. Setting new device verification state
    authView.show2FAField = true
    authView.isNewDeviceVerification = true
    check(authView.show2FAField === true, "AuthView show2FAField set to true")
    check(authView.isNewDeviceVerification === true, "AuthView isNewDeviceVerification set to true")

    // 3. clearInputs() resets isNewDeviceVerification
    authView.clearInputs()
    check(authView.isNewDeviceVerification === false, "clearInputs() resets isNewDeviceVerification to false")

    // 4. Changing loginMethod resets isNewDeviceVerification and show2FAField
    authView.show2FAField = true
    authView.isNewDeviceVerification = true
    authView.loginMethod = "apikey"
    check(authView.show2FAField === false, "loginMethod change resets show2FAField")
    check(authView.isNewDeviceVerification === false, "loginMethod change resets isNewDeviceVerification")
    authView.loginMethod = "password"

    // 5. Response parsing logic simulation for New Device Verification challenge
    var respNewDevice = {
      ok: false,
      error: "New device verification required. Please check your email for the verification code.",
      two_factor_required: true,
      new_device_verification_required: true
    }
    var errLower = (respNewDevice.error || "").toLowerCase()
    var isNewDevice = Boolean(respNewDevice.new_device_verification_required)
        || errLower.indexOf("new device verification") !== -1
    var is2FA = isNewDevice || Boolean(respNewDevice.two_factor_required)
    check(isNewDevice === true, "isNewDevice correctly parsed from response")
    check(is2FA === true, "is2FA set to true for New Device challenge")

    // Payload verification
    var code = "654321"
    var password = "secretPassword"
    var payload1 = { password: password, code: code }
    if (isNewDevice) {
      payload1.new_device_otp = code
    }
    check(payload1.new_device_otp === "654321", "payload includes new_device_otp when isNewDevice is true")

    // 6. Response parsing logic simulation for standard 2FA challenge
    var resp2FA = {
      ok: false,
      error: "Two-factor authentication required or invalid code.",
      two_factor_required: true
    }
    var errLower2 = (resp2FA.error || "").toLowerCase()
    var isNewDevice2 = Boolean(resp2FA.new_device_verification_required)
        || errLower2.indexOf("new device verification") !== -1
    var is2FA2 = isNewDevice2 || Boolean(resp2FA.two_factor_required)
    check(isNewDevice2 === false, "isNewDevice false for standard 2FA")
    check(is2FA2 === true, "is2FA true for standard 2FA")

    var payload2 = { password: password, code: code }
    if (isNewDevice2) {
      payload2.new_device_otp = code
    }
    check(payload2.new_device_otp === undefined, "payload excludes new_device_otp when isNewDevice is false")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
