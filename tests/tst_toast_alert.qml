import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner
  width: 880
  height: 560

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  ToastAlert {
    id: toast
    errorMessage: "Email two-factor authentication required. Please check your email for the verification code."
  }

  property int testStep: 0

  Timer {
    id: testTimer
    interval: 50
    repeat: true
    running: true
    onTriggered: {
      testStep++
      if (testStep === 1) {
        // 1. Initial Email 2FA message is wide enough and not truncated
        check(toast.maxMessageWidth === 560, "ToastAlert maxMessageWidth is 560px")
        check(toast.implicitWidth > 450, "Toast expanded to accommodate full 2FA message (width: " + Math.round(toast.implicitWidth) + "px)")

        // Switch to short message
        toast.errorMessage = "Quick alert"
      } else if (testStep === 2) {
        // 2. Short message keeps toast compact
        var shortWidth = Math.round(toast.implicitWidth)
        check(shortWidth < 200, "Short message keeps toast compact (width: " + shortWidth + "px)")

        // Switch to very long message
        toast.errorMessage = "This is an extraordinarily long error message intended to exceed the maximum allowed width of the toast alert component and verify that the layout maximum width constraint and truncation mechanisms work properly."
      } else if (testStep === 3) {
        // 3. Excessively long message is bounded
        var boundedWidth = Math.round(toast.implicitWidth)
        check(boundedWidth <= toast.maxMessageWidth + 60, "Excessively long message is bounded (width: " + boundedWidth + "px)")

        testTimer.stop()
        Qt.exit(failures === 0 ? 0 : 1)
      }
    }
  }
}
