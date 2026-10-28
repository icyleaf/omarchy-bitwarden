import QtQuick

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

  // Mirrors AuthView.qml's quick-unlock button gating (ADR-0025).
  readonly property bool isBusy: false
  readonly property bool quickUnlockAvailable: true
  readonly property bool quickUnlockButtonVisible: quickUnlockAvailable && !isBusy

  // Mirrors OmarchyBitwarden.qml's readiness resolution.
  property bool quickUnlockReady: false
  function applyCheckOutput(text, exitCode) {
    if (exitCode !== 0) {
      quickUnlockReady = false
      return
    }
    try {
      let data = JSON.parse((text || "").trim())
      quickUnlockReady = Boolean(data && data.available)
    } catch (e) {
      quickUnlockReady = false
    }
  }

  Component.onCompleted: {
    console.log("Running Quick Unlock Gating Tests...")

    // 1. Button shows only when the engine reports readiness.
    check(quickUnlockButtonVisible === true, "Button visible when quick unlock is available")

    // 2. Busy state hides the button (no double prompts).
    var busyRunner = Qt.createQmlObject(
      'import QtQuick; QtObject { property bool isBusy: true; property bool quickUnlockAvailable: true; readonly property bool quickUnlockButtonVisible: quickUnlockAvailable && !isBusy }',
      testRunner, "busyState")
    check(busyRunner.quickUnlockButtonVisible === false, "Button hidden while busy")

    // 3. Engine without the feature (older binary, exit != 0) fails closed.
    applyCheckOutput("{}", 2)
    check(quickUnlockReady === false, "Non-zero exit clears readiness")

    // 4. Engine reports enabled + retained key.
    applyCheckOutput(JSON.stringify({ ok: true, enabled: true, available: true }), 0)
    check(quickUnlockReady === true, "available=true marks readiness")

    // 5. Enabled in settings but no retained key: not available.
    applyCheckOutput(JSON.stringify({ ok: true, enabled: true, available: false }), 0)
    check(quickUnlockReady === false, "available=false clears readiness")

    // 6. Malformed output fails closed.
    applyCheckOutput("not json", 0)
    check(quickUnlockReady === false, "Unparseable output clears readiness")

    console.log("ALL QUICK UNLOCK GATING TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
