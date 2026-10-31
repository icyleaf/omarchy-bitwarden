import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  // The REAL AuthView under the stub Commons harness: a rename of the quick
  // unlock properties, a re-binding of the visibility expression or an
  // unhooked signal must fail this suite instead of drifting silently.
  AuthView {
    id: authView
    authState: ({ status: "locked", has_session: true })
    onQuickUnlockRequested: quickUnlocks++
  }
  property int quickUnlocks: 0

  // Mirrors OmarchyBitwarden.qml's readiness resolution (auth
  // quick-unlock-check output); kept as is.
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

  // Depth-first search for the Text item showing exactly `text`.
  function findText(item, text) {
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].text === text) return kids[i]
      var found = findText(kids[i], text)
      if (found) return found
    }
    return null
  }

  // The quick unlock card is the Rectangle directly parenting the labeled
  // Text (and the MouseArea that emits the signal).
  function quickUnlockButton() {
    var label = findText(authView, "Unlock with System Authentication")
    return label ? label.parent : null
  }

  function findMouseArea(item) {
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i] instanceof MouseArea) return kids[i]
      var found = findMouseArea(kids[i])
      if (found) return found
    }
    return null
  }

  function readSource(path) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", path, false)
    xhr.send()
    return xhr.responseText
  }

  Component.onCompleted: {
    console.log("Running Quick Unlock Gating Tests...")

    // --- Real AuthView: the button exists and is fail-closed by default.
    var button = quickUnlockButton()
    check(button !== null, "quick unlock button exists in AuthView (label drift fails here)")
    if (button) {
      check(authView.quickUnlockAvailable === false, "AuthView quickUnlockAvailable defaults to false")
      check(button.visible === false, "button hidden by default (feature off)")

      // 1. Button shows only when the engine reports readiness.
      authView.quickUnlockAvailable = true
      authView.isBusy = false
      check(button.visible === true, "button visible when quick unlock is available")

      // 2. Busy state hides the button (no double prompts).
      authView.isBusy = true
      check(button.visible === false, "button hidden while busy")
      authView.isBusy = false
      check(button.visible === true, "button returns when the prompt finishes")

      // 3. A click emits quickUnlockRequested (wired through the MouseArea).
      quickUnlocks = 0
      var ma = findMouseArea(button)
      check(ma !== null, "the quick unlock card contains a click target")
      if (ma) {
        ma.clicked(null)
        check(quickUnlocks === 1, "clicking the card emits quickUnlockRequested")
        ma.clicked(null)
        check(quickUnlocks === 2, "every click emits quickUnlockRequested")
      }
      authView.quickUnlockAvailable = false
      check(button.visible === false, "readiness lost hides the button again")
    }

    // --- Root wiring source-grep: OmarchyBitwarden.qml must feed the real
    // readiness into AuthView and route the signal back to doQuickUnlock().
    // This is what fails when the root side drifts (renamed property,
    // unhooked handler), which an in-component mirror cannot see. Reading
    // the file needs QML_XHR_ALLOW_FILE_READ=1 (set by scripts/test-all.sh);
    // an unreadable source fails the suite rather than skipping it.
    var src = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    check(src.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")
    var authViewIdx = src.indexOf("AuthView {")
    check(authViewIdx !== -1, "OmarchyBitwarden.qml instantiates AuthView")
    var wiring = authViewIdx !== -1 ? src.substring(authViewIdx) : ""
    check(wiring.indexOf("quickUnlockAvailable: root.quickUnlockReady") !== -1,
          "AuthView is wired to root.quickUnlockReady")
    check(wiring.indexOf("onQuickUnlockRequested: root.doQuickUnlock()") !== -1,
          "quickUnlockRequested is wired to root.doQuickUnlock()")
    // The 3s auth-status poll must not spawn a second helper while unlocked:
    // readiness is only meaningful on the locked view, and the lock
    // transition refreshes it from the auth-status handler instead.
    check(src.indexOf('root.authState.status !== "unlocked"') !== -1,
          "readiness polling is skipped while the vault is unlocked")

    // --- Readiness parsing mirror (auth quick-unlock-check output).
    // 4. Engine without the feature (older binary, exit != 0) fails closed.
    applyCheckOutput("{}", 2)
    check(quickUnlockReady === false, "Non-zero exit clears readiness")

    // 5. Engine reports enabled + retained key.
    applyCheckOutput(JSON.stringify({ ok: true, enabled: true, available: true }), 0)
    check(quickUnlockReady === true, "available=true marks readiness")

    // 6. Enabled in settings but no retained key: not available.
    applyCheckOutput(JSON.stringify({ ok: true, enabled: true, available: false }), 0)
    check(quickUnlockReady === false, "available=false clears readiness")

    // 7. Malformed output fails closed.
    applyCheckOutput("not json", 0)
    check(quickUnlockReady === false, "Unparseable output clears readiness")

    if (failures === 0) {
      console.log("ALL QUICK UNLOCK GATING TESTS PASSED!")
    } else {
      console.error(failures + " QUICK UNLOCK GATING TEST(S) FAILED")
    }
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
