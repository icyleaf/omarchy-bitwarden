import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components"

Item {
  id: testRunner
  width: 800; height: 600

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  property var selections: []
  property var boundSelections: []
  property int closeRequests: 0

  TypePickerModal {
    id: modal
    // The picker never closes itself: the parent owns `active` (so the
    // `active: root.showTypePicker` binding survives). These handlers mirror
    // the OmarchyBitwarden wiring.
    onTypeSelected: function(cipherType) {
      selections.push(cipherType)
      modal.active = false
    }
    onCloseRequested: {
      closeRequests++
      modal.active = false
    }
  }

  // The Text item under `item` showing exactly `text`, if any.
  function findText(item, text) {
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].text === text) return kids[i]
      var found = findText(kids[i], text)
      if (found) return found
    }
    return null
  }

  Component.onCompleted: {
    console.log("Running TypePickerModal Keyboard Workflow Tests...")

    // 1. Initial state: hidden until activated
    check(modal.visible === false, "hidden when inactive")
    check(modal.selectedIndex === 0, "Login is the default selection")

    // 2. Activation shows the centered picker with Login, Secure Note, Card, and SSH Key
    modal.active = true
    check(modal.visible === true, "visible when active")
    check(findText(modal, "Login") !== null, "a Text shows Login")
    check(findText(modal, "Secure Note") !== null, "a Text shows Secure Note")
    check(findText(modal, "Card") !== null, "a Text shows Card")
    check(findText(modal, "SSH Key") !== null, "a Text shows SSH Key")
    check(findText(modal, "L") !== null, "a Text shows the L hint")
    check(findText(modal, "N") !== null, "a Text shows the N hint")
    check(findText(modal, "C") !== null, "a Text shows the C hint")
    check(findText(modal, "S") !== null, "a Text shows the S hint")

    // 3. Single-key L picks Login immediately and closes the picker
    modal.handleKey(Qt.Key_L, Qt.NoModifier)
    check(selections.length === 1 && selections[0] === "login", "single-key L emits typeSelected(\"login\")")
    check(modal.active === false, "picker closes after picking Login")

    // 4. A fresh picker always starts on Login
    modal.active = true
    check(modal.selectedIndex === 0, "selection resets to Login on reopen")

    // 5. Single-key N picks Secure Note immediately
    modal.handleKey(Qt.Key_N, Qt.NoModifier)
    check(selections.length === 2 && selections[1] === "note", "single-key N emits typeSelected(\"note\")")
    check(modal.active === false, "picker closes after picking Secure Note")

    // 5b. Single-key C picks Card immediately
    modal.active = true
    modal.handleKey(Qt.Key_C, Qt.NoModifier)
    check(selections.length === 3 && selections[2] === "card", "single-key C emits typeSelected(\"card\")")
    check(modal.active === false, "picker closes after picking Card")

    // 5c. Single-key S picks SSH Key immediately
    modal.active = true
    modal.handleKey(Qt.Key_S, Qt.NoModifier)
    check(selections.length === 4 && selections[3] === "ssh_key", "single-key S emits typeSelected(\"ssh_key\")")
    check(modal.active === false, "picker closes after picking SSH Key")

    // 6. Arrow navigation moves across the four choices and Enter confirms
    modal.active = true
    modal.handleKey(Qt.Key_Down, Qt.NoModifier)
    check(modal.selectedIndex === 1, "Down moves selection to Secure Note")
    modal.handleKey(Qt.Key_Down, Qt.NoModifier)
    check(modal.selectedIndex === 2, "Down moves selection to Card")
    modal.handleKey(Qt.Key_Down, Qt.NoModifier)
    check(modal.selectedIndex === 3, "Down moves selection to SSH Key")
    modal.handleKey(Qt.Key_Down, Qt.NoModifier)
    check(modal.selectedIndex === 0, "Down wraps back to Login")
    modal.handleKey(Qt.Key_Up, Qt.NoModifier)
    check(modal.selectedIndex === 3, "Up wraps back to SSH Key")
    modal.handleKey(Qt.Key_Return, Qt.NoModifier)
    check(selections.length === 5 && selections[4] === "ssh_key", "Enter confirms the highlighted option (ssh_key)")
    check(modal.active === false, "picker closes after Enter")

    // 7. Enter on the default selection confirms Login
    modal.active = true
    modal.handleKey(Qt.Key_Enter, Qt.NoModifier)
    check(selections.length === 6 && selections[5] === "login", "Enter confirms Login by default")

    // 8. Repeated Ctrl+N cycles the selection while the picker is open
    modal.active = true
    modal.handleKey(Qt.Key_N, Qt.ControlModifier)
    check(modal.selectedIndex === 1, "Ctrl+N cycles Login -> Secure Note")
    modal.handleKey(Qt.Key_N, Qt.ControlModifier)
    check(modal.selectedIndex === 2, "Ctrl+N cycles Secure Note -> Card")
    modal.handleKey(Qt.Key_N, Qt.ControlModifier)
    check(modal.selectedIndex === 3, "Ctrl+N cycles Card -> SSH Key")
    modal.handleKey(Qt.Key_N, Qt.ControlModifier)
    check(modal.selectedIndex === 0, "Ctrl+N cycles SSH Key -> Login")
    check(selections.length === 6, "cycling with Ctrl+N does not select anything")
    modal.handleKey(Qt.Key_N, Qt.ControlModifier)
    modal.handleKey(Qt.Key_Return, Qt.NoModifier)
    check(selections.length === 7 && selections[6] === "note", "Enter after cycling confirms Secure Note")

    // 9. Modifier-stacked letter presses are not single-key shortcuts
    modal.active = true
    modal.handleKey(Qt.Key_L, Qt.ControlModifier)
    check(selections.length === 7, "Ctrl+L is ignored (not a single-key pick)")
    modal.active = false

    // 10. Esc dismisses the picker without selecting anything
    var closesBefore = closeRequests
    modal.active = true
    modal.handleKey(Qt.Key_Escape, Qt.NoModifier)
    check(closeRequests === closesBefore + 1, "Esc emits closeRequested()")
    check(modal.active === false, "Esc closes the picker")
    check(selections.length === 7, "Esc does not emit typeSelected()")

    // 11. Theme contract: default colors bind to the dynamic theme tokens
    check(modal.foreground === Commons.Color.foreground, "foreground binds to Color.foreground")
    check(modal.accent === Commons.Color.accent, "accent binds to Color.accent")
    check(modal.muted === Commons.Color.muted, "muted binds to Color.muted")
    check(modal.cardBackground === Commons.Color.popups.background, "cardBackground binds to Color.popups.background")
    check(modal.borderColor === Commons.Color.popups.border, "borderColor binds to Color.popups.border")

    console.log("TypePickerModal Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
  }

  // Regression: an `active` binding (like the real `active: root.showTypePicker`
  // wiring) must survive pick and dismiss cycles instead of being broken by an
  // imperative write inside the component.
  Item {
    id: pickerProxy
    property bool shown: false
  }

  TypePickerModal {
    id: boundModal
    active: pickerProxy.shown
    onTypeSelected: function(cipherType) {
      boundSelections.push(cipherType)
      pickerProxy.shown = false
    }
    onCloseRequested: pickerProxy.shown = false
  }

  Timer {
    interval: 1
    running: true
    onTriggered: {
      pickerProxy.shown = true
      check(boundModal.visible === true, "bound picker opens through the active binding")
      boundModal.handleKey(Qt.Key_L, Qt.NoModifier)
      check(boundSelections.length === 1 && boundSelections[0] === "login", "bound picker picks Login")
      check(pickerProxy.shown === false, "bound picker closes through the parent handler")
      pickerProxy.shown = true
      check(boundModal.visible === true, "bound picker reopens after a pick (binding preserved)")
      boundModal.handleKey(Qt.Key_Escape, Qt.NoModifier)
      check(pickerProxy.shown === false, "bound picker closes on Esc")
      pickerProxy.shown = true
      check(boundModal.visible === true, "bound picker reopens after Esc (binding preserved)")
      boundModal.handleKey(Qt.Key_N, Qt.NoModifier)
      check(boundSelections.length === 2 && boundSelections[1] === "note", "bound picker picks Secure Note on reopen")

      console.log("TypePickerModal Binding Regression Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
      Qt.exit(failures === 0 ? 0 : 1)
    }
  }
}
