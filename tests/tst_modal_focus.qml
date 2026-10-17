import QtQuick
import QtQuick.Controls

Item {
  id: testRunner
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  // Simulation harness mirroring OmarchyBitwarden properties
  property bool opened: true
  property string effectiveView: "search"
  property var authState: ({ status: "unlocked", has_session: true })
  property var config: ({ remember_last_search: false })
  property var selectedItem: ({ id: "item1", name: "Sample Item" })

  property bool showActionPalette: false
  property bool showSshKeyModal: false
  property bool showPasswordHistoryModal: false
  property bool showPasswordGeneratorModal: false

  readonly property bool hasActiveModal: showActionPalette || showSshKeyModal || showPasswordHistoryModal || showPasswordGeneratorModal

  property int searchFocusRestoredCount: 0

  function simulateFocusRestore() {
    if (opened && effectiveView === "search" && !hasActiveModal) {
      searchFocusRestoredCount++
    }
  }

  // Helper simulating focusRoot.Keys.onPressed handler checks
  function canTriggerScopeShortcut() {
    return (effectiveView === "search" && !hasActiveModal)
  }

  function canTriggerToggleRevealed() {
    return (showPasswordHistoryModal || (effectiveView === "search" && selectedItem !== null && !hasActiveModal))
  }

  Component.onCompleted: {
    console.log("Running Modal Focus and Background Sync Guard Tests...")

    // 1. Initial State: no modals active
    check(hasActiveModal === false, "Initial hasActiveModal is false")
    check(canTriggerScopeShortcut() === true, "Scope shortcuts (Alt+V / Alt+F) enabled when no modals active")
    check(canTriggerToggleRevealed() === true, "Toggle revealed (Ctrl+T) enabled when no modals active")

    // 2. SSH Key modal active
    showSshKeyModal = true
    check(hasActiveModal === true, "hasActiveModal is true when showSshKeyModal is true")
    check(canTriggerScopeShortcut() === false, "Scope shortcuts inhibited during SSH Key modal")
    check(canTriggerToggleRevealed() === false, "Toggle revealed inhibited during SSH Key modal")

    searchFocusRestoredCount = 0
    simulateFocusRestore()
    check(searchFocusRestoredCount === 0, "Background focus restore is inhibited when SSH Key modal is active")

    showSshKeyModal = false
    check(hasActiveModal === false, "hasActiveModal is false after closing SSH Key modal")
    check(canTriggerScopeShortcut() === true, "Scope shortcuts re-enabled after closing SSH Key modal")

    // 3. Password History modal active
    showPasswordHistoryModal = true
    check(hasActiveModal === true, "hasActiveModal is true when showPasswordHistoryModal is true")
    check(canTriggerScopeShortcut() === false, "Scope shortcuts inhibited during Password History modal")
    check(canTriggerToggleRevealed() === true, "Toggle revealed explicitly permitted during Password History modal")

    searchFocusRestoredCount = 0
    simulateFocusRestore()
    check(searchFocusRestoredCount === 0, "Background focus restore is inhibited when Password History modal is active")

    showPasswordHistoryModal = false
    check(hasActiveModal === false, "hasActiveModal is false after closing Password History modal")

    // 4. Action Palette active
    showActionPalette = true
    check(hasActiveModal === true, "hasActiveModal is true when showActionPalette is true")
    check(canTriggerScopeShortcut() === false, "Scope shortcuts inhibited during Action Palette")
    check(canTriggerToggleRevealed() === false, "Toggle revealed inhibited during Action Palette")

    searchFocusRestoredCount = 0
    simulateFocusRestore()
    check(searchFocusRestoredCount === 0, "Background focus restore is inhibited when Action Palette is active")

    showActionPalette = false
    check(hasActiveModal === false, "hasActiveModal is false after closing Action Palette")

    // 5. Password Generator modal active
    showPasswordGeneratorModal = true
    check(hasActiveModal === true, "hasActiveModal is true when showPasswordGeneratorModal is true")
    check(canTriggerScopeShortcut() === false, "Scope shortcuts inhibited during Password Generator modal")
    check(canTriggerToggleRevealed() === false, "Toggle revealed inhibited during Password Generator modal")

    searchFocusRestoredCount = 0
    simulateFocusRestore()
    check(searchFocusRestoredCount === 0, "Background focus restore is inhibited when Password Generator modal is active")

    showPasswordGeneratorModal = false
    check(hasActiveModal === false, "hasActiveModal is false after closing Password Generator modal")

    // 5. No modals: focus restore executes
    searchFocusRestoredCount = 0
    simulateFocusRestore()
    check(searchFocusRestoredCount === 1, "Background focus restore proceeds when no modals are active")

    // 6. Test legacy unguarded behavior vs guarded behavior
    // The bug was: condition only checked !showActionPalette
    var legacyGuardSshModal = (!showActionPalette) // would be true even if showSshKeyModal is true!
    showSshKeyModal = true
    check(legacyGuardSshModal === true, "Legacy guard would erroneously pass during SSH Key modal")
    check(!hasActiveModal === false, "New unified guard correctly blocks focus steal during SSH Key modal")

    showSshKeyModal = false
    showPasswordHistoryModal = true
    var legacyGuardHistoryModal = (!showActionPalette) // would be true even if showPasswordHistoryModal is true!
    check(legacyGuardHistoryModal === true, "Legacy guard would erroneously pass during Password History modal")
    check(!hasActiveModal === false, "New unified guard correctly blocks focus steal during Password History modal")

    showPasswordHistoryModal = false

    console.log("Modal Focus Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
