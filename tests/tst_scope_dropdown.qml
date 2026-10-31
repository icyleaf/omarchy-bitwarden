import QtQuick
import QtQuick.Controls
import "../components"
import "lib"

ApplicationWindow {
  id: testRunner
  visible: true
  width: 400
  height: 300

  property bool selectionEmitted: false
  property string selectedScopeId: ""
  property bool resetEmitted: false
  property bool closedEmitted: false

  ScopeDropdown {
    id: dropdown
    title: "Vault"
    currentValue: "all"
    items: [
      { id: "all", name: "All Vaults", icon: "\uf009", count: 10 },
      { id: "personal", name: "Personal", icon: "\uf007", count: 4 },
      { id: "org-1", name: "Acme Corp", icon: "\uf1ad", count: 6 }
    ]
    onSelected: function(id) {
      testRunner.selectionEmitted = true
      testRunner.selectedScopeId = id
    }
    onResetRequested: {
      testRunner.resetEmitted = true
    }
    onClosed: {
      testRunner.closedEmitted = true
    }
  }

  Timer {
    id: testTimer
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running ScopeDropdown Automated Tests...")

      // 1. Initial State
      Assert.check(dropdown.isFiltered === false, "Initially isFiltered is false")
      Assert.check(dropdown.currentItem !== null, "currentItem is not null")
      Assert.check(dropdown.currentItem.id === "all", "currentItem.id is 'all'")
      Assert.check(dropdown.isOpen === false, "Dropdown is initially closed")

      // 2. Open & Close
      dropdown.open()
      Assert.check(dropdown.isOpen === true, "dropdown.open() sets isOpen to true")
      dropdown.close()
      Assert.check(dropdown.isOpen === false, "dropdown.close() sets isOpen to false")
      Assert.check(testRunner.closedEmitted === true, "closed signal was emitted on close")

      // 3. Selection
      dropdown.selected("org-1")
      Assert.check(testRunner.selectionEmitted === true, "selected signal was emitted")
      Assert.check(testRunner.selectedScopeId === "org-1", "selectedScopeId is 'org-1'")

      dropdown.currentValue = "org-1"
      Assert.check(dropdown.isFiltered === true, "isFiltered is true when currentValue is 'org-1'")
      Assert.check(dropdown.currentItem.name === "Acme Corp", "currentItem reactive update reflects 'Acme Corp'")

      // 4. Open with active value -> pre-selects correct index (2)
      dropdown.open()
      Assert.check(dropdown.isOpen === true, "dropdown.open() with active filter")
      dropdown.close()

      // 5. Reset
      dropdown.currentValue = "all"
      Assert.check(dropdown.isFiltered === false, "isFiltered is false after reset to 'all'")
      Assert.check(dropdown.currentItem.id === "all", "currentItem is 'all'")

      // 6. Cycle Next
      dropdown.cycleNext()
      Assert.check(testRunner.selectedScopeId === "personal", "cycleNext from 'all' selects 'personal'")
      dropdown.currentValue = "personal"
      dropdown.cycleNext()
      Assert.check(testRunner.selectedScopeId === "org-1", "cycleNext from 'personal' selects 'org-1'")
      dropdown.currentValue = "org-1"
      dropdown.cycleNext()
      Assert.check(testRunner.selectedScopeId === "all", "cycleNext from 'org-1' cycles back to 'all'")

      if (Assert.failures === 0)
        console.log("All ScopeDropdown tests passed successfully!")
      Qt.exit(Assert.exitCode())
    }
  }
}
