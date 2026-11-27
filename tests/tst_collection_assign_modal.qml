import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components" as Components
import "../components/CipherMutation.js" as CipherMutation
import "lib"

Item {
  id: testRunner
  width: 800
  height: 600

  property int confirmCount: 0
  property var lastColIds: []
  property int closeCount: 0

  Components.CollectionAssignModal {
    id: assignModal
    width: 800
    height: 600
    active: false
    itemName: "Org Prod DB"
    organizationId: "org-1"
    organizationName: "Acme Corp"
    initialCollectionIds: ["col-ro", "col-w1"]
    collections: [
      { id: "col-w1", organization_id: "org-1", name: "Engineering", read_only: false, hide_passwords: false, manage: false },
      { id: "col-w2", organization_id: "org-1", name: "Platform", read_only: false, hide_passwords: false, manage: false },
      { id: "col-m1", organization_id: "org-1", name: "Ops Managed", read_only: true, hide_passwords: false, manage: true },
      { id: "col-ro", organization_id: "org-1", name: "Audit ReadOnly", read_only: true, hide_passwords: true, manage: false },
      { id: "col-other", organization_id: "org-2", name: "Other Org", read_only: false, hide_passwords: false, manage: false }
    ]
    onConfirmRequested: function(colIds) {
      testRunner.confirmCount++
      testRunner.lastColIds = colIds
    }
    onCloseRequested: {
      testRunner.closeCount++
    }
  }

  Timer {
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running CollectionAssignModal & CipherMutation.canAssignCollections Tests...")

      // 1. CipherMutation.canAssignCollections & guard errors across permissions and ownership
      var types = ["login", "note", "card", "identity", "ssh_key"]
      for (var t = 0; t < types.length; t++) {
        Assert.check(
          CipherMutation.canAssignCollections({ id: "p-" + t, type_name: types[t], edit: true, view_password: true }) === false,
          "canAssignCollections is false for personal " + types[t]
        )
        Assert.check(
          CipherMutation.canAssignCollections({ id: "o-ok-" + t, type_name: types[t], organization_id: "org-1", edit: true, view_password: true }) === true,
          "canAssignCollections is true for Organization " + types[t] + " with edit && view_password"
        )
        Assert.check(
          CipherMutation.canAssignCollections({ id: "o-ro-" + t, type_name: types[t], organization_id: "org-1", edit: false, view_password: true }) === false,
          "canAssignCollections is false for Organization " + types[t] + " with edit: false"
        )
        Assert.check(
          CipherMutation.canAssignCollections({ id: "o-hp-" + t, type_name: types[t], organization_id: "org-1", edit: true, view_password: false }) === false,
          "canAssignCollections is false for Organization " + types[t] + " with view_password: false"
        )
        Assert.check(
          CipherMutation.canAssignCollections({ id: "o-tr-" + t, type_name: types[t], organization_id: "org-1", edit: true, view_password: true, deleted_at: "2026-01-01T00:00:00Z" }) === false,
          "canAssignCollections is false for trashed Organization " + types[t]
        )
      }

      var noEditErr = CipherMutation.assignCollectionsGuardError({ id: "o1", type_name: "login", organization_id: "org-1", edit: false, view_password: true })
      Assert.check(noEditErr.indexOf("permission") !== -1, "assignCollectionsGuardError explains missing edit permission")

      var hiddenPwErr = CipherMutation.assignCollectionsGuardError({ id: "o2", type_name: "login", organization_id: "org-1", edit: true, view_password: false })
      Assert.check(hiddenPwErr.indexOf("passwords are hidden") !== -1, "assignCollectionsGuardError explains hidden passwords guard")

      // 2. CipherMutation.withoutItem pure eviction helper (for unavailable: true convergence)
      var items = [{ id: "a", name: "Alpha" }, { id: "b", name: "Beta" }, { id: "c", name: "Gamma" }]
      var evicted = CipherMutation.withoutItem(items, "b")
      Assert.check(evicted.length === 2 && evicted[0].id === "a" && evicted[1].id === "c", "withoutItem removes target item without mutating source list")
      Assert.check(items.length === 3, "source list remains immutable after withoutItem")

      // 3. Opening modal loads all Org collections (including read-only) and pre-selects initialCollectionIds
      assignModal.active = true
      Assert.check(
        assignModal.orgCollections.length === 4,
        "all 4 collections for org-1 appear (excluding org-2)"
      )
      Assert.check(
        assignModal.isCollectionSelected("col-ro") && assignModal.isCollectionSelected("col-w1"),
        "initialCollectionIds are pre-selected when modal opens"
      )
      Assert.check(assignModal.canSubmit === true, "canSubmit is true when initial collections are selected")

      // 4. Non-writable collection (read_only && !manage) is locked and cannot be toggled off
      assignModal.toggleCollection("col-ro")
      Assert.check(
        assignModal.isCollectionSelected("col-ro") === true,
        "locked read-only collection cannot be unchecked"
      )

      // 5. Writable collections (including manage: true) can be toggled
      assignModal.toggleCollection("col-w1")
      assignModal.toggleCollection("col-w2")
      assignModal.toggleCollection("col-m1")
      Assert.check(
        !assignModal.isCollectionSelected("col-w1")
          && assignModal.isCollectionSelected("col-w2")
          && assignModal.isCollectionSelected("col-m1")
          && assignModal.isCollectionSelected("col-ro"),
        "writable and manage:true collections toggle cleanly while preserving locked read-only collection"
      )

      // 6. Submit emits confirmRequested with full target collection IDs
      assignModal.submit()
      Assert.check(testRunner.confirmCount === 1, "submit() emits confirmRequested")
      Assert.check(
        testRunner.lastColIds.length === 3
          && testRunner.lastColIds.indexOf("col-ro") >= 0
          && testRunner.lastColIds.indexOf("col-w2") >= 0
          && testRunner.lastColIds.indexOf("col-m1") >= 0,
        "emitted collectionIds preserve locked read-only collection plus selected writable collections"
      )

      // 7. Disables submit when zero collections remain selected
      assignModal.active = false
      assignModal.initialCollectionIds = ["col-w1"]
      assignModal.active = true
      assignModal.toggleCollection("col-w1")
      Assert.check(assignModal.selectedCollectionIds.length === 0, "all writable collections unchecked")
      Assert.check(assignModal.canSubmit === false, "canSubmit is false when no collections remain selected")
      assignModal.submit()
      Assert.check(testRunner.confirmCount === 1, "submit() does not emit when zero collections remain selected")
      Assert.check(assignModal.errorMessage.length > 0, "submit() with empty selection sets errorMessage")

      // 8. Busy state blocks close and submit
      assignModal.isBusy = true
      assignModal.requestClose()
      Assert.check(testRunner.closeCount === 0, "requestClose() is blocked while busy")
      assignModal.isBusy = false
      assignModal.requestClose()
      Assert.check(testRunner.closeCount === 1, "requestClose() emits closeRequested when idle")

      // 9. Dual-theme WCAG contrast (Dark + Light presets)
      var presets = ["tokyo-night", "catppuccin-latte"]
      for (var p = 0; p < presets.length; p++) {
        var preset = presets[p]
        Commons.Color.setPreset(preset)
        var card = Commons.Color.popups.background
        Assert.checkContrast(
          preset,
          "CollectionAssignModal error banner",
          Components.StatusPalette.labelOnTint(Components.StatusPalette.error, 0.15, card),
          Assert.compositeOver(Components.StatusPalette.error, 0.15, card)
        )
        Assert.checkContrast(
          preset,
          "CollectionAssignModal confirm button",
          assignModal.textOnConfirm,
          assignModal.confirmRole
        )
      }

      if (Assert.failures === 0) {
        console.log("ALL COLLECTION ASSIGN MODAL TESTS PASSED!")
      }
      Qt.exit(Assert.exitCode())
    }
  }
}
