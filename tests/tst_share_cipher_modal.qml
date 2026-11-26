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
  property string lastOrgId: ""
  property var lastColIds: []
  property int closeCount: 0

  Components.ShareCipherModal {
    id: shareModal
    width: 800
    height: 600
    active: false
    itemName: "GitHub Deploy"
    organizations: [
      { id: "org-writable", name: "Acme Corp" },
      { id: "org-manage", name: "Ops Team" },
      { id: "org-ro-only", name: "ReadOnly Org" }
    ]
    collections: [
      { id: "col-w1", organization_id: "org-writable", name: "Engineering", read_only: false, hide_passwords: false, manage: false },
      { id: "col-ro1", organization_id: "org-writable", name: "Audit", read_only: true, hide_passwords: true, manage: false },
      { id: "col-m1", organization_id: "org-manage", name: "Managed Secrets", read_only: true, hide_passwords: false, manage: true },
      { id: "col-ro-only", organization_id: "org-ro-only", name: "Locked", read_only: true, hide_passwords: true, manage: false }
    ]
    onConfirmRequested: function(orgId, colIds) {
      testRunner.confirmCount++
      testRunner.lastOrgId = orgId
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
      console.log("Running ShareCipherModal & CipherMutation.canShare Tests...")

      // 1. CipherMutation.canShare eligibility across types, ownership, and trash state
      var types = ["login", "note", "card", "identity", "ssh_key"]
      for (var t = 0; t < types.length; t++) {
        Assert.check(
          CipherMutation.canShare({ id: "p-" + t, type_name: types[t] }) === true,
          "canShare is true for personal non-trashed " + types[t]
        )
        Assert.check(
          CipherMutation.canShare({ id: "o-" + t, type_name: types[t], organization_id: "org-1" }) === false,
          "canShare is false for Organization-owned " + types[t]
        )
        Assert.check(
          CipherMutation.canShare({ id: "tr-" + t, type_name: types[t], deleted_at: "2026-01-01T00:00:00Z" }) === false,
          "canShare is false for trashed personal " + types[t]
        )
      }

      // 2. Opening modal selects first Organization with >= 1 writable collection
      shareModal.active = true
      Assert.check(
        shareModal.availableOrganizations.length === 2,
        "only Organizations with >= 1 writable collection (!read_only || manage) appear (got " + shareModal.availableOrganizations.length + ")"
      )
      Assert.check(
        shareModal.selectedOrganizationId === "org-writable",
        "first writable Organization is auto-selected"
      )
      Assert.check(
        shareModal.availableCollections.length === 1 && shareModal.availableCollections[0].id === "col-w1",
        "only writable collections for selected Organization appear"
      )
      Assert.check(
        shareModal.warningMessage.toLowerCase().indexOf("irreversible") !== -1,
        "modal displays prominent irreversible ownership-transfer warning"
      )

      // 3. Submit is blocked until >= 1 writable collection is selected
      Assert.check(shareModal.canSubmit === false, "canSubmit is false with zero collections selected")
      shareModal.submit()
      Assert.check(testRunner.confirmCount === 0, "submit() does not emit without selected collections")
      Assert.check(shareModal.errorMessage.length > 0, "submit() without collection sets errorMessage for Error Alert Banner")

      // 4. Non-writable collection cannot be toggled
      shareModal.toggleCollection("col-ro1")
      Assert.check(shareModal.selectedCollectionIds.length === 0, "read-only collection cannot be toggled")

      // 5. Toggling writable collection enables submit and emits payload
      shareModal.toggleCollection("col-w1")
      Assert.check(shareModal.canSubmit === true, "canSubmit is true once a writable collection is selected")
      shareModal.submit()
      Assert.check(testRunner.confirmCount === 1, "submit() emits confirmRequested")
      Assert.check(testRunner.lastOrgId === "org-writable", "emitted orgId matches selected Organization")
      Assert.check(
        testRunner.lastColIds.length === 1 && testRunner.lastColIds[0] === "col-w1",
        "emitted collectionIds match selected writable collections"
      )

      // 6. Switching Organization clears collection selection and supports manage: true collections
      shareModal.selectOrganization("org-manage")
      Assert.check(shareModal.selectedCollectionIds.length === 0, "switching Organization resets collection selection")
      Assert.check(shareModal.canSubmit === false, "canSubmit resets to false after switching Organization")
      Assert.check(
        shareModal.availableCollections.length === 1 && shareModal.availableCollections[0].id === "col-m1",
        "manage: true collection is treated as writable"
      )
      shareModal.toggleCollection("col-m1")
      Assert.check(shareModal.canSubmit === true, "selecting manage: true collection enables submit")

      // 7. Busy state blocks dismissal and submission
      shareModal.isBusy = true
      shareModal.requestClose()
      Assert.check(testRunner.closeCount === 0, "requestClose() is blocked while busy")
      shareModal.isBusy = false
      shareModal.requestClose()
      Assert.check(testRunner.closeCount === 1, "requestClose() emits closeRequested when idle")

      // 8. Dual-theme WCAG contrast (Dark + Light presets)
      var presets = ["tokyo-night", "catppuccin-latte"]
      for (var p = 0; p < presets.length; p++) {
        var preset = presets[p]
        Commons.Color.setPreset(preset)
        var card = Commons.Color.popups.background
        Assert.checkContrast(
          preset,
          "ShareCipherModal warning banner",
          Components.StatusPalette.labelOnTint(shareModal.warningRole, 0.15, card),
          Assert.compositeOver(shareModal.warningRole, 0.15, card)
        )
        Assert.checkContrast(
          preset,
          "ShareCipherModal error banner",
          Components.StatusPalette.labelOnTint(Components.StatusPalette.error, 0.15, card),
          Assert.compositeOver(Components.StatusPalette.error, 0.15, card)
        )
        Assert.checkContrast(
          preset,
          "ShareCipherModal confirm button",
          shareModal.textOnConfirm,
          shareModal.confirmRole
        )
      }

      if (Assert.failures === 0) {
        console.log("ALL SHARE CIPHER MODAL TESTS PASSED!")
      }
      Qt.exit(Assert.exitCode())
    }
  }
}
