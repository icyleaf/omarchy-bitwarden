import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components" as Components
import "../components/CipherMutation.js" as CipherMutation
import "lib"

// Headless behavioral & dual-theme contrast tests for Overlay Attachment V2 UX (#473):
//  - CipherMutation attachment helpers (writable personal vs trashed/org, replaceItem,
//    activeAttachmentPreview auto-close check, FileDialog URL-to-path decoding)
//  - ItemInspector Attachments (N) section visibility at N == 0, + Attach button,
//    per-row Delete button, isAttachmentMutating busy lock, Error Alert Banner
//  - DeleteAttachmentModal confirmation, busy guards, Error Alert Banner, reset
//  - Dark & Light Theme Token WCAG AA contrast checks
Item {
  id: testRunner
  width: 900
  height: 700

  function findChildByName(parentItem, name) {
    if (!parentItem || !parentItem.children) return null
    for (var i = 0; i < parentItem.children.length; i++) {
      var child = parentItem.children[i]
      if (child.objectName === name) return child
      var found = findChildByName(child, name)
      if (found) return found
    }
    return null
  }

  function linearChannel(c) {
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
  }

  function relativeLuminance(color) {
    return 0.2126 * linearChannel(color.r)
         + 0.7152 * linearChannel(color.g)
         + 0.0722 * linearChannel(color.b)
  }

  function contrastRatio(fg, bg) {
    var l1 = relativeLuminance(fg)
    var l2 = relativeLuminance(bg)
    var lighter = Math.max(l1, l2)
    var darker = Math.min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)
  }

  function compositeOver(fg, alpha, bg) {
    return Qt.rgba(
      fg.r * alpha + bg.r * (1 - alpha),
      fg.g * alpha + bg.g * (1 - alpha),
      fg.b * alpha + bg.b * (1 - alpha),
      1.0
    )
  }

  property var uploadedItemSignal: null
  property var deletedItemSignal: null
  property var deletedAttSignal: null
  property int modalConfirmCount: 0
  property int modalCloseCount: 0

  Components.ItemInspector {
    id: inspector
    width: 420
    height: 600
    foreground: Commons.Color.foreground
    accent: Commons.Color.accent
    muted: Commons.Color.muted
    borderColor: Commons.Color.menu.border
    onUploadAttachmentRequested: function(item) { testRunner.uploadedItemSignal = item }
    onDeleteAttachmentRequested: function(item, att) {
      testRunner.deletedItemSignal = item
      testRunner.deletedAttSignal = att
    }
  }

  Components.DeleteAttachmentModal {
    id: deleteAttModal
    width: 600
    height: 500
    active: false
    itemName: "GitHub"
    attachmentName: "recovery-codes.txt"
    attachmentSize: "128 B"
    foreground: Commons.Color.foreground
    accent: Commons.Color.accent
    muted: Commons.Color.muted
    cardBackground: Commons.Color.popups.background
    borderColor: Commons.Color.popups.border
    onConfirmRequested: { testRunner.modalConfirmCount++ }
    onCloseRequested: { testRunner.modalCloseCount++ }
  }

  Timer {
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Overlay Attachment V2 UX & Contrast Tests...")

      // 1. CipherMutation attachment helper seam
      var personalLogin = {
        id: "p1",
        name: "GitHub",
        type_name: "login",
        deleted_at: null,
        organization_id: null,
        login: { username: "octocat", password: "secret", uris: [] },
        fields: [],
        attachments: []
      }
      var trashedLogin = {
        id: "t1",
        name: "Old Login",
        type_name: "login",
        deleted_at: "2026-11-20T00:00:00Z",
        organization_id: null,
        login: { username: "old", password: "old", uris: [] },
        fields: [],
        attachments: [{ id: "att-t", fileName: "old.txt", sizeName: "10 B" }]
      }
      var orgLogin = {
        id: "o1",
        name: "Corp Login",
        type_name: "login",
        deleted_at: null,
        organization_id: "org-1",
        edit: true,
        view_password: true,
        login: { username: "svc", password: "pw", uris: [] },
        fields: [],
        attachments: [{ id: "att-o", fileName: "corp.pem", sizeName: "2 KB" }]
      }

      Assert.check(CipherMutation.canMutateAttachments(personalLogin) === true,
        "canMutateAttachments is true for active personal Cipher")
      Assert.check(CipherMutation.canMutateAttachments(trashedLogin) === false,
        "canMutateAttachments is false for trashed Cipher")
      Assert.check(CipherMutation.canMutateAttachments(orgLogin) === false,
        "canMutateAttachments is false for Organization Cipher until #457")
      Assert.check(CipherMutation.attachmentMutationGuardError(trashedLogin).indexOf("Trash") !== -1,
        "attachmentMutationGuardError returns actionable Trash error")
      Assert.check(CipherMutation.attachmentMutationGuardError(orgLogin).indexOf("Organization") !== -1,
        "attachmentMutationGuardError returns actionable Organization error")

      var listBefore = [personalLogin, orgLogin]
      var updatedPersonal = Object.assign({}, personalLogin, {
        attachments: [{ id: "att-1", fileName: "recovery.txt", sizeName: "64 B" }]
      })
      var listAfter = CipherMutation.replaceItem(listBefore, updatedPersonal)
      Assert.check(listAfter.length === 2 && listAfter[0].attachments.length === 1,
        "replaceItem updates matching item in list")
      Assert.check(listBefore[0].attachments.length === 0,
        "replaceItem does not mutate input array")

      var activePreview = { item_id: "p1", attachment_id: "att-1", filename: "recovery.txt" }
      Assert.check(CipherMutation.shouldCloseAttachmentPreview(activePreview, "p1", "att-1") === true,
        "shouldCloseAttachmentPreview returns true when deleted attachment matches active preview")
      Assert.check(CipherMutation.shouldCloseAttachmentPreview(activePreview, "p1", "att-2") === false,
        "shouldCloseAttachmentPreview returns false for sibling attachment")
      Assert.check(CipherMutation.shouldCloseAttachmentPreview(null, "p1", "att-1") === false,
        "shouldCloseAttachmentPreview returns false when no preview is active")

      Assert.check(CipherMutation.localPathFromFileUrl("file:///tmp/my%20cert%20(1).pem") === "/tmp/my cert (1).pem",
        "localPathFromFileUrl decodes file:// URL to local filesystem path")

      // 2. ItemInspector: Attachments (0) always visible for writable personal Cipher
      inspector.item = personalLogin
      var section = findChildByName(inspector, "attachmentsSection")
      var headerTitle = findChildByName(inspector, "attachmentsHeaderTitle")
      var attachBtn = findChildByName(inspector, "attachFileButton")
      var emptyLabel = findChildByName(inspector, "attachmentsEmptyLabel")
      var busyLabel = findChildByName(inspector, "attachmentBusyLabel")
      var errorBanner = findChildByName(inspector, "attachmentErrorBanner")

      Assert.check(section !== null && section.visible === true,
        "Attachments section is visible at N == 0 for writable personal Cipher")
      Assert.check(headerTitle !== null && headerTitle.text === "Attachments (0)",
        "Attachments header shows 'Attachments (0)'")
      Assert.check(attachBtn !== null && attachBtn.visible === true && attachBtn.enabled === true,
        "+ Attach button is visible and enabled on writable personal Cipher")
      Assert.check(emptyLabel !== null && emptyLabel.visible === true,
        "Empty state helper is visible when N == 0")
      Assert.check(busyLabel !== null && busyLabel.visible === false,
        "Busy label is hidden when idle")
      Assert.check(errorBanner !== null && errorBanner.visible === false,
        "Attachment Error Alert Banner is hidden when errorMessage is empty")

      // 3. ItemInspector: with attachments + delete button + busy lock + error banner
      inspector.item = updatedPersonal
      Assert.check(headerTitle.text === "Attachments (1)",
        "Attachments header updates to 'Attachments (1)'")
      Assert.check(emptyLabel.visible === false,
        "Empty state helper hides when N > 0")
      var rowDeleteBtn = findChildByName(inspector, "deleteAttachmentButton_0")
      Assert.check(rowDeleteBtn !== null && rowDeleteBtn.visible === true && rowDeleteBtn.enabled === true,
        "Per-row Delete attachment button is visible and enabled on writable personal Cipher")

      // Emit signals via public button interfaces
      inspector.uploadAttachmentRequested(inspector.item)
      Assert.check(testRunner.uploadedItemSignal && testRunner.uploadedItemSignal.id === "p1",
        "uploadAttachmentRequested delivers target item")
      rowDeleteBtn.clicked()
      Assert.check(testRunner.deletedItemSignal && testRunner.deletedItemSignal.id === "p1"
        && testRunner.deletedAttSignal && testRunner.deletedAttSignal.id === "att-1",
        "Per-row Delete button emits deleteAttachmentRequested with item and attachment")

      // Localized busy lock disables concurrent attachment mutations
      inspector.isAttachmentMutating = true
      Assert.check(attachBtn.enabled === false,
        "+ Attach button is disabled while isAttachmentMutating is true")
      Assert.check(rowDeleteBtn.enabled === false,
        "Per-row Delete button is disabled while isAttachmentMutating is true")
      Assert.check(busyLabel.visible === true,
        "Busy indicator is visible while isAttachmentMutating is true")
      inspector.isAttachmentMutating = false

      // Error Alert Banner visibility
      inspector.attachmentErrorMessage = "Attachment exceeds 500 MiB limit."
      Assert.check(errorBanner.visible === true,
        "Attachment Error Alert Banner becomes visible when attachmentErrorMessage is set")
      inspector.attachmentErrorMessage = ""

      // 4. ItemInspector: read-only Organization Cipher hides mutation controls
      inspector.item = orgLogin
      Assert.check(section.visible === true,
        "Attachments section remains visible on Organization Cipher with existing attachments")
      Assert.check(attachBtn.visible === false,
        "+ Attach button is hidden on Organization Cipher until #457")
      var orgRowDeleteBtn = findChildByName(inspector, "deleteAttachmentButton_0")
      Assert.check(orgRowDeleteBtn !== null && orgRowDeleteBtn.visible === false,
        "Per-row Delete button is hidden on Organization Cipher until #457")

      // 5. DeleteAttachmentModal behavioral seam
      deleteAttModal.active = true
      Assert.check(deleteAttModal.headline.indexOf("recovery-codes.txt") !== -1
        && deleteAttModal.headline.indexOf("GitHub") !== -1,
        "DeleteAttachmentModal headline shows both attachment filename and cipher name")
      deleteAttModal.confirm()
      Assert.check(testRunner.modalConfirmCount === 1,
        "DeleteAttachmentModal.confirm() emits confirmRequested")
      deleteAttModal.requestClose()
      Assert.check(testRunner.modalCloseCount === 1,
        "DeleteAttachmentModal.requestClose() emits closeRequested")

      // Busy guard blocks duplicate confirm and close
      deleteAttModal.isBusy = true
      deleteAttModal.confirm()
      deleteAttModal.requestClose()
      Assert.check(testRunner.modalConfirmCount === 1 && testRunner.modalCloseCount === 1,
        "DeleteAttachmentModal blocks confirm() and requestClose() while isBusy is true")
      deleteAttModal.isBusy = false

      // Error Alert Banner & reset on reopen
      deleteAttModal.errorMessage = "HTTP 500: server error"
      var modalErrBanner = findChildByName(deleteAttModal, "deleteAttachmentErrorBanner")
      Assert.check(modalErrBanner !== null && modalErrBanner.visible === true,
        "DeleteAttachmentModal renders Error Alert Banner when errorMessage is set")
      deleteAttModal.active = false
      deleteAttModal.active = true
      Assert.check(deleteAttModal.errorMessage === "",
        "DeleteAttachmentModal resets errorMessage on reopen")

      // 6. Dual-theme WCAG AA contrast checks (Dark & Light)
      var themes = ["dark", "light"]
      for (var t = 0; t < themes.length; t++) {
        var mode = themes[t]
        Commons.Color.setPreset(mode)
        var cardBg = Commons.Color.popups.background
        var confirmRatio = contrastRatio(deleteAttModal.textOnConfirm, deleteAttModal.confirmRole)
        Assert.check(confirmRatio >= 4.5,
          mode + " theme: DeleteAttachmentModal confirm button contrast >= 4.5 (got " + confirmRatio.toFixed(2) + ")")

        var warnBg = compositeOver(deleteAttModal.warningRole, 0.15, cardBg)
        var warnLabel = Components.StatusPalette.labelOnTint(deleteAttModal.warningRole, 0.15, cardBg)
        var warnRatio = contrastRatio(warnLabel, warnBg)
        Assert.check(warnRatio >= 4.5,
          mode + " theme: DeleteAttachmentModal warning banner contrast >= 4.5 (got " + warnRatio.toFixed(2) + ")")

        var errBg = compositeOver(Components.StatusPalette.error, 0.15, cardBg)
        var errLabel = Components.StatusPalette.labelOnTint(Components.StatusPalette.error, 0.15, cardBg)
        var errRatio = contrastRatio(errLabel, errBg)
        Assert.check(errRatio >= 4.5,
          mode + " theme: Attachment Error Alert Banner contrast >= 4.5 (got " + errRatio.toFixed(2) + ")")
      }
      Commons.Color.setPreset("dark")

      if (Assert.failures === 0) {
        console.log("ALL OVERLAY ATTACHMENT UX TESTS PASSED!")
      }
      Qt.exit(Assert.exitCode())
    }
  }
}
