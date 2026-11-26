import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components"
import "../components" as Components
import "../components/CipherMutation.js" as CipherMutation

// Issue #380: favorite toggle and soft/permanent delete for personal Login and
// Secure Note ciphers. These tests exercise the pure mutation helpers, the
// confirmation modal, and the root wiring that glues them to the Overlay.
Item {
  id: testRunner
  width: 900
  height: 700

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  property int confirmCount: 0
  property bool lastPermanent: false
  property int closeCount: 0
  property int ghostClickCount: 0

  Components.GhostIconButton {
    id: testGhostBtn
    iconText: "\uf005"
    onClicked: testRunner.ghostClickCount++
  }

  Components.DeleteCipherModal {
    id: deleteModal
    active: false
    itemName: "GitHub"
    onConfirmRequested: function(permanent) {
      testRunner.confirmCount++
      testRunner.lastPermanent = permanent
    }
    onCloseRequested: testRunner.closeCount++
  }

  function readSource(path) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", path, false)
    xhr.send()
    return xhr.responseText
  }

  function sourceWindow(src, needle, before, after) {
    var idx = String(src || "").indexOf(needle)
    if (idx < 0) return ""
    return src.substring(Math.max(0, idx - (before || 0)), idx + (after || 0))
  }

  Component.onCompleted: {
    console.log("Running Cipher Favorite & Delete Mutation Tests...")

    // ------------------------------------------------------------------
    // 1. CipherMutation guards
    // ------------------------------------------------------------------
    var login = { id: "c1", type_name: "login", name: "GitHub", favorite: false }
    var note = { id: "n1", type_name: "note", name: "Wifi" }
    var card = { id: "d1", type_name: "card", name: "Visa" }
    var identity = { id: "i1", type_name: "identity", name: "Passport" }
    var ssh = { id: "s1", type_name: "ssh_key", name: "Deploy Key" }
    var orgLogin = { id: "c2", type_name: "login", organization_id: "org-1" }
    var orgNote = { id: "n2", type_name: "note", organization_id: "org-1" }
    var orgCard = { id: "d2", type_name: "card", organization_id: "org-1" }
    var orgIdentity = { id: "i2", type_name: "identity", organization_id: "org-1" }
    var orgSsh = { id: "s2", type_name: "ssh_key", organization_id: "org-1" }

    check(CipherMutation.isMutableType(login) === true, "Login ciphers are mutable")
    check(CipherMutation.isMutableType(note) === true, "Secure Notes are mutable")
    check(CipherMutation.isMutableType(card) === true, "Cards are mutable for favorite/delete")
    check(CipherMutation.isMutableType(identity) === true, "Identities are mutable for favorite/delete")
    check(CipherMutation.isMutableType(ssh) === true, "SSH keys are mutable for favorite/delete")
    check(CipherMutation.isMutableType(null) === false, "null is not mutable")

    check(CipherMutation.isEditableType(login) === true, "Login ciphers are editable")
    check(CipherMutation.isEditableType(note) === true, "Secure Notes are editable")
    check(CipherMutation.isEditableType(ssh) === true, "SSH keys are metadata-editable")
    check(CipherMutation.isEditableType(card) === true, "Cards are editable in Inspector Form")
    check(CipherMutation.isEditableType(identity) === true, "Identities are editable in Inspector Form")
    check(CipherMutation.isEditableType(null) === false, "null is not editable")

    check(CipherMutation.isOrganizationOwned(orgLogin) === true, "organization login is detected")
    check(CipherMutation.isOrganizationOwned(login) === false, "personal login is not organization-owned")

    check(CipherMutation.canMutate(login) === true, "personal login can mutate")
    check(CipherMutation.canMutate(note) === true, "personal note can mutate")
    check(CipherMutation.canMutate(card) === true, "personal card can mutate")
    check(CipherMutation.canMutate(identity) === true, "personal identity can mutate")
    check(CipherMutation.canMutate(ssh) === true, "personal SSH key can mutate")
    check(CipherMutation.canMutate(orgLogin) === false, "organization login cannot mutate")
    check(CipherMutation.canMutate(orgNote) === false, "organization note cannot mutate")
    check(CipherMutation.canMutate(orgCard) === false, "organization card cannot mutate")
    check(CipherMutation.canMutate(orgIdentity) === false, "organization identity cannot mutate")
    check(CipherMutation.canMutate(orgSsh) === false, "organization SSH key cannot mutate")

    // Organization Ciphers support per-user Favorite & Folder via /partial regardless of edit flag
    var orgReadOnly = { id: "org-ro", type_name: "login", organization_id: "org-1", edit: false, view_password: false, can_delete: false, can_restore: false }
    var orgHidePass = { id: "org-hp", type_name: "login", organization_id: "org-1", edit: true, view_password: false, can_delete: true, can_restore: true }
    var orgWritable = { id: "org-w", type_name: "login", organization_id: "org-1", edit: true, view_password: true, can_delete: true, can_restore: true }
    check(CipherMutation.canFavorite(login) === true, "personal login can be favorited")
    check(CipherMutation.canFavorite(orgReadOnly) === true, "read-only organization login can be favorited via /partial")
    check(CipherMutation.canFavorite(orgHidePass) === true, "hide-password organization login can be favorited via /partial")
    check(CipherMutation.canAssignFolder(orgReadOnly) === true, "read-only organization login supports personal folder assignment via /partial")
    check(CipherMutation.canEdit(login) === true, "personal login can be edited")
    check(CipherMutation.canEdit(orgWritable) === true, "writable organization login (edit && view_password) can be edited")
    check(CipherMutation.editGuardError(orgWritable) === "", "writable organization login has no edit guard error")
    check(CipherMutation.canEdit(orgReadOnly) === false, "read-only organization login cannot be edited")
    check(CipherMutation.canEdit(orgHidePass) === false, "hide-password organization login cannot be edited (fail-closed)")
    check(CipherMutation.editGuardError(orgReadOnly).indexOf("permission") !== -1, "read-only organization edit guard explains missing permission")
    check(CipherMutation.editGuardError(orgHidePass).indexOf("hidden") !== -1, "hide-password organization edit guard explains hidden passwords")
    check(CipherMutation.canDelete(login) === true, "personal login can be deleted")
    check(CipherMutation.canDelete(orgReadOnly) === false, "non-deletable organization login cannot be deleted")
    check(CipherMutation.deleteGuardError(orgReadOnly).indexOf("permission") !== -1, "non-deletable organization delete guard explains missing permission")

    check(CipherMutation.nextFavorite(login) === true, "favorite toggles false to true")
    check(CipherMutation.nextFavorite({ favorite: true }) === false, "favorite toggles true to false")
    check(CipherMutation.nextFavorite(null) === true, "missing item defaults to favoriting")

    // ------------------------------------------------------------------
    // 2. Optimistic list update and rollback
    // ------------------------------------------------------------------
    var rawRows = [
      { id: "c1", favorite: false, name: "GitHub" },
      { id: "n1", favorite: true, name: "Wifi" }
    ]
    var rawSnapshot = JSON.stringify(rawRows)
    var filteredRows = [{ id: "c1", favorite: false, name: "GitHub" }]

    var optimisticRaw = CipherMutation.withFavorite(rawRows, "c1", true)
    var optimisticFiltered = CipherMutation.withFavorite(filteredRows, "c1", true)
    check(optimisticRaw[0].favorite === true, "raw row flips optimistically")
    check(optimisticFiltered[0].favorite === true, "filtered row flips optimistically")
    check(JSON.stringify(rawRows) === rawSnapshot, "withFavorite does not mutate the source list")
    check(rawRows[0].favorite === false, "source row keeps the pre-mutation value")
    check(optimisticRaw[1].favorite === true, "unrelated rows are preserved")

    var rolledBack = CipherMutation.withFavorite(optimisticRaw, "c1", false)
    check(rolledBack[0].favorite === false, "rollback restores the previous favorite value")
    check(JSON.stringify(rolledBack) === rawSnapshot, "rollback restores the full list")

    var untouched = CipherMutation.withFavorite(rawRows, "missing", true)
    check(JSON.stringify(untouched) === rawSnapshot, "unknown ids leave the list untouched")
    check(CipherMutation.withFavorite(null, "c1", true).length === 0, "null list yields an empty list")

    var coerced = CipherMutation.withFavorite(rawRows, "c1", "yes")
    check(coerced[0].favorite === true, "favorite flag is coerced to Boolean")
    check(typeof coerced[0].favorite === "boolean", "favorite flag is stored as a boolean")

    // ------------------------------------------------------------------
    // 3. DeleteCipherModal soft delete (default)
    // ------------------------------------------------------------------
    check(deleteModal.permanent === false, "delete modal defaults to soft delete")
    check(deleteModal.title === "Delete Item", "delete modal title is Delete Item")
    check(deleteModal.confirmLabel === "Move to Trash", "soft delete confirms Move to Trash")
    check(deleteModal.warningMessage.indexOf("Trash") !== -1,
          "soft delete warning mentions the Trash")
    check(deleteModal.warningMessage.indexOf("cannot be undone") === -1,
          "soft delete warning is not irreversible")
    check(deleteModal.warningRole == StatusPalette.warn, "soft delete uses the warning role")
    check(deleteModal.confirmRole == StatusPalette.warn, "soft delete confirm uses the warning role")
    check(deleteModal.headline.indexOf("GitHub") !== -1, "headline names the cipher")
    check(deleteModal.headline.indexOf("Trash") !== -1, "soft headline mentions the Trash")

    deleteModal.confirm()
    check(testRunner.confirmCount === 1, "soft delete emits confirmRequested")
    check(testRunner.lastPermanent === false, "soft delete requests a non-permanent delete")

    // ------------------------------------------------------------------
    // 4. DeleteCipherModal permanent delete
    // ------------------------------------------------------------------
    deleteModal.togglePermanent()
    check(deleteModal.permanent === true, "toggle switches to permanent delete")
    check(deleteModal.confirmLabel === "Delete Permanently", "permanent confirm label is explicit")
    check(deleteModal.warningMessage.indexOf("cannot be undone") !== -1,
          "permanent warning states the action is irreversible")
    check(deleteModal.warningRole == StatusPalette.danger, "permanent delete uses the danger role")
    check(deleteModal.confirmRole == StatusPalette.danger, "permanent confirm uses the danger role")
    check(deleteModal.headline.indexOf("Permanently delete") !== -1,
          "permanent headline states the destructive intent")

    deleteModal.confirm()
    check(testRunner.confirmCount === 2, "permanent delete emits confirmRequested")
    check(testRunner.lastPermanent === true, "permanent delete requests --permanent")

    deleteModal.togglePermanent()
    check(deleteModal.permanent === false, "toggle can return to soft delete")

    // ------------------------------------------------------------------
    // 5. DeleteCipherModal busy guards and reset
    // ------------------------------------------------------------------
    deleteModal.isBusy = true
    deleteModal.togglePermanent()
    check(deleteModal.permanent === false, "busy modal ignores the permanent toggle")
    deleteModal.confirm()
    check(testRunner.confirmCount === 2, "busy modal ignores confirm")
    deleteModal.requestClose()
    check(testRunner.closeCount === 0, "busy modal ignores close requests")

    deleteModal.isBusy = false
    deleteModal.requestClose()
    check(testRunner.closeCount === 1, "idle modal emits closeRequested")

    deleteModal.active = true
    check(deleteModal.permanent === false, "opening the modal resets the permanent toggle")
    deleteModal.togglePermanent()
    deleteModal.errorMessage = "stale error"
    deleteModal.active = false
    deleteModal.active = true
    check(deleteModal.permanent === false, "reopening resets the permanent toggle")
    check(deleteModal.errorMessage === "", "reopening clears a stale error banner")

    // ------------------------------------------------------------------
    // 5b. GhostIconButton busy guards
    // ------------------------------------------------------------------
    check(testGhostBtn.isBusy === false, "ghost button defaults to idle")
    testGhostBtn.clicked()
    check(testRunner.ghostClickCount === 1, "idle ghost button emits clicked")
    testGhostBtn.isBusy = true
    check(testGhostBtn.isBusy === true, "ghost button can be set busy")
    check(testGhostBtn.opacity === 0.6, "busy ghost button dims opacity to 0.6")
    testGhostBtn.isBusy = false
    check(testGhostBtn.opacity === 1.0, "idle ghost button restores opacity to 1.0")

    // ------------------------------------------------------------------
    // 6. Root wiring (source checks)
    // ------------------------------------------------------------------
    var src = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    check(src.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")

    check(src.indexOf('[root.helperPath, "vault", "edit", itemId, "--stdin", "--json"]') !== -1,
          "favorite runs vault edit <id> --stdin --json")
    check(src.indexOf("cipherFavoriteProc.payload = JSON.stringify({ favorite: nextFavorite })") !== -1,
          "favorite serializes only the favorite flag over stdin")
    check(src.indexOf("cipherFavoriteProc.command = [root.helperPath, \"vault\", \"edit\", itemId, \"--stdin\", \"--json\"]") !== -1,
          "favorite argv carries no secrets")
    var favoriteProcWindow = sourceWindow(src, "id: cipherFavoriteProc", 0, 1600)
    check(favoriteProcWindow.indexOf("stdinEnabled: true") !== -1, "favorite process enables stdin")
    check(favoriteProcWindow.indexOf("write(payload") !== -1, "favorite payload is written over stdin")

    check(src.indexOf('var cmd = [root.helperPath, "vault", "delete", item.id, "--yes", "--json"]') !== -1,
          "delete runs vault delete <id> --yes --json")
    check(src.indexOf('if (permanent) cmd.push("--permanent")') !== -1,
          "permanent delete appends --permanent")
    var deleteProcWindow = sourceWindow(src, "id: cipherDeleteProc", 0, 1500)
    check(deleteProcWindow.indexOf("stdinEnabled") === -1, "delete process needs no stdin")
    check(deleteProcWindow.indexOf("permanent") !== -1, "delete process tracks the permanent flag")

    var modalLine = src.indexOf("readonly property bool hasActiveModal")
    var modalWindow = modalLine >= 0 ? src.substring(modalLine, modalLine + 400) : ""
    check(modalWindow.indexOf("root.showDeleteCipherModal") !== -1,
          "hasActiveModal includes the delete confirmation modal")

    check(src.indexOf('root.showActionPalette = false') !== -1, "opening a modal closes the action palette")
    check(src.indexOf("function openDeleteCipherModal(item)") !== -1,
          "root exposes openDeleteCipherModal")
    check(src.indexOf("function toggleCipherFavorite(item)") !== -1,
          "root exposes toggleCipherFavorite")
    var folderAssignProcWindow = sourceWindow(src, "id: cipherFolderAssignProc", 0, 1600)
    check(folderAssignProcWindow.indexOf("stdinEnabled: true") !== -1,
          "folder assignment process enables stdin (Zero-Argv)")

    check(src.indexOf('label: item.favorite ? "Unfavorite Item" : "Favorite Item"') !== -1,
          "action palette exposes Favorite/Unfavorite Item")
    check(src.indexOf('label: "Delete Item"') !== -1, "action palette exposes Delete Item")
    check(src.indexOf('sequence: "Ctrl+B"') !== -1, "Ctrl+B shortcut is declared")
    check(src.indexOf('sequence: "Ctrl+D"') !== -1, "Ctrl+D shortcut is declared")
    check(src.split('sequence: "Ctrl+B"').length - 1 === 1, "Ctrl+B is declared exactly once")
    check(src.split('sequence: "Ctrl+D"').length - 1 === 1, "Ctrl+D is declared exactly once")
    check(src.indexOf("else if (event.key === Qt.Key_B && root.effectiveView === \"search\"") !== -1,
          "the key handler routes Ctrl+B to the favorite toggle")
    check(src.indexOf("else if (event.key === Qt.Key_D && root.effectiveView === \"search\"") !== -1,
          "the key handler routes Ctrl+D to the delete modal")

    check(src.indexOf("onFavoriteToggled: function(item) { root.toggleCipherFavorite(item) }") !== -1,
          "Inspector favoriteToggled is wired to the root")
    check(src.indexOf("onDeleteRequested: function(item) { root.openDeleteCipherModal(item) }") !== -1,
          "Inspector deleteRequested is wired to the root")

    var deleteSuccessWindow = sourceWindow(src, "function handleCipherDeleteSuccess(data)", 0, 900)
    check(deleteSuccessWindow.indexOf('data.outcome === "deleted_needs_sync"') !== -1,
          "delete success handles deleted_needs_sync")
    check(deleteSuccessWindow.indexOf("root.syncVault(true, true)") !== -1,
          "deleted_needs_sync triggers a background sync")
    check(deleteSuccessWindow.indexOf("root.invalidateVaultList()") !== -1,
          "successful delete invalidates the cached vault list")
    check(deleteSuccessWindow.indexOf("root.loadVaultItems()") !== -1,
          "successful delete reloads the vault list")

    var favoriteSuccessWindow = sourceWindow(src, "function handleCipherFavoriteSuccess(data)", 0, 700)
    check(favoriteSuccessWindow.indexOf('data.outcome === "saved_needs_sync"') !== -1,
          "favorite success handles saved_needs_sync")
    check(favoriteSuccessWindow.indexOf("root.syncVault(true, true)") !== -1,
          "favorite saved_needs_sync triggers a background sync")

    var favoriteFailureWindow = sourceWindow(src, "function handleCipherFavoriteFailure(message)", 0, 400)
    check(favoriteFailureWindow.indexOf("root.applyCipherFavorite(cipherFavoriteProc.itemId, cipherFavoriteProc.previousFavorite)") !== -1,
          "favorite failure rolls the optimistic update back")
    check(favoriteFailureWindow.indexOf("root.errorMessage = message") !== -1,
          "favorite failure surfaces an error")

    check(src.indexOf("root.applyCipherFavorite(itemId, nextFavorite)") !== -1,
          "favorite applies optimistically before the process starts")
    check(src.indexOf("root.updatingResults = true") !== -1,
          "optimistic updates guard the reveal state")
    check(src.indexOf('root.statusMessage = "Favorite update in progress..."') !== -1,
          "root reports in-progress status message when toggle called while mutating")
    check(src.indexOf("isFavoriteMutating: cipherFavoriteProc.running && cipherFavoriteProc.itemId === (root.selectedItem ? root.selectedItem.id : \"\")") !== -1,
          "root passes scoped isFavoriteMutating to ItemInspector")

    var escapeWindow = sourceWindow(src, "if (root.showDeleteCipherModal) {", 0, 300)
    check(escapeWindow.indexOf("!deleteCipherModalComponent.isBusy") !== -1,
          "Escape is blocked while the delete modal is busy")

    // ------------------------------------------------------------------
    // 7. All five personal cipher types support Favorite and Delete
    // ------------------------------------------------------------------
    var paletteGate = src.indexOf('if (CipherMutation.isMutableType(item)) {')
    var favoriteLabel = src.indexOf('label: item.favorite ? "Unfavorite Item" : "Favorite Item"')
    var deleteLabel = src.indexOf('label: "Delete Item"')
    check(paletteGate >= 0, "palette gates favorite/delete behind CipherMutation.isMutableType")
    check(favoriteLabel > paletteGate && deleteLabel > paletteGate,
          "favorite and delete actions exist inside the mutable-type gate")

    var inspectorSrc = readSource(Qt.resolvedUrl("../components/ItemInspector.qml"))
    check(inspectorSrc.indexOf("property bool isFavoriteMutating: false") !== -1,
          "ItemInspector declares isFavoriteMutating")
    check(inspectorSrc.indexOf("isBusy: inspectorRoot.isFavoriteMutating") !== -1,
          "favorite button binds isBusy to isFavoriteMutating")
    check(inspectorSrc.indexOf("enabled: !inspectorRoot.isFavoriteMutating") !== -1,
          "favorite button disables while mutating")
    check(inspectorSrc.indexOf("signal favoriteToggled(var item)") !== -1,
          "ItemInspector declares favoriteToggled")
    check(inspectorSrc.indexOf("signal deleteRequested(var item)") !== -1,
          "ItemInspector declares deleteRequested")
    check(inspectorSrc.indexOf("onClicked: inspectorRoot.favoriteToggled(inspectorRoot.item)") !== -1,
          "Inspector star emits favoriteToggled")
    check(inspectorSrc.indexOf("onClicked: inspectorRoot.deleteRequested(inspectorRoot.item)") !== -1,
          "Inspector trash emits deleteRequested")
    check(inspectorSrc.indexOf('visible: Boolean(inspectorRoot.item && CipherMutation.isMutableType(inspectorRoot.item))') !== -1,
          "Inspector offers favorite/delete for all mutable cipher types")

    var paletteSrc = readSource(Qt.resolvedUrl("../components/ActionPaletteModal.qml"))
    check(paletteSrc.indexOf('pressedKey = "Ctrl+B"') !== -1,
          "action palette maps Ctrl+B to the favorite action")
    check(paletteSrc.indexOf('pressedKey = "Ctrl+D"') !== -1,
          "action palette maps Ctrl+D to the delete action")

    // ------------------------------------------------------------------
    // 8. Theme token compliance
    // ------------------------------------------------------------------
    check(deleteModal.hasOwnProperty("cardBackground"), "delete modal exposes cardBackground token")
    check(deleteModal.hasOwnProperty("foreground"), "delete modal exposes foreground token")
    check(deleteModal.hasOwnProperty("accent"), "delete modal exposes accent token")
    check(deleteModal.hasOwnProperty("borderColor"), "delete modal exposes borderColor token")
    check(deleteModal.hasOwnProperty("muted"), "delete modal exposes muted token")

    var deleteModalSrc = readSource(Qt.resolvedUrl("../components/DeleteCipherModal.qml"))
    check(deleteModalSrc.length > 0, "DeleteCipherModal.qml is readable")
    check(!/#[0-9a-fA-F]{3,8}\b/.test(deleteModalSrc), "delete modal contains no bare hex colors")
    check(!/Qt\.rgba\(\s*[\d.]+\s*,/.test(deleteModalSrc), "delete modal contains no numeric Qt.rgba literals")

    console.log("Cipher Favorite & Delete Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
