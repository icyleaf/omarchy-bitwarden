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
    var card = { id: "d1", type_name: "card" }
    var identity = { id: "i1", type_name: "identity" }
    var ssh = { id: "s1", type_name: "ssh_key" }
    var orgLogin = { id: "c2", type_name: "login", organization_id: "org-1" }
    var orgNote = { id: "n2", type_name: "note", organization_id: "org-1" }

    check(CipherMutation.isMutableType(login) === true, "Login ciphers are mutable")
    check(CipherMutation.isMutableType(note) === true, "Secure Notes are mutable")
    check(CipherMutation.isMutableType(card) === false, "Cards are not mutable")
    check(CipherMutation.isMutableType(identity) === false, "Identities are not mutable")
    check(CipherMutation.isMutableType(ssh) === false, "SSH keys are not mutable")
    check(CipherMutation.isMutableType(null) === false, "null is not mutable")

    check(CipherMutation.isOrganizationOwned(orgLogin) === true, "organization login is detected")
    check(CipherMutation.isOrganizationOwned(login) === false, "personal login is not organization-owned")

    check(CipherMutation.canMutate(login) === true, "personal login can mutate")
    check(CipherMutation.canMutate(note) === true, "personal note can mutate")
    check(CipherMutation.canMutate(orgLogin) === false, "organization login cannot mutate")
    check(CipherMutation.canMutate(orgNote) === false, "organization note cannot mutate")
    check(CipherMutation.canMutate(card) === false, "card cannot mutate")

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
    check(src.indexOf("function cipherMutationGuard(item)") !== -1,
          "root exposes the shared mutation guard")

    var guardWindow = sourceWindow(src, "function cipherMutationGuard(item)", 0, 400)
    check(guardWindow.indexOf('"Organization ciphers are read-only."') !== -1,
          "organization ciphers surface a read-only error")
    check(guardWindow.indexOf("CipherMutation.isMutableType") !== -1,
          "the guard rejects non-mutable cipher types")

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

    var escapeWindow = sourceWindow(src, "if (root.showDeleteCipherModal) {", 0, 300)
    check(escapeWindow.indexOf("!deleteCipherModalComponent.isBusy") !== -1,
          "Escape is blocked while the delete modal is busy")

    // ------------------------------------------------------------------
    // 7. Mutable types only: Card and Identity stay read-only
    // ------------------------------------------------------------------
    var paletteGate = src.indexOf('if (item.type_name === "login" || item.type_name === "note") {')
    var favoriteLabel = src.indexOf('label: item.favorite ? "Unfavorite Item" : "Favorite Item"')
    var deleteLabel = src.indexOf('label: "Delete Item"')
    check(paletteGate >= 0, "palette gates mutations behind Login/Secure Note")
    check(favoriteLabel > paletteGate && deleteLabel > paletteGate,
          "favorite and delete actions only exist inside the mutable-type gate")
    check(src.indexOf('item.type_name === "card" && item.card') !== -1,
          "Card actions remain copy-only")

    var inspectorSrc = readSource(Qt.resolvedUrl("../components/ItemInspector.qml"))
    check(inspectorSrc.indexOf("signal favoriteToggled(var item)") !== -1,
          "ItemInspector declares favoriteToggled")
    check(inspectorSrc.indexOf("signal deleteRequested(var item)") !== -1,
          "ItemInspector declares deleteRequested")
    check(inspectorSrc.indexOf("onClicked: inspectorRoot.favoriteToggled(inspectorRoot.item)") !== -1,
          "Inspector star emits favoriteToggled")
    check(inspectorSrc.indexOf("onClicked: inspectorRoot.deleteRequested(inspectorRoot.item)") !== -1,
          "Inspector trash emits deleteRequested")
    check(inspectorSrc.indexOf('visible: Boolean(inspectorRoot.item && (inspectorRoot.item.type_name === "login" || inspectorRoot.item.type_name === "note"))') !== -1,
          "Inspector only offers mutations for Login and Secure Note")

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
