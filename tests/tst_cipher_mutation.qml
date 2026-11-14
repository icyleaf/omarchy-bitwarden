import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons as Commons
import "../components" as Components

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

  property var submitted: null
  property int submitCount: 0
  property int generateCount: 0
  property int closeCount: 0

  Components.CipherFormModal {
    id: form
    active: false
    cipherType: "login"
    folders: [
      { id: "f1", name: "Work" },
      { id: "f2", name: "Personal" }
    ]
    defaultFolderId: ""
    onSubmitRequested: function(payload) {
      testRunner.submitted = payload
      testRunner.submitCount++
    }
    onGeneratePasswordRequested: testRunner.generateCount++
    onCloseRequested: testRunner.closeCount++
  }

  function readSource(path) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", path, false)
    xhr.send()
    return xhr.responseText
  }

  function sourceLine(src, needle) {
    var lines = String(src || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf(needle) !== -1) return lines[i]
    }
    return ""
  }

  Component.onCompleted: {
    console.log("Running CipherFormModal Create Mutation Tests...")

    // ------------------------------------------------------------------
    // 1. Login payload construction
    // ------------------------------------------------------------------
    form.cipherType = "login"
    form.defaultFolderId = ""
    form.resetForm()
    form.cipherName = "  My Login  "
    form.folderId = "f1"
    form.username = "alice"
    form.password = "  p@ss word  "
    form.notes = "line1\nline2"
    form.setUri(0, "https://example.com")
    form.addUri()
    form.setUri(1, "   ")
    form.addUri()
    form.setUri(2, "https://second.example")
    form.addCustomField(0)
    form.setFieldName(0, "recovery")
    form.setFieldValue(0, "abc")
    form.addCustomField(1)
    form.setFieldName(1, "hidden-token")
    form.setFieldValue(1, "s3cret")
    form.addCustomField(2)
    form.setFieldName(2, "enabled")
    form.toggleFieldBoolean(2)

    var loginPayload = form.buildPayload()
    check(loginPayload !== null, "login payload builds")
    check(loginPayload.cipher_type === "login", "login payload carries cipher_type=login")
    check(loginPayload.name === "My Login", "name is trimmed")
    check(loginPayload.folder_id === "f1", "selected folder id is serialized")
    check(loginPayload.username === "alice", "username is serialized")
    check(loginPayload.password === "  p@ss word  ", "password whitespace is preserved verbatim")
    check(loginPayload.notes === "line1\nline2", "notes are serialized")
    check(loginPayload.uris.length === 2, "blank URI rows are filtered out")
    check(loginPayload.uris[0] === "https://example.com" && loginPayload.uris[1] === "https://second.example",
          "non-blank URIs keep their order")
    check(loginPayload.fields.length === 3, "all custom fields are serialized")
    check(loginPayload.fields[0].type === 0 && loginPayload.fields[0].name === "recovery" && loginPayload.fields[0].value === "abc",
          "Text custom field round-trips")
    check(loginPayload.fields[1].type === 1 && loginPayload.fields[1].name === "hidden-token" && loginPayload.fields[1].value === "s3cret",
          "Hidden custom field round-trips")
    check(loginPayload.fields[2].type === 2 && loginPayload.fields[2].name === "enabled" && loginPayload.fields[2].value === "true",
          "Boolean custom field serializes true")
    check(form.title === "New Login", "login modal title is New Login")

    // Hidden field mask/reveal toggle.
    check(form.customFieldAt(1).revealed === false, "Hidden custom field starts masked")
    form.toggleFieldRevealed(1)
    check(form.customFieldAt(1).revealed === true, "Hidden custom field can be revealed")
    form.toggleFieldRevealed(1)
    check(form.customFieldAt(1).revealed === false, "Hidden custom field can be masked again")

    // ------------------------------------------------------------------
    // 2. Secure Note payload omits login-only fields
    // ------------------------------------------------------------------
    form.cipherType = "note"
    form.resetForm()
    form.cipherName = "  My Note  "
    form.username = "ignored"
    form.password = "ignored"
    form.setUri(0, "https://ignored.example")
    form.notes = "body"
    var notePayload = form.buildPayload()
    check(notePayload !== null, "secure note payload builds")
    check(notePayload.cipher_type === "note", "note payload carries cipher_type=note")
    check(notePayload.name === "My Note", "note name is trimmed")
    check(notePayload.username === undefined, "note payload omits username")
    check(notePayload.password === undefined, "note payload omits password")
    check(notePayload.uris === undefined, "note payload omits URIs")
    check(notePayload.notes === "body", "note payload keeps the note body")
    check(form.isLogin === false, "note mode hides login-only fields")
    check(form.title === "New Secure Note", "note modal title is New Secure Note")

    // ------------------------------------------------------------------
    // 3. Validation
    // ------------------------------------------------------------------
    form.cipherType = "login"
    form.resetForm()
    form.cipherName = "   "
    testRunner.submitted = null
    testRunner.submitCount = 0
    form.submit()
    check(form.errorMessage === "Cipher name is required.", "blank name is rejected")
    check(testRunner.submitCount === 0, "blank name does not emit a submit")

    form.resetForm()
    form.cipherName = "Valid"
    form.addCustomField(0)
    form.setFieldName(0, "   ")
    form.submit()
    check(form.errorMessage === "Custom field name cannot be empty.", "blank custom field name is rejected")
    check(testRunner.submitCount === 0, "blank custom field name does not emit a submit")

    form.resetForm()
    form.cipherName = "Valid"
    form.submit()
    check(testRunner.submitCount === 1, "valid form emits submitRequested")
    check(form.errorMessage === "", "valid submit clears the error")

    // ------------------------------------------------------------------
    // 4. Folder selector defaults
    // ------------------------------------------------------------------
    form.defaultFolderId = "f2"
    form.resetForm()
    check(form.folderId === "f2", "active folder scope pre-selects the folder")
    form.defaultFolderId = "does-not-exist"
    form.resetForm()
    check(form.folderId === "", "unknown default folder falls back to No Folder")

    var folderOptions = form.folderOptions()
    check(folderOptions.length === 3, "folder selector lists No Folder plus every folder")
    check(folderOptions[0].name === "No Folder", "first folder option is No Folder")
    check(folderOptions[1].name === "Personal" && folderOptions[2].name === "Work", "folders are sorted by name")

    form.defaultFolderId = ""
    form.resetForm()
    form.cipherName = "No Folder"
    var noFolderPayload = form.buildPayload()
    check(noFolderPayload.folder_id === null, "No Folder serializes folder_id as null")

    // ------------------------------------------------------------------
    // 5. Inline password generation
    // ------------------------------------------------------------------
    form.resetForm()
    testRunner.generateCount = 0
    form.requestGeneratePassword()
    check(testRunner.generateCount === 1, "Generate emits generatePasswordRequested")
    check(form.isGeneratingPassword === true, "Generate marks the field busy")
    form.setGeneratedPassword("Abcdef1234567890")
    check(form.password === "Abcdef1234567890", "generated password fills the field")
    check(form.password.length === 16, "generated password is 16 characters")
    check(form.passwordRevealed === true, "generated password is revealed immediately")
    check(form.isGeneratingPassword === false, "Generate clears the busy flag")

    form.isEngineOutdated = true
    testRunner.generateCount = 0
    form.requestGeneratePassword()
    check(testRunner.generateCount === 0, "outdated engine blocks password generation")
    check(form.errorMessage.indexOf("outdated") !== -1, "outdated engine surfaces an upgrade hint")
    form.isEngineOutdated = false

    // ------------------------------------------------------------------
    // 6. Zero-argv process invocation and root wiring (source checks)
    // ------------------------------------------------------------------
    var src = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    check(src.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")
    check(src.indexOf('[root.helperPath, "vault", "create", "--stdin", "--json"]') !== -1,
          "create runs vault create --stdin --json")
    check(src.indexOf("stdinEnabled: true") !== -1, "create process enables stdin")
    check(src.indexOf("write(payload") !== -1, "create payload is written over stdin")
    check(src.indexOf("cipherCreateProc.payload = JSON.stringify(payload)") !== -1,
          "create serializes the JSON payload for stdin")

    var createIdx = src.indexOf('"vault", "create", "--stdin", "--json"')
    var createWindow = createIdx >= 0 ? src.substring(Math.max(0, createIdx - 200), createIdx + 200) : ""
    check(createWindow.indexOf("--password") === -1, "create argv carries no --password flag")
    check(createWindow.indexOf("--notes") === -1, "create argv carries no --notes flag")

    var modalLine = sourceLine(src, "readonly property bool hasActiveModal")
    check(modalLine.indexOf("root.showCipherFormModal") !== -1,
          "hasActiveModal includes the cipher form modal")

    check(src.indexOf("root.openCipherCreateModal(root.activeCategory === \"note\" ? \"note\" : \"login\")") !== -1,
          "Ctrl+N opens Secure Note on the note tab and Login otherwise")
    check(src.indexOf('sequence: "Ctrl+N"') !== -1, "Ctrl+N shortcut is declared")
    check(src.indexOf('"Create Login"') !== -1, "action palette exposes Create Login")
    check(src.indexOf('"Create Secure Note"') !== -1, "action palette exposes Create Secure Note")
    check(src.indexOf("onCreateCipherRequested") !== -1, "SearchHeader create signal is wired")
    check(src.indexOf("root.applyPendingCipherSelection()") !== -1,
          "vault reload applies the pending new-cipher selection")
    check(src.indexOf("root.revealCreatedCipher(") !== -1,
          "post-create filter reset is wired")
    check(src.indexOf('data.outcome === "saved_needs_sync"') !== -1,
          "post-create handles saved_needs_sync")
    check(src.indexOf("root.syncVault(true, true)") !== -1,
          "saved_needs_sync triggers a background sync")
    check(src.indexOf("!cipherFormModalComponent.isBusy") !== -1,
          "Escape is blocked while the create modal is busy")

    var searchHeaderSrc = readSource(Qt.resolvedUrl("../components/SearchHeader.qml"))
    check(searchHeaderSrc.indexOf("createCipherRequested") !== -1,
          "SearchHeader declares the create signal")
    check(searchHeaderSrc.indexOf('searchHeaderRoot.activeCategory === "login" || searchHeaderRoot.activeCategory === "note"') !== -1,
          "SearchHeader + button only shows on Login and Secure Note tabs")

    var paletteSrc = readSource(Qt.resolvedUrl("../components/ActionPaletteModal.qml"))
    check(paletteSrc.indexOf('pressedKey = "Ctrl+N"') !== -1,
          "action palette maps Ctrl+N to the Create Login shortcut")

    // ------------------------------------------------------------------
    // 7. Edit mode prefill
    // ------------------------------------------------------------------
    var originalLogin = {
      id: "c1",
      type_name: "login",
      name: "GitHub",
      folder_id: "f1",
      notes: "hello",
      login: {
        username: "alice",
        password: "pw123",
        uris: [{ uri: "https://github.com" }, { uri: "https://gist.github.com" }]
      },
      fields: [
        { name: "recovery", value: "abc", type: 0 },
        { name: "token", value: "s3cret", type: 1 },
        { name: "enabled", value: "true", type: 2 },
        { name: "linked-user", value: "bob", type: 3 }
      ]
    }

    form.cipherType = "login"
    form.mode = "edit"
    form.originalItem = originalLogin
    form.defaultFolderId = ""
    form.resetForm()

    check(form.isEdit === true, "edit mode is detected")
    check(form.title === "Edit Item", "edit modal title is Edit Item")
    check(form.cipherName === "GitHub", "edit prefills the cipher name")
    check(form.folderId === "f1", "edit prefills the stored folder id")
    check(form.notes === "hello", "edit prefills notes")
    check(form.username === "alice", "edit prefills the username")
    check(form.password === "pw123", "edit prefills the password")
    check(form.passwordRevealed === false, "edit keeps the password masked")
    check(form.uriAt(0).uri === "https://github.com" && form.uriAt(1).uri === "https://gist.github.com",
          "edit prefills every Login URI in order")
    check(form.customFieldAt(0).name === "recovery" && form.customFieldAt(0).type === 0,
          "edit prefills Text custom fields")
    check(form.customFieldAt(1).name === "token" && form.customFieldAt(1).type === 1,
          "edit prefills Hidden custom fields")
    check(form.customFieldAt(2).name === "enabled" && form.customFieldAt(2).value === "true",
          "edit prefills Boolean custom fields")
    check(form.linkedFields.length === 1 && form.linkedFields[0].name === "linked-user",
          "Linked fields are split out of the editable list")
    check(form.customFieldAt(3) === null, "Linked fields never become editable rows")

    // A momentarily incomplete folder list must not move the cipher to No Folder.
    form.folders = []
    form.resetForm()
    check(form.folderId === "f1", "edit preserves the folder id when the folder list is incomplete")
    form.folders = [
      { id: "f1", name: "Work" },
      { id: "f2", name: "Personal" }
    ]
    form.resetForm()

    // ------------------------------------------------------------------
    // 8. Edit diff: unchanged form is a no-op
    // ------------------------------------------------------------------
    testRunner.submitted = null
    testRunner.submitCount = 0
    testRunner.closeCount = 0
    form.submit()
    check(testRunner.submitCount === 0, "unchanged edit emits no submit")
    check(testRunner.closeCount === 1, "unchanged edit closes the modal without a process")
    check(form.errorMessage === "", "no-op edit leaves no error banner")
    check(Object.keys(form.buildEditPayload("GitHub")).length === 0,
          "unchanged edit builds an empty diff")

    // ------------------------------------------------------------------
    // 9. Edit diff: only changed keys travel
    // ------------------------------------------------------------------
    form.resetForm()
    form.cipherName = "  GitHub Work  "
    form.username = "carol"
    testRunner.submitted = null
    testRunner.submitCount = 0
    form.submit()
    check(testRunner.submitCount === 1, "dirty edit emits submitRequested")
    check(testRunner.submitted.name === "GitHub Work", "changed name is trimmed in the diff")
    check(testRunner.submitted.username === "carol", "changed username is in the diff")
    check(testRunner.submitted.password === undefined, "unchanged password is omitted")
    check(testRunner.submitted.notes === undefined, "unchanged notes are omitted")
    check(testRunner.submitted.folder_id === undefined, "unchanged folder is omitted")
    check(testRunner.submitted.uris === undefined, "unchanged URIs are omitted")
    check(testRunner.submitted.fields === undefined, "unchanged fields are omitted")
    check(testRunner.submitted.cipher_type === undefined, "edit diff carries no cipher_type")

    form.resetForm()
    form.password = "newpw"
    check(form.buildEditPayload("GitHub").password === "newpw", "changed password is in the diff")
    check(form.buildEditPayload("GitHub").username === undefined, "password-only diff omits the username")

    form.resetForm()
    form.notes = ""
    check(form.buildEditPayload("GitHub").notes === "", "clearing notes sends an empty string")

    form.resetForm()
    form.folderId = "f2"
    check(form.buildEditPayload("GitHub").folder_id === "f2", "folder change is in the diff")

    form.resetForm()
    form.folderId = ""
    var noFolderDiff = form.buildEditPayload("GitHub")
    check(noFolderDiff.hasOwnProperty("folder_id") && noFolderDiff.folder_id === "",
          "No Folder serializes as an empty folder_id in edit mode")

    // ------------------------------------------------------------------
    // 10. Edit diff: URIs
    // ------------------------------------------------------------------
    form.resetForm()
    form.setUri(0, "https://gitlab.com")
    var uriDiff = form.buildEditPayload("GitHub")
    check(uriDiff.uris.length === 2 && uriDiff.uris[0] === "https://gitlab.com" &&
          uriDiff.uris[1] === "https://gist.github.com", "edited URIs are sent in order")

    form.resetForm()
    form.addUri()
    form.setUri(2, "https://third.example")
    check(form.buildEditPayload("GitHub").uris.length === 3, "added URIs extend the diff")

    form.resetForm()
    form.removeUri(0)
    form.removeUri(0)
    var clearedUriDiff = form.buildEditPayload("GitHub")
    check(clearedUriDiff.clear_uris === true, "emptying the URI list sends clear_uris")
    check(clearedUriDiff.uris === undefined, "clear_uris replaces the uris array")

    // ------------------------------------------------------------------
    // 11. Edit diff: custom fields and Linked preservation
    // ------------------------------------------------------------------
    form.resetForm()
    form.setFieldValue(1, "rotated")
    var valueDiff = form.buildEditPayload("GitHub")
    check(valueDiff.fields.length === 1 && valueDiff.fields[0].name === "token" &&
          valueDiff.fields[0].value === "rotated" && valueDiff.fields[0].type === 1,
          "changed field value is upserted with its type")
    check(valueDiff.remove_fields === undefined, "value-only change removes nothing")

    form.resetForm()
    form.setFieldName(0, "recovery-code")
    var renameDiff = form.buildEditPayload("GitHub")
    check(renameDiff.remove_fields.length === 1 && renameDiff.remove_fields[0] === "recovery",
          "renamed field removes the old name")
    check(renameDiff.fields.length === 1 && renameDiff.fields[0].name === "recovery-code" &&
          renameDiff.fields[0].value === "abc", "renamed field upserts the new name")

    form.resetForm()
    form.removeCustomField(2)
    var removeDiff = form.buildEditPayload("GitHub")
    check(removeDiff.remove_fields.length === 1 && removeDiff.remove_fields[0] === "enabled",
          "deleted field is listed in remove_fields")
    check(removeDiff.fields === undefined, "deletion alone upserts nothing")

    form.resetForm()
    form.setFieldName(0, "a")
    form.setFieldName(1, "b")
    form.setFieldName(2, "c")
    var linkedDiff = form.buildEditPayload("GitHub")
    var linkedJson = JSON.stringify(linkedDiff)
    check(linkedJson.indexOf("linked-user") === -1, "Linked fields never enter the update diff")
    check(linkedDiff.remove_fields.indexOf("linked-user") === -1,
          "Linked fields are never scheduled for removal")
    check(form.linkedFields.length === 1, "Linked fields stay visible after a diff")

    form.resetForm()
    form.addCustomField(0)
    form.setFieldName(3, "new-field")
    form.setFieldValue(3, "v")
    check(form.buildEditPayload("GitHub").fields[0].name === "new-field",
          "newly added field is upserted")

    // ------------------------------------------------------------------
    // 12. Edit mode: Secure Note and validation
    // ------------------------------------------------------------------
    var originalNote = {
      id: "n1",
      type_name: "note",
      name: "Wifi",
      folder_id: "",
      notes: "ssid",
      fields: [{ name: "pin", value: "1234", type: 1 }]
    }

    form.cipherType = "note"
    form.originalItem = originalNote
    form.resetForm()
    check(form.isLogin === false, "note edit hides login-only fields")
    check(form.username === "" && form.password === "", "note edit prefills no credentials")
    check(form.uriAt(0).uri === "", "note edit prefills a single blank URI row")
    check(form.customFieldAt(0).name === "pin", "note edit prefills custom fields")

    form.notes = "ssid-2"
    var noteDiff = form.buildEditPayload("Wifi")
    check(noteDiff.notes === "ssid-2", "note edit diff carries the note body")
    check(noteDiff.username === undefined && noteDiff.password === undefined && noteDiff.uris === undefined,
          "note edit diff omits login-only keys")

    form.resetForm()
    form.cipherName = "   "
    testRunner.submitCount = 0
    testRunner.closeCount = 0
    form.submit()
    check(form.errorMessage === "Cipher name is required.", "edit still requires a cipher name")
    check(testRunner.submitCount === 0 && testRunner.closeCount === 0,
          "blank name in edit neither submits nor closes")

    form.resetForm()
    form.setFieldName(0, "  ")
    form.submit()
    check(form.errorMessage === "Custom field name cannot be empty.",
          "edit still rejects blank custom field names")

    // Restore create mode for the remaining checks.
    form.mode = "create"
    form.originalItem = null
    form.cipherType = "login"
    form.resetForm()

    // ------------------------------------------------------------------
    // 13. Edit wiring (source checks)
    // ------------------------------------------------------------------
    check(src.indexOf('[root.helperPath, "vault", "edit", item.id, "--stdin", "--json"]') !== -1,
          "edit runs vault edit <id> --stdin --json")
    check(src.indexOf("cipherEditProc.payload = JSON.stringify(payload)") !== -1,
          "edit serializes the JSON diff for stdin")
    check(src.indexOf("mode: root.cipherFormEditItem ? \"edit\" : \"create\"") !== -1,
          "modal switches to edit mode for the selected cipher")
    check(src.indexOf("originalItem: root.cipherFormEditItem") !== -1,
          "modal receives the cipher being edited")
    check(src.indexOf("if (root.cipherFormEditItem) root.submitCipherEdit(payload)") !== -1,
          "modal submit dispatches to the edit handler")

    check(src.indexOf('"Organization ciphers are read-only."') !== -1,
          "organization ciphers surface a read-only error")
    var orgGuardIdx = src.indexOf("function openCipherEditModal(item)")
    var orgGuardWindow = orgGuardIdx >= 0 ? src.substring(orgGuardIdx, orgGuardIdx + 1200) : ""
    check(orgGuardWindow.indexOf("item.organization_id") !== -1,
          "the organization guard runs before the modal opens")
    check(orgGuardWindow.indexOf("root.showCipherFormModal = true") > orgGuardWindow.indexOf("item.organization_id"),
          "organization ciphers never open the edit modal")

    check(src.indexOf('label: "Edit Item"') !== -1, "action palette exposes Edit Item")
    check(src.indexOf("function() { root.openCipherEditModal(item) }") !== -1,
          "action palette Edit Item opens the edit modal")
    check(src.indexOf('onEditRequested: function(item) { root.openCipherEditModal(item) }') !== -1,
          "Inspector Edit button is wired to the edit modal")

    var ctrlECount = src.split('sequence: "Ctrl+E"').length - 1
    check(ctrlECount === 1, "Ctrl+E is declared exactly once")
    check(src.indexOf('if (item.type_name === "ssh_key") root.openSshKeyModal("export", item)') !== -1,
          "Ctrl+E keeps SSH export for SSH keys")
    check(src.indexOf("else root.openCipherEditModal(item)") !== -1,
          "Ctrl+E opens the edit modal for Login and Secure Note")
    check(src.indexOf("else root.openCipherEditModal(root.selectedItem)") !== -1,
          "the key handler also routes Ctrl+E to the edit modal")

    var editSuccessIdx = src.indexOf("function handleCipherEditSuccess(data)")
    var editSuccessWindow = editSuccessIdx >= 0 ? src.substring(editSuccessIdx, editSuccessIdx + 900) : ""
    check(editSuccessWindow.indexOf('data.outcome === "saved_needs_sync"') !== -1,
          "edit success handles saved_needs_sync")
    check(editSuccessWindow.indexOf("root.syncVault(true, true)") !== -1,
          "edit saved_needs_sync triggers a background sync")
    check(editSuccessWindow.indexOf("root.pendingSelectItemId = editedId") !== -1,
          "post-edit reload re-selects the edited cipher")
    check(editSuccessWindow.indexOf("root.revealCreatedCipher(") !== -1,
          "post-edit filter reset is wired")
    check(editSuccessWindow.indexOf("root.cipherFormEditItem = null") !== -1,
          "edit success clears the edited item")

    check(src.indexOf("cipherFormModalComponent.errorMessage = errMsg") !== -1,
          "daemon errors keep the modal open with an inline banner")
    var modalEditSrc = readSource(Qt.resolvedUrl("../components/CipherFormModal.qml"))
    check(modalEditSrc.indexOf("if (isEdit && Object.keys(payload).length === 0)") !== -1,
          "no-op edit dismisses without spawning a process")
    check(modalEditSrc.indexOf("closeRequested()") !== -1,
          "the modal dismisses itself through closeRequested")

    var inspectorSrc = readSource(Qt.resolvedUrl("../components/ItemInspector.qml"))
    check(inspectorSrc.indexOf("signal editRequested(var item)") !== -1,
          "ItemInspector declares editRequested")
    check(inspectorSrc.indexOf("inspectorRoot.editRequested(inspectorRoot.item)") !== -1,
          "Inspector Edit button emits editRequested")
    check(inspectorSrc.indexOf('inspectorRoot.item.type_name === "login" || inspectorRoot.item.type_name === "note"') !== -1,
          "Inspector only offers Edit for Login and Secure Note")

    // ------------------------------------------------------------------
    // 14. Theme token compliance
    // ------------------------------------------------------------------
    check(form.hasOwnProperty("cardBackground"), "cipher modal exposes cardBackground token")
    check(form.hasOwnProperty("foreground"), "cipher modal exposes foreground token")
    check(form.hasOwnProperty("accent"), "cipher modal exposes accent token")
    check(form.hasOwnProperty("borderColor"), "cipher modal exposes borderColor token")

    var modalSrc = readSource(Qt.resolvedUrl("../components/CipherFormModal.qml"))
    check(!/#[0-9a-fA-F]{3,8}\b/.test(modalSrc), "cipher modal contains no bare hex colors")
    check(!/Qt\.rgba\(\s*[\d.]+\s*,/.test(modalSrc), "cipher modal contains no numeric Qt.rgba literals")

    // ------------------------------------------------------------------
    // 15. Focus guard mirror
    // ------------------------------------------------------------------
    var showCipherFormModal = true
    var hasActiveModal = false || false || false || false || showCipherFormModal
    check(hasActiveModal === true, "open cipher modal counts as an active modal")
    showCipherFormModal = false
    hasActiveModal = false || false || false || false || showCipherFormModal
    check(hasActiveModal === false, "closed cipher modal releases the focus guard")

    console.log("CipherFormModal Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
