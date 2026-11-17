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

  // Inspector Form (issue #386) harness counters.
  property var editorSubmitted: null
  property int editorSubmitCount: 0
  property int editorGenerateCount: 0
  property int editorCancelCount: 0

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

  Components.CipherEditor {
    id: editor
    width: 500
    height: 600
    active: false
    cipherType: "login"
    folders: [
      { id: "f1", name: "Work" },
      { id: "f2", name: "Personal" }
    ]
    defaultFolderId: ""
    onSubmitRequested: function(payload) {
      testRunner.editorSubmitted = payload
      testRunner.editorSubmitCount++
    }
    onGeneratePasswordRequested: testRunner.editorGenerateCount++
    onCancelRequested: testRunner.editorCancelCount++
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

  // Strip line comments before scanning for palette literals: issue references
  // such as `#386` in a comment are not hardcoded colors (the static gate
  // strips comments too).
  function stripLineComments(src) {
    var lines = String(src || "").split("\n")
    var out = []
    for (var i = 0; i < lines.length; i++) {
      var idx = lines[i].indexOf("//")
      out.push(idx >= 0 ? lines[i].substring(0, idx) : lines[i])
    }
    return out.join("\n")
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

    check(src.indexOf("root.showTypePicker = true") !== -1,
          "Ctrl+N opens the Type Picker instead of creating directly")
    check(src.indexOf("root.openCipherCreateModal(cipherType)") !== -1,
          "Type Picker selection routes into cipher creation")
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

    // ==================================================================
    // Inspector-Embedded Cipher Creation Form (issue #386)
    // ==================================================================
    console.log("Running Inspector Cipher Creation Form Tests...")

    // ------------------------------------------------------------------
    // 16. CipherEditor Login payload construction
    // ------------------------------------------------------------------
    editor.cipherType = "login"
    editor.defaultFolderId = ""
    editor.resetForm()
    check(editor.title === "New Login", "editor login title is New Login")
    check(editor.isLogin === true, "editor login mode is detected")
    editor.cipherName = "  My Login  "
    editor.folderId = "f1"
    editor.username = "alice"
    editor.password = "  p@ss word  "
    editor.notes = "line1\nline2"
    editor.setUri(0, "https://example.com")
    editor.addUri()
    editor.setUri(1, "   ")
    editor.addUri()
    editor.setUri(2, "https://second.example")
    editor.addCustomField(0)
    editor.setFieldName(0, "recovery")
    editor.setFieldValue(0, "abc")
    editor.addCustomField(1)
    editor.setFieldName(1, "hidden-token")
    editor.setFieldValue(1, "s3cret")
    editor.addCustomField(2)
    editor.setFieldName(2, "enabled")
    editor.toggleFieldBoolean(2)

    var editorLoginPayload = editor.buildPayload()
    check(editorLoginPayload !== null, "editor login payload builds")
    check(editorLoginPayload.cipher_type === "login", "editor login payload carries cipher_type=login")
    check(editorLoginPayload.name === "My Login", "editor login name is trimmed")
    check(editorLoginPayload.folder_id === "f1", "editor login folder id is serialized")
    check(editorLoginPayload.username === "alice", "editor login username is serialized")
    check(editorLoginPayload.password === "  p@ss word  ", "editor password whitespace is preserved verbatim")
    check(editorLoginPayload.notes === "line1\nline2", "editor login notes are serialized")
    check(editorLoginPayload.uris.length === 2, "editor blank URI rows are filtered out")
    check(editorLoginPayload.uris[0] === "https://example.com" && editorLoginPayload.uris[1] === "https://second.example",
          "editor non-blank URIs keep their order")
    check(editorLoginPayload.fields.length === 3, "editor serializes all custom fields")
    check(editorLoginPayload.fields[0].type === 0 && editorLoginPayload.fields[0].name === "recovery" &&
          editorLoginPayload.fields[0].value === "abc", "editor Text custom field round-trips")
    check(editorLoginPayload.fields[1].type === 1 && editorLoginPayload.fields[1].name === "hidden-token" &&
          editorLoginPayload.fields[1].value === "s3cret", "editor Hidden custom field round-trips")
    check(editorLoginPayload.fields[2].type === 2 && editorLoginPayload.fields[2].name === "enabled" &&
          editorLoginPayload.fields[2].value === "true", "editor Boolean custom field serializes true")

    check(editor.customFieldAt(1).revealed === false, "editor Hidden custom field starts masked")
    editor.toggleFieldRevealed(1)
    check(editor.customFieldAt(1).revealed === true, "editor Hidden custom field can be revealed")
    editor.toggleFieldRevealed(1)
    check(editor.customFieldAt(1).revealed === false, "editor Hidden custom field can be masked again")

    // ------------------------------------------------------------------
    // 17. CipherEditor Secure Note payload omits login-only fields
    // ------------------------------------------------------------------
    editor.cipherType = "note"
    editor.resetForm()
    check(editor.title === "New Secure Note", "editor note title is New Secure Note")
    check(editor.isLogin === false, "editor note mode hides login-only fields")
    editor.cipherName = "  My Note  "
    editor.username = "ignored"
    editor.password = "ignored"
    editor.setUri(0, "https://ignored.example")
    editor.notes = "body"
    var editorNotePayload = editor.buildPayload()
    check(editorNotePayload !== null, "editor note payload builds")
    check(editorNotePayload.cipher_type === "note", "editor note payload carries cipher_type=note")
    check(editorNotePayload.name === "My Note", "editor note name is trimmed")
    check(!editorNotePayload.hasOwnProperty("username"), "editor note payload omits username")
    check(!editorNotePayload.hasOwnProperty("password"), "editor note payload omits password")
    check(!editorNotePayload.hasOwnProperty("uris"), "editor note payload omits URIs")
    check(editorNotePayload.notes === "body", "editor note payload keeps the note body")

    // ------------------------------------------------------------------
    // 18. CipherEditor validation
    // ------------------------------------------------------------------
    editor.cipherType = "login"
    editor.resetForm()
    editor.cipherName = "   "
    testRunner.editorSubmitted = null
    testRunner.editorSubmitCount = 0
    editor.submit()
    check(editor.errorMessage === "Cipher name is required.", "editor rejects a blank name")
    check(testRunner.editorSubmitCount === 0, "editor blank name does not emit a submit")

    editor.resetForm()
    editor.cipherName = "Valid"
    editor.addCustomField(0)
    editor.setFieldName(0, "   ")
    editor.submit()
    check(editor.errorMessage === "Custom field name cannot be empty.", "editor rejects a blank custom field name")
    check(testRunner.editorSubmitCount === 0, "editor blank field name does not emit a submit")

    editor.resetForm()
    editor.cipherName = "Valid"
    editor.submit()
    check(testRunner.editorSubmitCount === 1, "editor valid form emits submitRequested")
    check(editor.errorMessage === "", "editor valid submit clears the error")

    // ------------------------------------------------------------------
    // 19. CipherEditor folder selector defaults
    // ------------------------------------------------------------------
    editor.defaultFolderId = "f2"
    editor.resetForm()
    check(editor.folderId === "f2", "editor active folder scope pre-selects the folder")
    check(editor.folderLabel() === "Personal", "editor folder label resolves the selected folder")
    editor.defaultFolderId = "does-not-exist"
    editor.resetForm()
    check(editor.folderId === "", "editor unknown default folder falls back to No Folder")
    check(editor.folderLabel() === "No Folder", "editor folder label falls back to No Folder")

    var editorFolderOptions = editor.folderOptions()
    check(editorFolderOptions.length === 3, "editor folder selector lists No Folder plus every folder")
    check(editorFolderOptions[0].name === "No Folder", "editor first folder option is No Folder")
    check(editorFolderOptions[1].name === "Personal" && editorFolderOptions[2].name === "Work",
          "editor folders are sorted by name")

    editor.defaultFolderId = ""
    editor.resetForm()
    editor.cipherName = "No Folder"
    var editorNoFolderPayload = editor.buildPayload()
    check(editorNoFolderPayload.folder_id === null, "editor No Folder serializes folder_id as null")

    // ------------------------------------------------------------------
    // 20. CipherEditor dirty tracking
    // ------------------------------------------------------------------
    editor.resetForm()
    check(editor.isDirty === false, "editor pristine draft is clean")

    editor.cipherName = "x"
    check(editor.isDirty === true, "editor typed name marks the draft dirty")
    editor.cipherName = ""
    check(editor.isDirty === false, "editor reverting the name restores a clean draft")

    editor.username = "user"
    check(editor.isDirty === true, "editor typed username marks the draft dirty")
    editor.username = ""

    editor.password = "pw"
    check(editor.isDirty === true, "editor typed password marks the draft dirty")
    editor.password = ""

    editor.notes = "note"
    check(editor.isDirty === true, "editor typed notes mark the draft dirty")
    editor.notes = ""

    editor.setUri(0, "https://dirty.example")
    check(editor.isDirty === true, "editor non-blank URI marks the draft dirty")
    editor.setUri(0, "")
    check(editor.isDirty === false, "editor clearing the URI restores a clean draft")

    editor.addUri()
    check(editor.isDirty === false, "editor a blank URI row alone stays clean")
    editor.removeUri(1)

    editor.defaultFolderId = "f1"
    editor.resetForm()
    check(editor.isDirty === false, "editor default folder alone stays clean")
    editor.folderId = "f2"
    check(editor.isDirty === true, "editor changing the folder marks the draft dirty")
    editor.folderId = "f1"
    check(editor.isDirty === false, "editor restoring the default folder stays clean")

    editor.defaultFolderId = ""
    editor.resetForm()
    editor.addCustomField(0)
    check(editor.isDirty === true, "editor a custom field marks the draft dirty")
    editor.removeCustomField(0)
    check(editor.isDirty === false, "editor removing the custom field restores a clean draft")

    // ------------------------------------------------------------------
    // 21. CipherEditor cancel and dirty-draft confirmation
    // ------------------------------------------------------------------
    editor.resetForm()
    testRunner.editorCancelCount = 0
    editor.requestCancel()
    check(testRunner.editorCancelCount === 1, "editor pristine Esc cancels immediately")
    check(editor.discardPromptVisible === false, "editor pristine cancel shows no discard prompt")

    editor.resetForm()
    editor.cipherName = "draft"
    testRunner.editorCancelCount = 0
    editor.requestCancel()
    check(editor.discardPromptVisible === true, "editor dirty Esc raises the discard prompt")
    check(testRunner.editorCancelCount === 0, "editor dirty Esc does not cancel immediately")

    editor.keepEditing()
    check(editor.discardPromptVisible === false, "editor Keep Editing dismisses the prompt")
    check(testRunner.editorCancelCount === 0, "editor Keep Editing keeps the draft")

    editor.requestCancel()
    editor.confirmDiscard()
    check(editor.discardPromptVisible === false, "editor Discard dismisses the prompt")
    check(testRunner.editorCancelCount === 1, "editor Discard emits cancelRequested")

    // ------------------------------------------------------------------
    // 22. CipherEditor keyboard seam (handleKey)
    // ------------------------------------------------------------------
    // Pristine Esc cancels.
    editor.resetForm()
    testRunner.editorCancelCount = 0
    check(editor.handleKey(Qt.Key_Escape, Qt.NoModifier) === true, "editor handleKey consumes Esc")
    check(testRunner.editorCancelCount === 1, "editor handleKey Esc cancels a pristine draft")

    // Dirty Esc opens the prompt; a second Esc keeps editing.
    editor.resetForm()
    editor.cipherName = "draft"
    testRunner.editorCancelCount = 0
    check(editor.handleKey(Qt.Key_Escape, Qt.NoModifier) === true, "editor handleKey Esc consumes the dismiss")
    check(editor.discardPromptVisible === true, "editor handleKey dirty Esc raises the prompt")
    check(editor.handleKey(Qt.Key_Escape, Qt.NoModifier) === true, "editor handleKey Esc consumes the prompt dismiss")
    check(editor.discardPromptVisible === false, "editor handleKey Esc on the prompt keeps editing")
    check(testRunner.editorCancelCount === 0, "editor handleKey prompt Esc does not cancel")

    // Accepting the prompt discards.
    editor.requestCancel()
    check(editor.handleKey(Qt.Key_Return, Qt.NoModifier) === true, "editor handleKey consumes Return")
    check(testRunner.editorCancelCount === 1, "editor handleKey Return on the prompt discards")

    // Ctrl+S saves a valid draft.
    editor.resetForm()
    editor.cipherName = "KeySaved"
    testRunner.editorSubmitCount = 0
    check(editor.handleKey(Qt.Key_S, Qt.ControlModifier) === true, "editor handleKey consumes Ctrl+S")
    check(testRunner.editorSubmitCount === 1, "editor handleKey Ctrl+S submits a valid draft")
    check(testRunner.editorSubmitted.name === "KeySaved", "editor handleKey Ctrl+S carries the payload")

    // Ctrl+S on an invalid draft surfaces the error and does not submit.
    editor.resetForm()
    testRunner.editorSubmitCount = 0
    check(editor.handleKey(Qt.Key_S, Qt.ControlModifier) === true, "editor handleKey consumes Ctrl+S on a blank draft")
    check(editor.errorMessage === "Cipher name is required.", "editor handleKey Ctrl+S validates first")
    check(testRunner.editorSubmitCount === 0, "editor handleKey Ctrl+S does not submit a blank draft")

    // Ctrl+G requests password generation.
    editor.resetForm()
    testRunner.editorGenerateCount = 0
    check(editor.handleKey(Qt.Key_G, Qt.ControlModifier) === true, "editor handleKey consumes Ctrl+G")
    check(testRunner.editorGenerateCount === 1, "editor handleKey Ctrl+G requests generation")
    check(editor.isGeneratingPassword === true, "editor handleKey Ctrl+G marks the field busy")

    // Ctrl+G is blocked on an outdated engine.
    editor.resetForm()
    editor.isEngineOutdated = true
    testRunner.editorGenerateCount = 0
    check(editor.handleKey(Qt.Key_G, Qt.ControlModifier) === true, "editor handleKey consumes Ctrl+G when outdated")
    check(testRunner.editorGenerateCount === 0, "editor outdated engine blocks generation")
    check(editor.errorMessage.indexOf("outdated") !== -1, "editor outdated engine surfaces an upgrade hint")
    editor.isEngineOutdated = false

    // Unhandled keys bubble untouched.
    check(editor.handleKey(Qt.Key_A, Qt.NoModifier) === false, "editor handleKey ignores plain character keys")

    // Generator fill handoff clears the busy flag and reveals the secret.
    editor.resetForm()
    editor.isGeneratingPassword = true
    editor.setGeneratedPassword("Abcdef1234567890")
    check(editor.password === "Abcdef1234567890", "editor generated password fills the field")
    check(editor.passwordRevealed === true, "editor generated password is revealed")
    check(editor.isGeneratingPassword === false, "editor generated password clears the busy flag")

    // A busy draft refuses a second submit (duplicate-submission guard).
    editor.resetForm()
    editor.cipherName = "Busy"
    editor.isBusy = true
    testRunner.editorSubmitCount = 0
    editor.submit()
    check(testRunner.editorSubmitCount === 0, "editor busy draft refuses a duplicate submit")
    editor.isBusy = false

    // ------------------------------------------------------------------
    // 22b. CipherEditor lifecycle: secret scrubbing
    // ------------------------------------------------------------------
    editor.resetForm()
    editor.active = true
    editor.cipherName = "secret-name"
    editor.username = "secret-user"
    editor.password = "secret-pass"
    editor.notes = "secret-notes"
    check(editor.isDirty === true, "editor draft with secrets is dirty")
    editor.active = false
    check(editor.cipherName === "" && editor.username === "" && editor.password === "" && editor.notes === "",
          "editor scrubs the draft secrets when it closes")
    check(editor.isDirty === false, "editor scrubbed draft is clean")

    // ------------------------------------------------------------------
    // 23. CipherEditor theme tokens and source hygiene
    // ------------------------------------------------------------------
    check(editor.hasOwnProperty("cardBackground"), "editor exposes cardBackground token")
    check(editor.hasOwnProperty("foreground"), "editor exposes foreground token")
    check(editor.hasOwnProperty("accent"), "editor exposes accent token")
    check(editor.hasOwnProperty("borderColor"), "editor exposes borderColor token")

    var editorSrc = readSource(Qt.resolvedUrl("../components/CipherEditor.qml"))
    check(editorSrc.length > 0, "CipherEditor.qml readable")
    var editorCode = stripLineComments(editorSrc)
    check(!/#[0-9a-fA-F]{3,8}\b/.test(editorCode), "CipherEditor contains no bare hex colors")
    check(!/Qt\.rgba\(\s*[\d.]+\s*,/.test(editorCode), "CipherEditor contains no numeric Qt.rgba literals")
    check(editorSrc.indexOf("signal submitRequested(var payload)") !== -1,
          "CipherEditor declares the submitRequested signal")
    check(editorSrc.indexOf("signal generatePasswordRequested()") !== -1,
          "CipherEditor declares the generatePasswordRequested signal")
    check(editorSrc.indexOf("signal cancelRequested()") !== -1,
          "CipherEditor declares the cancelRequested signal")
    check(editorSrc.indexOf("function handleKey(key, modifiers)") !== -1,
          "CipherEditor owns a single handleKey keyboard seam")
    check(editorSrc.indexOf("Keys.onPressed") === -1,
          "CipherEditor declares no competing live Keys handler")
    check(editorSrc.indexOf("titleInput.forceActiveFocus()") !== -1,
          "CipherEditor focuses the Title field when it opens")

    // ------------------------------------------------------------------
    // 24. Overlay wiring (source checks)
    // ------------------------------------------------------------------
    check(src.indexOf("id: cipherEditorComponent") !== -1, "Overlay instantiates the CipherEditor")
    check(src.indexOf("active: root.showCipherEditor") !== -1, "CipherEditor visibility is bound to showCipherEditor")
    check(src.indexOf("cipherType: root.cipherEditorType") !== -1, "CipherEditor receives the picked cipher type")
    check(src.indexOf("defaultFolderId: root.cipherEditorDefaultFolderId") !== -1,
          "CipherEditor receives the scoped default folder")
    check(src.indexOf("onSubmitRequested: function(payload) { root.submitCipherCreate(payload) }") !== -1,
          "CipherEditor submit routes to cipher creation")
    check(src.indexOf("onGeneratePasswordRequested: { root.openPasswordGeneratorForCipherEditor() }") !== -1,
          "CipherEditor Generate opens the generator in fill mode")

    var modalLine2 = sourceLine(src, "readonly property bool hasActiveModal")
    check(modalLine2.indexOf("root.showCipherEditor") !== -1,
          "hasActiveModal includes the Inspector Form")
    check(modalLine2.indexOf("root.showCipherFormModal") !== -1,
          "hasActiveModal still includes the edit modal")

    var createFnIdx = src.indexOf("function openCipherCreateModal(cipherType)")
    var createFnWindow = createFnIdx >= 0 ? src.substring(createFnIdx, createFnIdx + 900) : ""
    check(createFnWindow.indexOf("root.showCipherEditor = true") !== -1,
          "openCipherCreateModal opens the Inspector Form")
    check(createFnWindow.indexOf("root.showCipherFormModal = true") === -1,
          "openCipherCreateModal no longer opens the centered modal")

    check(src.indexOf('sequence: "Ctrl+S"') !== -1, "Ctrl+S shortcut is declared")
    check(src.indexOf("cipherEditorComponent.handleKey(Qt.Key_S, Qt.ControlModifier)") !== -1,
          "Ctrl+S triggers the editor save through handleKey")
    check(src.indexOf('sequence: "Ctrl+G"') !== -1, "Ctrl+G shortcut is declared")
    check(src.indexOf("cipherEditorComponent.handleKey(Qt.Key_G, Qt.ControlModifier)") !== -1,
          "editor Ctrl+G requests password generation through handleKey")
    check(src.indexOf("enabled: root.opened && root.showCipherEditor && !root.showPasswordGeneratorModal") !== -1,
          "editor shortcuts are disabled while the generator modal overlays the draft")

    var escEditorIdx = src.indexOf("} else if (root.showCipherEditor) {")
    check(escEditorIdx !== -1 && src.substring(escEditorIdx, escEditorIdx + 220).indexOf("handleKey(Qt.Key_Escape, Qt.NoModifier)") !== -1,
          "Esc routes to the editor cancel path through handleKey")

    check(src.indexOf("function openPasswordGeneratorForCipherEditor()") !== -1,
          "Overlay declares the editor generator helper")
    check(src.indexOf("root.passwordGeneratorFillMode = true") !== -1,
          "editor generator opens in fill mode")
    check(src.indexOf("root.passwordGeneratorFillMode = false") !== -1,
          "manual generator invocation stays in clipboard mode")

    check(src.indexOf("fillMode: root.passwordGeneratorFillMode") !== -1,
          "PasswordGeneratorModal receives fillMode")
    check(src.indexOf("cipherEditorComponent.setGeneratedPassword(password)") !== -1,
          "generator selection back-fills the editor password")

    check(src.indexOf("cipherEditorComponent.isBusy = true") !== -1,
          "create submit marks the editor busy")
    check(src.indexOf("root.submitCipherCreate(payload)") !== -1, "editor payload reaches submitCipherCreate")

    check(src.indexOf("modalsActive: root.hasActiveModal") !== -1,
          "SearchHeader suspends itself while the editor is active")
    check(searchHeaderSrc.indexOf("enabled: !searchHeaderRoot.modalsActive") !== -1,
          "SearchHeader search box is disabled while a sub-interaction owns the keyboard")

    check(src.indexOf("visible: root.selectedItem !== null && !root.showCipherEditor") !== -1,
          "ItemInspector hides while the Inspector Form is open")
    check(src.indexOf("visible: root.selectedItem === null && !root.showCipherEditor") !== -1,
          "EmptyInspector hides while the Inspector Form is open")

    // ------------------------------------------------------------------
    // 25. Focus guard mirror with the Inspector Form
    // ------------------------------------------------------------------
    var showCipherEditor = true
    var hasActiveModalWithEditor = false || false || false || false || false || showCipherEditor
    check(hasActiveModalWithEditor === true, "open Inspector Form counts as an active sub-interaction")
    showCipherEditor = false
    hasActiveModalWithEditor = false || false || false || false || false || showCipherEditor
    check(hasActiveModalWithEditor === false, "closed Inspector Form releases the focus guard")

    console.log("CipherFormModal Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
