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

  // Inspector Form (issues #386, #387) harness counters.
  property var editorSubmitted: null
  property int editorSubmitCount: 0
  property int editorGenerateCount: 0
  property int editorCancelCount: 0

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
    console.log("Running Inspector Cipher Editor Tests (Create & Edit)...")

    // ==================================================================
    // CipherEditor Create Mode Tests
    // ==================================================================

    // ------------------------------------------------------------------
    // 1. Login payload construction
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
    // 2. Secure Note payload omits login-only fields
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
    // 3. CipherEditor validation
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
    // 4. CipherEditor folder selector defaults
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
    // 5. CipherEditor dirty tracking (create mode)
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
    // 6. CipherEditor cancel and dirty-draft confirmation
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
    // 7. CipherEditor keyboard seam (handleKey)
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
    // 7b. CipherEditor lifecycle: secret scrubbing
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

    // ==================================================================
    // CipherEditor Edit Mode Tests
    // ==================================================================

    console.log("Running CipherEditor Edit Mode Tests...")

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

    // ------------------------------------------------------------------
    // 8. Edit mode prefill
    // ------------------------------------------------------------------
    editor.cipherType = "login"
    editor.mode = "edit"
    editor.originalItem = originalLogin
    editor.defaultFolderId = ""
    editor.resetForm()

    check(editor.isEdit === true, "edit mode is detected")
    check(editor.title === "Edit Item", "edit editor title is Edit Item")
    check(editor.cipherName === "GitHub", "edit prefills the cipher name")
    check(editor.folderId === "f1", "edit prefills the stored folder id")
    check(editor.notes === "hello", "edit prefills notes")
    check(editor.username === "alice", "edit prefills the username")
    check(editor.password === "pw123", "edit prefills the password")
    check(editor.passwordRevealed === false, "edit keeps the password masked")
    check(editor.uriAt(0).uri === "https://github.com" && editor.uriAt(1).uri === "https://gist.github.com",
          "edit prefills every Login URI in order")
    check(editor.customFieldAt(0).name === "recovery" && editor.customFieldAt(0).type === 0,
          "edit prefills Text custom fields")
    check(editor.customFieldAt(1).name === "token" && editor.customFieldAt(1).type === 1,
          "edit prefills Hidden custom fields")
    check(editor.customFieldAt(2).name === "enabled" && editor.customFieldAt(2).value === "true",
          "edit prefills Boolean custom fields")
    check(editor.linkedFields.length === 1 && editor.linkedFields[0].name === "linked-user",
          "Linked fields are split out of the editable list")
    check(editor.customFieldAt(3) === null, "Linked fields never become editable rows")

    // A momentarily incomplete folder list must not move the cipher to No Folder.
    editor.folders = []
    editor.resetForm()
    check(editor.folderId === "f1", "edit preserves the folder id when the folder list is incomplete")
    editor.folders = [
      { id: "f1", name: "Work" },
      { id: "f2", name: "Personal" }
    ]
    editor.resetForm()

    // ------------------------------------------------------------------
    // 9. Edit diff: unchanged form is a no-op
    // ------------------------------------------------------------------
    testRunner.editorSubmitted = null
    testRunner.editorSubmitCount = 0
    testRunner.editorCancelCount = 0
    editor.submit()
    check(testRunner.editorSubmitCount === 0, "unchanged edit emits no submit")
    check(testRunner.editorCancelCount === 1, "unchanged edit closes the editor without a process")
    check(editor.errorMessage === "", "no-op edit leaves no error banner")
    check(Object.keys(editor.buildEditPayload("GitHub")).length === 0,
          "unchanged edit builds an empty diff")

    // ------------------------------------------------------------------
    // 10. Edit diff: only changed keys travel
    // ------------------------------------------------------------------
    editor.resetForm()
    editor.cipherName = "  GitHub Work  "
    editor.username = "carol"
    testRunner.editorSubmitted = null
    testRunner.editorSubmitCount = 0
    editor.submit()
    check(testRunner.editorSubmitCount === 1, "dirty edit emits submitRequested")
    check(testRunner.editorSubmitted.name === "GitHub Work", "changed name is trimmed in the diff")
    check(testRunner.editorSubmitted.username === "carol", "changed username is in the diff")
    check(testRunner.editorSubmitted.password === undefined, "unchanged password is omitted")
    check(testRunner.editorSubmitted.notes === undefined, "unchanged notes are omitted")
    check(testRunner.editorSubmitted.folder_id === undefined, "unchanged folder is omitted")
    check(testRunner.editorSubmitted.uris === undefined, "unchanged URIs are omitted")
    check(testRunner.editorSubmitted.fields === undefined, "unchanged fields are omitted")
    check(testRunner.editorSubmitted.cipher_type === undefined, "edit diff carries no cipher_type")

    editor.resetForm()
    editor.password = "newpw"
    check(editor.buildEditPayload("GitHub").password === "newpw", "changed password is in the diff")
    check(editor.buildEditPayload("GitHub").username === undefined, "password-only diff omits the username")

    editor.resetForm()
    editor.notes = ""
    check(editor.buildEditPayload("GitHub").notes === "", "clearing notes sends an empty string")

    editor.resetForm()
    editor.folderId = "f2"
    check(editor.buildEditPayload("GitHub").folder_id === "f2", "folder change is in the diff")

    editor.resetForm()
    editor.folderId = ""
    var noFolderDiff = editor.buildEditPayload("GitHub")
    check(noFolderDiff.hasOwnProperty("folder_id") && noFolderDiff.folder_id === "",
          "No Folder serializes as an empty folder_id in edit mode")

    // ------------------------------------------------------------------
    // 11. Edit diff: URIs
    // ------------------------------------------------------------------
    editor.resetForm()
    editor.setUri(0, "https://gitlab.com")
    var uriDiff = editor.buildEditPayload("GitHub")
    check(uriDiff.uris.length === 2 && uriDiff.uris[0] === "https://gitlab.com" &&
          uriDiff.uris[1] === "https://gist.github.com", "edited URIs are sent in order")

    editor.resetForm()
    editor.addUri()
    editor.setUri(2, "https://third.example")
    check(editor.buildEditPayload("GitHub").uris.length === 3, "added URIs extend the diff")

    editor.resetForm()
    editor.removeUri(0)
    editor.removeUri(0)
    var clearedUriDiff = editor.buildEditPayload("GitHub")
    check(clearedUriDiff.clear_uris === true, "emptying the URI list sends clear_uris")
    check(clearedUriDiff.uris === undefined, "clear_uris replaces the uris array")

    // ------------------------------------------------------------------
    // 12. Edit diff: custom fields and Linked preservation
    // ------------------------------------------------------------------
    editor.resetForm()
    editor.setFieldValue(1, "rotated")
    var valueDiff = editor.buildEditPayload("GitHub")
    check(valueDiff.fields.length === 1 && valueDiff.fields[0].name === "token" &&
          valueDiff.fields[0].value === "rotated" && valueDiff.fields[0].type === 1,
          "changed field value is upserted with its type")
    check(valueDiff.remove_fields === undefined, "value-only change removes nothing")

    editor.resetForm()
    editor.setFieldName(0, "recovery-code")
    var renameDiff = editor.buildEditPayload("GitHub")
    check(renameDiff.remove_fields.length === 1 && renameDiff.remove_fields[0] === "recovery",
          "renamed field removes the old name")
    check(renameDiff.fields.length === 1 && renameDiff.fields[0].name === "recovery-code" &&
          renameDiff.fields[0].value === "abc", "renamed field upserts the new name")

    editor.resetForm()
    editor.removeCustomField(2)
    var removeDiff = editor.buildEditPayload("GitHub")
    check(removeDiff.remove_fields.length === 1 && removeDiff.remove_fields[0] === "enabled",
          "deleted field is listed in remove_fields")
    check(removeDiff.fields === undefined, "deletion alone upserts nothing")

    editor.resetForm()
    editor.setFieldName(0, "a")
    editor.setFieldName(1, "b")
    editor.setFieldName(2, "c")
    var linkedDiff = editor.buildEditPayload("GitHub")
    var linkedJson = JSON.stringify(linkedDiff)
    check(linkedJson.indexOf("linked-user") === -1, "Linked fields never enter the update diff")
    check(linkedDiff.remove_fields.indexOf("linked-user") === -1,
          "Linked fields are never scheduled for removal")
    check(editor.linkedFields.length === 1, "Linked fields stay visible after a diff")

    editor.resetForm()
    editor.addCustomField(0)
    editor.setFieldName(3, "new-field")
    editor.setFieldValue(3, "v")
    check(editor.buildEditPayload("GitHub").fields[0].name === "new-field",
          "newly added field is upserted")

    // ------------------------------------------------------------------
    // 13. Edit mode: Secure Note and validation
    // ------------------------------------------------------------------
    var originalNote = {
      id: "n1",
      type_name: "note",
      name: "Wifi",
      folder_id: "",
      notes: "ssid",
      fields: [{ name: "pin", value: "1234", type: 1 }]
    }

    editor.cipherType = "note"
    editor.originalItem = originalNote
    editor.resetForm()
    check(editor.isLogin === false, "note edit hides login-only fields")
    check(editor.username === "" && editor.password === "", "note edit prefills no credentials")
    check(editor.uriAt(0).uri === "", "note edit prefills a single blank URI row")
    check(editor.customFieldAt(0).name === "pin", "note edit prefills custom fields")

    editor.notes = "ssid-2"
    var noteDiff = editor.buildEditPayload("Wifi")
    check(noteDiff.notes === "ssid-2", "note edit diff carries the note body")
    check(noteDiff.username === undefined && noteDiff.password === undefined && noteDiff.uris === undefined,
          "note edit diff omits login-only keys")

    editor.resetForm()
    editor.cipherName = "   "
    testRunner.editorSubmitCount = 0
    testRunner.editorCancelCount = 0
    editor.submit()
    check(editor.errorMessage === "Cipher name is required.", "edit still requires a cipher name")
    check(testRunner.editorSubmitCount === 0 && testRunner.editorCancelCount === 0,
          "blank name in edit neither submits nor cancels immediately")

    editor.resetForm()
    editor.setFieldName(0, "  ")
    editor.submit()
    check(editor.errorMessage === "Custom field name cannot be empty.",
          "edit still rejects blank custom field names")

    // Restore create mode for the remaining checks.
    editor.mode = "create"
    editor.originalItem = null
    editor.cipherType = "login"
    editor.resetForm()

    // ------------------------------------------------------------------
    // 14. Edit mode dirty tracking
    // ------------------------------------------------------------------
    editor.cipherType = "login"
    editor.mode = "edit"
    editor.originalItem = originalLogin
    editor.resetForm()

    check(editor.isDirty === false, "editor pristine edit draft is clean")

    editor.cipherName = "GitHub Work"
    check(editor.isDirty === true, "editor changed name marks the edit draft dirty")
    editor.cipherName = "GitHub"
    check(editor.isDirty === false, "editor reverting the name restores a clean edit draft")

    editor.username = "carol"
    check(editor.isDirty === true, "editor changed username marks the edit draft dirty")
    editor.username = "alice"
    check(editor.isDirty === false, "editor reverting the username restores a clean edit draft")

    editor.password = "newpw"
    check(editor.isDirty === true, "editor changed password marks the edit draft dirty")
    editor.password = "pw123"
    check(editor.isDirty === false, "editor reverting the password restores a clean edit draft")

    editor.notes = "changed"
    check(editor.isDirty === true, "editor changed notes marks the edit draft dirty")
    editor.notes = "hello"
    check(editor.isDirty === false, "editor reverting the notes restores a clean edit draft")

    editor.folderId = "f2"
    check(editor.isDirty === true, "editor changed folder marks the edit draft dirty")
    editor.folderId = "f1"
    check(editor.isDirty === false, "editor reverting the folder restores a clean edit draft")

    editor.setUri(0, "https://gitlab.com")
    check(editor.isDirty === true, "editor changed URI marks the edit draft dirty")
    editor.resetForm()
    check(editor.isDirty === false, "editor reverting URI restores a clean edit draft")

    editor.addCustomField(0)
    editor.setFieldName(3, "extra")
    editor.setFieldValue(3, "value")
    check(editor.isDirty === true, "editor added custom field marks the edit draft dirty")
    editor.removeCustomField(3)
    check(editor.isDirty === false, "editor removing added custom field restores a clean edit draft")

    editor.removeCustomField(0)
    check(editor.isDirty === true, "editor removed existing custom field marks the edit draft dirty")

    // ------------------------------------------------------------------
    // 15. Edit cancel and dirty-draft confirmation
    // ------------------------------------------------------------------
    editor.resetForm()
    testRunner.editorCancelCount = 0
    editor.requestCancel()
    check(testRunner.editorCancelCount === 1, "editor pristine edit Esc cancels immediately")
    check(editor.discardPromptVisible === false, "editor pristine edit cancel shows no discard prompt")

    editor.resetForm()
    editor.cipherName = "draft"
    testRunner.editorCancelCount = 0
    editor.requestCancel()
    check(editor.discardPromptVisible === true, "editor dirty edit Esc raises the discard prompt")
    check(testRunner.editorCancelCount === 0, "editor dirty edit Esc does not cancel immediately")

    editor.keepEditing()
    check(editor.discardPromptVisible === false, "editor edit Keep Editing dismisses the prompt")
    check(testRunner.editorCancelCount === 0, "editor edit Keep Editing keeps the draft")

    editor.requestCancel()
    editor.confirmDiscard()
    check(editor.discardPromptVisible === false, "editor edit Discard dismisses the prompt")
    check(testRunner.editorCancelCount === 1, "editor edit Discard emits cancelRequested")

    // ==================================================================
    // Theme token compliance and source checks
    // ==================================================================

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
    // 16. Overlay wiring (source checks)
    // ------------------------------------------------------------------
    var src = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    check(src.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")

    // Create wiring
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

    var searchHeaderSrc = readSource(Qt.resolvedUrl("../components/SearchHeader.qml"))
    check(searchHeaderSrc.indexOf("createCipherRequested") !== -1,
          "SearchHeader declares the create signal")
    check(searchHeaderSrc.indexOf('searchHeaderRoot.activeCategory === "login" || searchHeaderRoot.activeCategory === "note"') !== -1,
          "SearchHeader + button only shows on Login and Secure Note tabs")

    var paletteSrc = readSource(Qt.resolvedUrl("../components/ActionPaletteModal.qml"))
    check(paletteSrc.indexOf('pressedKey = "Ctrl+N"') !== -1,
          "action palette maps Ctrl+N to the Create Login shortcut")

    // Edit wiring
    check(src.indexOf('[root.helperPath, "vault", "edit", item.id, "--stdin", "--json"]') !== -1,
          "edit runs vault edit <id> --stdin --json")
    check(src.indexOf("cipherEditProc.payload = JSON.stringify(payload)") !== -1,
          "edit serializes the JSON diff for stdin")

    check(src.indexOf('label: "Edit Item"') !== -1, "action palette exposes Edit Item")
    check(src.indexOf("function() { root.openCipherEditModal(item) }") !== -1,
          "action palette Edit Item opens the edit modal")
    check(src.indexOf('onEditRequested: function(item) { root.openCipherEditModal(item) }') !== -1,
          "Inspector Edit button is wired to the edit modal")

    var ctrlECount = src.split('sequence: "Ctrl+E"').length - 1
    check(ctrlECount === 1, "Ctrl+E is declared exactly once")
    check(src.indexOf('if (item.type_name === "ssh_key") root.openSshKeyModal("export", item)') === -1,
          "Ctrl+E no longer branches to SSH export")
    check(src.indexOf("if (root.selectedItem) root.openCipherEditModal(root.selectedItem)") !== -1,
          "Ctrl+E uniformly opens the edit modal for editable ciphers")
    check(src.indexOf("onEditItemRequested:") !== -1,
          "SearchHeader Ctrl+E routes to editItemRequested")
    check(src.indexOf('if (cipherType === "ssh_key") {\n      root.showTypePicker = false\n      root.openSshKeyModal("create", null)') !== -1,
          "TypePicker SSH Key selection routes to SshKeyModal")

    // SSH Key metadata-only edit in CipherEditor
    editor.active = false
    editor.mode = "edit"
    editor.cipherType = "ssh_key"
    editor.originalItem = {
      id: "ssh-1",
      type_name: "ssh_key",
      name: "Prod Key",
      folder_id: "f1",
      notes: "CI deploy key",
      fields: [{ name: "Env", value: "prod", type: 0 }]
    }
    editor.active = true
    check(editor.isSshKey === true, "CipherEditor recognizes ssh_key edit mode")
    check(editor.isLogin === false, "ssh_key edit mode hides login-only fields")
    editor.cipherName = "Prod Key Renamed"
    editor.notes = "Updated deploy notes"
    var sshPayloadBefore = testRunner.editorSubmitCount
    editor.submit()
    check(testRunner.editorSubmitCount === sshPayloadBefore + 1, "ssh_key edit submits minimal metadata diff")
    var sshDiff = testRunner.editorSubmitted
    check(sshDiff && sshDiff.name === "Prod Key Renamed", "ssh_key diff includes updated name")
    check(sshDiff && sshDiff.notes === "Updated deploy notes", "ssh_key diff includes updated notes")
    check(sshDiff && sshDiff.username === undefined && sshDiff.password === undefined && sshDiff.uris === undefined,
          "ssh_key diff never emits login-only keys")
    editor.active = false
    editor.mode = "create"
    editor.cipherType = "login"
    editor.originalItem = null

    // Card create mode: BIN auto-suggest, 4-digit year validation, no hard Luhn block
    editor.active = false
    editor.mode = "create"
    editor.cipherType = "card"
    editor.originalItem = null
    editor.active = true
    check(editor.isCard === true, "CipherEditor recognizes card create mode")
    check(editor.title === "New Card", "card create mode sets title to New Card")
    editor.cipherName = "Travel Visa"
    editor.cardholderName = "Jane Doe"
    editor.cardNumber = "4111111111111112" // intentionally non-Luhn to verify no hard Luhn block
    check(editor.cardBrand === "Visa", "BIN auto-suggest populates Visa when brand is unset")
    editor.cardBrand = "Mastercard"
    editor.cardNumber = "4111111111111119"
    check(editor.cardBrand === "Mastercard", "BIN auto-suggest never overrides a manually chosen brand")
    editor.cardBrand = "Visa"
    editor.cardExpMonth = "08"
    editor.cardExpYear = "29"
    var cardCreateBefore = testRunner.editorSubmitCount
    editor.submit()
    check(testRunner.editorSubmitCount === cardCreateBefore, "2-digit expiration year is rejected")
    check(editor.errorMessage.indexOf("4-digit") !== -1, "year validation explains 4-digit requirement")
    editor.cardExpYear = "2029"
    editor.cardCode = "123"
    editor.submit()
    check(testRunner.editorSubmitCount === cardCreateBefore + 1, "valid card create submits payload")
    var cardCreatePayload = testRunner.editorSubmitted
    check(cardCreatePayload && cardCreatePayload.cipher_type === "card", "card create emits cipher_type card")
    check(cardCreatePayload && cardCreatePayload.card && cardCreatePayload.card.brand === "Visa", "card create includes brand")
    check(cardCreatePayload && cardCreatePayload.card.number === "4111111111111119", "card create accepts non-Luhn number")
    check(cardCreatePayload && cardCreatePayload.card.expMonth === "08" && cardCreatePayload.card.expYear === "2029",
          "card create includes expiration month and year")
    check(cardCreatePayload && cardCreatePayload.card.code === "123", "card create includes security code")

    // Card edit mode: minimal dirty diff emits only modified card sub-fields
    editor.active = false
    editor.mode = "edit"
    editor.cipherType = "card"
    editor.originalItem = {
      id: "card-1",
      type_name: "card",
      name: "Travel Visa",
      folder_id: "f1",
      notes: "Primary card",
      card: {
        cardholderName: "Jane Doe",
        brand: "Visa",
        number: "4111111111111111",
        expMonth: "08",
        expYear: "2029",
        code: "123"
      },
      fields: []
    }
    editor.active = true
    check(editor.isDirty === false, "pristine card edit is not dirty")
    editor.cardExpMonth = "12"
    editor.cardCode = ""
    check(editor.isDirty === true, "modifying card sub-fields marks editor dirty")
    var cardEditBefore = testRunner.editorSubmitCount
    editor.submit()
    check(testRunner.editorSubmitCount === cardEditBefore + 1, "card edit submits minimal diff")
    var cardEditDiff = testRunner.editorSubmitted
    check(cardEditDiff && cardEditDiff.name === undefined, "unchanged name is omitted from card diff")
    check(cardEditDiff && cardEditDiff.card && cardEditDiff.card.expMonth === "12", "modified expMonth is emitted")
    check(cardEditDiff && cardEditDiff.card.code === "", "cleared code emits empty string")
    check(cardEditDiff && cardEditDiff.card.number === undefined && cardEditDiff.card.brand === undefined,
          "untouched card sub-fields are omitted from minimal diff")

    // Regression: opening an existing Card with empty brand and Visa BIN must NOT mutate brand or mark dirty
    editor.active = false
    editor.mode = "edit"
    editor.cipherType = "card"
    editor.originalItem = {
      id: "card-2",
      type_name: "card",
      name: "Unbranded Visa",
      folder_id: "",
      notes: "",
      card: {
        cardholderName: "Jane Doe",
        brand: "",
        number: "4111111111111111",
        expMonth: "08",
        expYear: "2029",
        code: ""
      },
      fields: []
    }
    editor.active = true
    check(editor.cardBrand === "", "prefilling an unbranded Card does not auto-mutate cardBrand")
    check(editor.isDirty === false, "prefilling an unbranded Card keeps the form pristine")
    // Regression: manually clearing brand prevents subsequent BIN auto-suggest overwrite
    editor.cardBrandManual = true
    editor.cardBrand = ""
    editor.cardNumber = "4111111111111112"
    check(editor.cardBrand === "", "manually cleared brand is not overwritten by BIN auto-suggest")

    // Identity create mode: all 18 fields including address3
    editor.active = false
    editor.mode = "create"
    editor.cipherType = "identity"
    editor.originalItem = null
    editor.active = true
    check(editor.isIdentity === true, "CipherEditor recognizes identity create mode")
    check(editor.title === "New Identity", "identity create mode sets title to New Identity")
    editor.cipherName = "Work Identity"
    editor.idTitle = "Dr"
    editor.idFirstName = "Ada"
    editor.idMiddleName = "Augusta"
    editor.idLastName = "Lovelace"
    editor.idUsername = "ada"
    editor.idCompany = "Analytical Engines"
    editor.idSsn = "123-45-6789"
    editor.idPassportNumber = "P998877"
    editor.idLicenseNumber = "DL-42"
    editor.idEmail = "ada@example.com"
    editor.idPhone = "+44 20 7946 0958"
    editor.idAddress1 = "12 St James Sq"
    editor.idAddress2 = "Floor 2"
    editor.idAddress3 = "Suite B"
    editor.idCity = "London"
    editor.idState = "Greater London"
    editor.idPostalCode = "SW1Y 4LB"
    editor.idCountry = "UK"
    var idCreateBefore = testRunner.editorSubmitCount
    editor.submit()
    check(testRunner.editorSubmitCount === idCreateBefore + 1, "identity create submits payload")
    var idCreatePayload = testRunner.editorSubmitted
    check(idCreatePayload && idCreatePayload.cipher_type === "identity", "identity create emits cipher_type identity")
    check(idCreatePayload && idCreatePayload.identity && idCreatePayload.identity.title === "Dr", "identity create includes title")
    check(idCreatePayload && idCreatePayload.identity.address3 === "Suite B", "identity create includes address3")
    check(idCreatePayload && idCreatePayload.identity.ssn === "123-45-6789", "identity create includes ssn")
    check(idCreatePayload && idCreatePayload.identity.licenseNumber === "DL-42", "identity create includes licenseNumber")

    // Identity edit mode: minimal dirty diff emits only modified identity sub-fields
    editor.active = false
    editor.mode = "edit"
    editor.cipherType = "identity"
    editor.originalItem = {
      id: "id-1",
      type_name: "identity",
      name: "Work Identity",
      folder_id: "f1",
      notes: "Notes",
      identity: {
        title: "Dr",
        firstName: "Ada",
        lastName: "Lovelace",
        address1: "12 St James Sq",
        address3: "Suite B",
        city: "London",
        ssn: "123-45-6789"
      },
      fields: []
    }
    editor.active = true
    check(editor.isDirty === false, "pristine identity edit is not dirty")
    editor.idCity = "Oxford"
    editor.idAddress3 = ""
    check(editor.isDirty === true, "modifying identity sub-fields marks editor dirty")
    var idEditBefore = testRunner.editorSubmitCount
    editor.submit()
    check(testRunner.editorSubmitCount === idEditBefore + 1, "identity edit submits minimal diff")
    var idEditDiff = testRunner.editorSubmitted
    check(idEditDiff && idEditDiff.name === undefined, "unchanged name is omitted from identity diff")
    check(idEditDiff && idEditDiff.identity && idEditDiff.identity.city === "Oxford", "modified city is emitted")
    check(idEditDiff && idEditDiff.identity.address3 === "", "cleared address3 emits empty string")
    check(idEditDiff && idEditDiff.identity.firstName === undefined && idEditDiff.identity.ssn === undefined,
          "untouched identity sub-fields are omitted from minimal diff")

    editor.active = false
    editor.mode = "create"
    editor.cipherType = "login"
    editor.originalItem = null

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
    check(editSuccessWindow.indexOf("root.cipherEditorEditItem = null") !== -1,
          "edit success clears the edited item")

    check(src.indexOf("cipherEditorComponent.errorMessage = errMsg") !== -1,
          "daemon errors keep the editor open with an inline banner")

    var inspectorSrc = readSource(Qt.resolvedUrl("../components/ItemInspector.qml"))
    check(inspectorSrc.indexOf("signal editRequested(var item)") !== -1,
          "ItemInspector declares editRequested")
    check(inspectorSrc.indexOf("inspectorRoot.editRequested(inspectorRoot.item)") !== -1,
          "Inspector Edit button emits editRequested")
    check(inspectorSrc.indexOf('CipherMutation.isEditableType(inspectorRoot.item)') !== -1,
          "Inspector offers Edit for editable cipher types via CipherMutation.isEditableType")

    // CipherEditor component instantiation
    check(src.indexOf("id: cipherEditorComponent") !== -1, "Overlay instantiates the CipherEditor")
    check(src.indexOf("active: root.showCipherEditor") !== -1, "CipherEditor visibility is bound to showCipherEditor")
    check(src.indexOf("mode: root.cipherEditorEditItem ? \"edit\" : \"create\"") !== -1,
          "CipherEditor switches to edit mode when cipherEditorEditItem is set")
    check(src.indexOf("cipherType: root.cipherEditorType") !== -1, "CipherEditor receives the picked cipher type")
    check(src.indexOf("defaultFolderId: root.cipherEditorDefaultFolderId") !== -1,
          "CipherEditor receives the scoped default folder")
    check(src.indexOf("originalItem: root.cipherEditorEditItem") !== -1,
          "CipherEditor receives the cipher being edited")
    check(src.indexOf("onSubmitRequested: function(payload)") !== -1 &&
          src.indexOf("root.submitCipherEdit(payload)") !== -1 &&
          src.indexOf("root.submitCipherCreate(payload)") !== -1 &&
          src.indexOf("root.cipherEditorEditItem") !== -1,
          "CipherEditor submit routes to edit handler in edit mode")

    check(src.indexOf("onGeneratePasswordRequested: { root.openPasswordGeneratorForCipherEditor() }") !== -1,
          "CipherEditor Generate opens the generator in fill mode")

    var modalLine2 = sourceLine(src, "readonly property bool hasActiveModal")
    check(modalLine2.indexOf("root.showCipherEditor") !== -1,
          "hasActiveModal includes the Inspector Form")

    var createFnIdx = src.indexOf("function openCipherCreateModal(cipherType)")
    var createFnWindow = createFnIdx >= 0 ? src.substring(createFnIdx, createFnIdx + 900) : ""
    check(createFnWindow.indexOf("root.showCipherEditor = true") !== -1,
          "openCipherCreateModal opens the Inspector Form")
    check(createFnWindow.indexOf("root.showCipherFormModal = true") === -1,
          "openCipherCreateModal no longer opens the centered modal")

    var editFnIdx = src.indexOf("function openCipherEditModal(item)")
    var editFnWindow = editFnIdx >= 0 ? src.substring(editFnIdx, editFnIdx + 900) : ""
    check(editFnWindow.indexOf("root.cipherEditorEditItem = item") !== -1,
          "openCipherEditModal installs the item before showing the editor")
    check(editFnWindow.indexOf("root.showCipherEditor = true") !== -1,
          "openCipherEditModal opens the Inspector Form")
    check(editFnWindow.indexOf("root.showCipherFormModal = true") === -1,
          "openCipherEditModal no longer opens the centered modal")

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
    check(src.indexOf("root.submitCipherEdit(payload)") !== -1, "edit payload reaches submitCipherEdit")

    check(src.indexOf("modalsActive: root.hasActiveModal") !== -1,
          "SearchHeader suspends itself while the editor is active")
    check(searchHeaderSrc.indexOf("enabled: !searchHeaderRoot.modalsActive") !== -1,
          "SearchHeader search box is disabled while a sub-interaction owns the keyboard")

    check(src.indexOf("visible: root.selectedItem !== null && !root.showCipherEditor") !== -1,
          "ItemInspector hides while the Inspector Form is open")
    check(src.indexOf("visible: root.selectedItem === null && !root.showCipherEditor") !== -1,
          "EmptyInspector hides while the Inspector Form is open")

    // ------------------------------------------------------------------
    // 17. Focus guard mirror with the Inspector Form
    // ------------------------------------------------------------------
    var showCipherEditor = true
    var hasActiveModalWithEditor = false || false || false || false || false || showCipherEditor
    check(hasActiveModalWithEditor === true, "open Inspector Form counts as an active sub-interaction")
    showCipherEditor = false
    hasActiveModalWithEditor = false || false || false || false || false || showCipherEditor
    check(hasActiveModalWithEditor === false, "closed Inspector Form releases the focus guard")

    // No CipherFormModal in focus guard
    var focusGuardIdx = src.indexOf("readonly property bool hasActiveModal")
    var focusGuardWindow = focusGuardIdx >= 0 ? src.substring(focusGuardIdx, focusGuardIdx + 200) : ""
    check(focusGuardWindow.indexOf("root.showCipherFormModal") === -1,
          "hasActiveModal no longer includes the retired CipherFormModal")

    console.log("CipherEditor Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}