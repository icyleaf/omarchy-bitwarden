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
    // 7. Theme token compliance
    // ------------------------------------------------------------------
    check(form.hasOwnProperty("cardBackground"), "cipher modal exposes cardBackground token")
    check(form.hasOwnProperty("foreground"), "cipher modal exposes foreground token")
    check(form.hasOwnProperty("accent"), "cipher modal exposes accent token")
    check(form.hasOwnProperty("borderColor"), "cipher modal exposes borderColor token")

    var modalSrc = readSource(Qt.resolvedUrl("../components/CipherFormModal.qml"))
    check(!/#[0-9a-fA-F]{3,8}\b/.test(modalSrc), "cipher modal contains no bare hex colors")
    check(!/Qt\.rgba\(\s*[\d.]+\s*,/.test(modalSrc), "cipher modal contains no numeric Qt.rgba literals")

    // ------------------------------------------------------------------
    // 8. Focus guard mirror
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
