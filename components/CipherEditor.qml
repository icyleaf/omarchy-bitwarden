import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "./CardFormatter.js" as CardFormatter
import qs.Commons
import qs.Commons as Commons

// Inspector-embedded cipher form for personal Login and Secure Note ciphers
// (issues #386, #387). Creation and edit drafts render in the right-hand
// Inspector column, so the vault list stays visible and no centered modal owns
// the screen.
//
// Secrets are only ever emitted through `submitRequested`; the Overlay pipes the
// payload to `omawarden vault create --stdin --json` or
// `omawarden vault edit <id> --stdin --json`, never via argv. In edit mode the
// payload is a minimal dirty diff against `originalItem`. The component never
// writes to the clipboard on its own.
//
// Keyboard: Ctrl+S saves, Esc cancels, Ctrl+G opens the Password Generator in
// fill mode (#385). Cancelling a dirty draft raises an inline discard prompt
// instead of silently dropping typed secrets.
ScrollView {
  id: editorRoot

  property bool active: false
  property string mode: "create" // "create" | "edit"
  property string cipherType: "login" // "login" | "note" | "card" | "identity" | "ssh_key"
  property var folders: [] // [{ id, name }]
  property string defaultFolderId: ""
  // In edit mode this is the selected vault item. Saving diffs against it.
  property var originalItem: null
  // Linked (type 3) fields are read-only and never enter the update payload.
  property var linkedFields: []

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.menu.border
  property string fontFamily: ""

  property bool isBusy: false
  property string errorMessage: ""
  property bool isGeneratingPassword: false
  property bool isEngineOutdated: false
  property string engineVersion: ""
  property string requiredVersion: "0.9.0"
  // True once the user asked to leave a dirty draft and must confirm discarding.
  property bool discardPromptVisible: false

  readonly property color textOnAccent: StatusPalette.textOn(accent)
  readonly property bool isLogin: cipherType === "login"
  readonly property bool isCard: cipherType === "card"
  readonly property bool isIdentity: cipherType === "identity"
  readonly property bool isSshKey: cipherType === "ssh_key"
  readonly property bool isEdit: mode === "edit"
  readonly property string title: isEdit ? "Edit Item" : (isLogin ? "New Login" : (isCard ? "New Card" : (isIdentity ? "New Identity" : "New Secure Note")))
  // Recomputed on every form mutation so the discard guard stays accurate even
  // when the user reverts their edits back to the original cipher.
  property bool isDirty: false

  // Editable form state.
  property string cipherName: ""
  property string folderId: ""
  property string username: ""
  property string password: ""
  property bool passwordRevealed: false
  property string cardholderName: ""
  property string cardBrand: ""
  property bool cardBrandManual: false
  property bool isResettingForm: false
  property string cardNumber: ""
  property bool cardNumberRevealed: false
  property string cardExpMonth: ""
  property string cardExpYear: ""
  property string cardCode: ""
  property bool cardCodeRevealed: false
  property string idTitle: ""
  property string idFirstName: ""
  property string idMiddleName: ""
  property string idLastName: ""
  property string idUsername: ""
  property string idCompany: ""
  property string idSsn: ""
  property bool idSsnRevealed: false
  property string idPassportNumber: ""
  property string idLicenseNumber: ""
  property string idEmail: ""
  property string idPhone: ""
  property string idAddress1: ""
  property string idAddress2: ""
  property string idAddress3: ""
  property string idCity: ""
  property string idState: ""
  property string idPostalCode: ""
  property string idCountry: ""
  property string notes: ""

  signal submitRequested(var payload)
  signal generatePasswordRequested()
  signal cancelRequested()

  clip: true
  visible: active
  ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
  ScrollBar.vertical: ScrollBar {
    id: editorVScrollBar
    policy: ScrollBar.AsNeeded
    contentItem: Rectangle {
      implicitWidth: 4
      radius: 2
      color: editorVScrollBar.pressed ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.4) : (editorVScrollBar.hovered ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.25) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.15))
    }
  }

  ListModel {
    id: uriModel
  }

  ListModel {
    id: fieldModel
  }

  // ----------------------------------------------------------------
  // Form state
  // ----------------------------------------------------------------

  function normalizeFolderId(value) {
    if (!value) return ""
    for (var i = 0; i < folders.length; i++) {
      if (folders[i].id === value) return value
    }
    return ""
  }

  function originalFields() {
    var out = []
    var src = (originalItem && originalItem.fields) ? originalItem.fields : []
    for (var i = 0; i < src.length; i++) {
      var field = src[i] || {}
      out.push({
        name: String(field.name || ""),
        value: String(field.value || ""),
        type: Number(field.type || 0)
      })
    }
    return out
  }

  function originalUriValues() {
    var out = []
    if (!originalItem || !originalItem.login || !originalItem.login.uris) return out
    var src = originalItem.login.uris
    for (var i = 0; i < src.length; i++) {
      var raw = src[i]
      var value = (typeof raw === "string") ? raw : ((raw && raw.uri) ? raw.uri : "")
      value = String(value || "").trim()
      if (value.length > 0) out.push(value)
    }
    return out
  }

  // Clears every plaintext value without repopulating from `originalItem`.
  // Called when the form closes so cancelled, saved, and locked drafts do not
  // linger in memory (security.md: secrets must not outlive the editor).
  function clearDraft() {
    errorMessage = ""
    isBusy = false
    isGeneratingPassword = false
    discardPromptVisible = false
    cipherName = ""
    folderId = ""
    username = ""
    password = ""
    passwordRevealed = false
    cardholderName = ""
    cardBrand = ""
    cardBrandManual = false
    cardNumber = ""
    cardNumberRevealed = false
    cardExpMonth = ""
    cardExpYear = ""
    cardCode = ""
    cardCodeRevealed = false
    idTitle = ""
    idFirstName = ""
    idMiddleName = ""
    idLastName = ""
    idUsername = ""
    idCompany = ""
    idSsn = ""
    idSsnRevealed = false
    idPassportNumber = ""
    idLicenseNumber = ""
    idEmail = ""
    idPhone = ""
    idAddress1 = ""
    idAddress2 = ""
    idAddress3 = ""
    idCity = ""
    idState = ""
    idPostalCode = ""
    idCountry = ""
    notes = ""
    uriModel.clear()
    fieldModel.clear()
    linkedFields = []
    isDirty = false
  }

  function resetForm() {
    isResettingForm = true
    clearDraft()

    var linked = []
    if (isEdit && originalItem) {
      cipherName = String(originalItem.name || "")
      // Keep the stored folder id even if the folder list is momentarily
      // incomplete, so an edit never silently moves the cipher to No Folder.
      folderId = String(originalItem.folder_id || "")
      notes = String(originalItem.notes || "")

      if (isLogin && originalItem.login) {
        username = String(originalItem.login.username || "")
        password = String(originalItem.login.password || "")
        var uris = originalItem.login.uris || []
        for (var u = 0; u < uris.length; u++) {
          var rawUri = uris[u]
          var uriValue = (typeof rawUri === "string") ? rawUri : ((rawUri && rawUri.uri) ? rawUri.uri : "")
          uriModel.append({ uri: String(uriValue || "") })
        }
      } else if (isCard && originalItem.card) {
        cardholderName = String(originalItem.card.cardholderName || "")
        cardBrand = String(originalItem.card.brand || "")
        cardNumber = String(originalItem.card.number || "")
        cardExpMonth = String(originalItem.card.expMonth || "")
        cardExpYear = String(originalItem.card.expYear || "")
        cardCode = String(originalItem.card.code || "")
      } else if (isIdentity && originalItem.identity) {
        idTitle = String(originalItem.identity.title || "")
        idFirstName = String(originalItem.identity.firstName || "")
        idMiddleName = String(originalItem.identity.middleName || "")
        idLastName = String(originalItem.identity.lastName || "")
        idUsername = String(originalItem.identity.username || "")
        idCompany = String(originalItem.identity.company || "")
        idSsn = String(originalItem.identity.ssn || "")
        idPassportNumber = String(originalItem.identity.passportNumber || "")
        idLicenseNumber = String(originalItem.identity.licenseNumber || "")
        idEmail = String(originalItem.identity.email || "")
        idPhone = String(originalItem.identity.phone || "")
        idAddress1 = String(originalItem.identity.address1 || "")
        idAddress2 = String(originalItem.identity.address2 || "")
        idAddress3 = String(originalItem.identity.address3 || "")
        idCity = String(originalItem.identity.city || "")
        idState = String(originalItem.identity.state || "")
        idPostalCode = String(originalItem.identity.postalCode || "")
        idCountry = String(originalItem.identity.country || "")
      }

      var fields = originalFields()
      for (var f = 0; f < fields.length; f++) {
        if (fields[f].type === 3) {
          linked.push(fields[f])
        } else {
          fieldModel.append({
            name: fields[f].name,
            value: fields[f].value,
            type: fields[f].type,
            revealed: false
          })
        }
      }
    } else {
      // The active folder scope pre-selects a folder, but that default alone
      // must not make a pristine draft look dirty.
      folderId = normalizeFolderId(defaultFolderId)
    }

    if (uriModel.count === 0) uriModel.append({ uri: "" })
    linkedFields = linked
    isResettingForm = false
    recomputeDirty()
  }

  onActiveChanged: {
    if (active) {
      // Opening initialises a pristine create draft or prefills the edit diff.
      resetForm()
      Qt.callLater(function() {
        if (titleInput) titleInput.forceActiveFocus()
      })
    } else {
      // Closing scrubs the plaintext secrets/notes out of memory.
      clearDraft()
    }
  }

  // A create draft is dirty once the user typed anything or added structure;
  // folder defaults and blank URI rows are not user intent, so they stay clean.
  // An edit draft is dirty only when it differs from the original cipher.
  function computeDirty() {
    if (isEdit) {
      return Object.keys(buildEditPayload(String(cipherName || "").trim())).length > 0
    }
    if (String(cipherName || "").trim() !== "") return true
    if (String(notes || "") !== "") return true
    if (String(folderId || "") !== String(normalizeFolderId(defaultFolderId) || "")) return true
    if (fieldModel.count > 0) return true
    if (isLogin) {
      if (String(username || "") !== "") return true
      if (String(password || "") !== "") return true
      for (var u = 0; u < uriModel.count; u++) {
        if (String(uriModel.get(u).uri || "").trim() !== "") return true
      }
    } else if (isCard) {
      if (String(cardholderName || "") !== "") return true
      if (String(cardBrand || "") !== "") return true
      if (String(cardNumber || "") !== "") return true
      if (String(cardExpMonth || "") !== "") return true
      if (String(cardExpYear || "") !== "") return true
      if (String(cardCode || "") !== "") return true
    } else if (isIdentity) {
      var idPairs = identityFieldPairs()
      for (var ii = 0; ii < idPairs.length; ii++) {
        if (idPairs[ii][1] !== "") return true
      }
    }
    return false
  }

  function identityFieldPairs() {
    return [
      ["title", String(idTitle || "")],
      ["firstName", String(idFirstName || "")],
      ["middleName", String(idMiddleName || "")],
      ["lastName", String(idLastName || "")],
      ["username", String(idUsername || "")],
      ["company", String(idCompany || "")],
      ["ssn", String(idSsn || "")],
      ["passportNumber", String(idPassportNumber || "")],
      ["licenseNumber", String(idLicenseNumber || "")],
      ["email", String(idEmail || "")],
      ["phone", String(idPhone || "")],
      ["address1", String(idAddress1 || "")],
      ["address2", String(idAddress2 || "")],
      ["address3", String(idAddress3 || "")],
      ["city", String(idCity || "")],
      ["state", String(idState || "")],
      ["postalCode", String(idPostalCode || "")],
      ["country", String(idCountry || "")]
    ]
  }

  function recomputeDirty() {
    isDirty = computeDirty()
  }

  onCipherNameChanged: recomputeDirty()
  onUsernameChanged: recomputeDirty()
  onPasswordChanged: recomputeDirty()
  onCardholderNameChanged: recomputeDirty()
  onCardBrandChanged: recomputeDirty()
  onCardNumberChanged: {
    if (!isResettingForm && isCard && !cardBrandManual && !String(cardBrand || "").trim()) {
      var suggested = CardFormatter.detectCardBrand(cardNumber)
      if (suggested) cardBrand = suggested
    }
    recomputeDirty()
  }
  onCardExpMonthChanged: recomputeDirty()
  onCardExpYearChanged: recomputeDirty()
  onCardCodeChanged: recomputeDirty()
  onIdTitleChanged: recomputeDirty()
  onIdFirstNameChanged: recomputeDirty()
  onIdMiddleNameChanged: recomputeDirty()
  onIdLastNameChanged: recomputeDirty()
  onIdUsernameChanged: recomputeDirty()
  onIdCompanyChanged: recomputeDirty()
  onIdSsnChanged: recomputeDirty()
  onIdPassportNumberChanged: recomputeDirty()
  onIdLicenseNumberChanged: recomputeDirty()
  onIdEmailChanged: recomputeDirty()
  onIdPhoneChanged: recomputeDirty()
  onIdAddress1Changed: recomputeDirty()
  onIdAddress2Changed: recomputeDirty()
  onIdAddress3Changed: recomputeDirty()
  onIdCityChanged: recomputeDirty()
  onIdStateChanged: recomputeDirty()
  onIdPostalCodeChanged: recomputeDirty()
  onIdCountryChanged: recomputeDirty()
  onNotesChanged: recomputeDirty()
  onFolderIdChanged: recomputeDirty()

  // ----------------------------------------------------------------
  // URIs
  // ----------------------------------------------------------------

  function addUri() {
    uriModel.append({ uri: "" })
  }

  function uriAt(index) {
    if (index < 0 || index >= uriModel.count) return null
    return uriModel.get(index)
  }

  function setUri(index, value) {
    if (index < 0 || index >= uriModel.count) return
    uriModel.setProperty(index, "uri", String(value || ""))
    recomputeDirty()
  }

  function removeUri(index) {
    if (index < 0 || index >= uriModel.count) return
    uriModel.remove(index)
    if (uriModel.count === 0) uriModel.append({ uri: "" })
    recomputeDirty()
  }

  // ----------------------------------------------------------------
  // Custom fields
  // ----------------------------------------------------------------

  function addCustomField(fieldType) {
    fieldModel.append({
      name: "",
      value: fieldType === 2 ? "false" : "",
      type: fieldType,
      revealed: false
    })
    recomputeDirty()
  }

  function removeCustomField(index) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.remove(index)
    recomputeDirty()
  }

  function customFieldAt(index) {
    if (index < 0 || index >= fieldModel.count) return null
    return fieldModel.get(index)
  }

  function setFieldName(index, value) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.setProperty(index, "name", String(value || ""))
    recomputeDirty()
  }

  function setFieldValue(index, value) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.setProperty(index, "value", String(value || ""))
    recomputeDirty()
  }

  function toggleFieldBoolean(index) {
    if (index < 0 || index >= fieldModel.count) return
    var current = fieldModel.get(index)
    fieldModel.setProperty(index, "value", current.value === "true" ? "false" : "true")
    recomputeDirty()
  }

  function toggleFieldRevealed(index) {
    if (index < 0 || index >= fieldModel.count) return
    var current = fieldModel.get(index)
    fieldModel.setProperty(index, "revealed", !current.revealed)
  }

  // ----------------------------------------------------------------
  // Folder selector
  // ----------------------------------------------------------------

  function folderOptions() {
    var list = [{ id: "__none__", name: "No Folder", icon: "\uf016" }]
    var sorted = (folders || []).slice()
    sorted.sort(function(a, b) {
      return String(a.name || "").localeCompare(String(b.name || ""))
    })
    for (var i = 0; i < sorted.length; i++) {
      list.push({ id: sorted[i].id, name: sorted[i].name, icon: "\uf07b" })
    }
    return list
  }

  function folderLabel() {
    if (!folderId) return "No Folder"
    for (var i = 0; i < folders.length; i++) {
      if (folders[i].id === folderId) return folders[i].name
    }
    return "No Folder"
  }

  // ----------------------------------------------------------------
  // Password generation (#385 fill-mode handoff)
  // ----------------------------------------------------------------

  function requestGeneratePassword() {
    if (isBusy || isGeneratingPassword) return
    if (isEngineOutdated) {
      errorMessage = "omawarden engine is outdated" + (engineVersion ? " (v" + engineVersion + ")" : "") +
                     ". Please upgrade omawarden to >= " + requiredVersion + " to generate passwords."
      return
    }
    errorMessage = ""
    isGeneratingPassword = true
    generatePasswordRequested()
  }

  // Called by the Overlay once the generator hands back the confirmed secret.
  function setGeneratedPassword(value) {
    isGeneratingPassword = false
    password = String(value || "")
    passwordRevealed = true
  }

  // ----------------------------------------------------------------
  // Payload + submission
  // ----------------------------------------------------------------

  function buildPayload() {
    var trimmedName = String(cipherName || "").trim()
    if (!trimmedName) {
      errorMessage = "Cipher name is required."
      return null
    }

    for (var i = 0; i < fieldModel.count; i++) {
      var field = fieldModel.get(i)
      if (!String(field.name || "").trim()) {
        errorMessage = "Custom field name cannot be empty."
        return null
      }
    }

    if (isCard) {
      var trimmedYear = String(cardExpYear || "").trim()
      if (trimmedYear.length > 0 && !/^\d{4}$/.test(trimmedYear)) {
        errorMessage = "Expiration year must be a 4-digit number (e.g. 2029)."
        return null
      }
    }

    if (isEdit && originalItem) return buildEditPayload(trimmedName)

    var payload = {
      cipher_type: cipherType,
      name: trimmedName,
      folder_id: folderId ? folderId : null
    }

    if (notes && notes.length > 0) payload.notes = notes

    if (isLogin) {
      if (username && username.length > 0) payload.username = username
      if (password && password.length > 0) payload.password = password

      var cleanedUris = []
      for (var u = 0; u < uriModel.count; u++) {
        var uri = String(uriModel.get(u).uri || "").trim()
        if (uri.length > 0) cleanedUris.push(uri)
      }
      if (cleanedUris.length > 0) payload.uris = cleanedUris
    } else if (isCard) {
      var cardObj = {}
      if (cardholderName && cardholderName.length > 0) cardObj.cardholderName = cardholderName
      if (cardBrand && cardBrand.length > 0) cardObj.brand = cardBrand
      if (cardNumber && cardNumber.length > 0) cardObj.number = cardNumber
      if (cardExpMonth && cardExpMonth.length > 0) cardObj.expMonth = cardExpMonth
      if (cardExpYear && String(cardExpYear).trim().length > 0) cardObj.expYear = String(cardExpYear).trim()
      if (cardCode && cardCode.length > 0) cardObj.code = cardCode
      payload.card = cardObj
    } else if (isIdentity) {
      var idObj = {}
      var idPairs = identityFieldPairs()
      for (var ii = 0; ii < idPairs.length; ii++) {
        if (idPairs[ii][1].length > 0) idObj[idPairs[ii][0]] = idPairs[ii][1]
      }
      payload.identity = idObj
    }

    var fields = []
    for (var f = 0; f < fieldModel.count; f++) {
      var item = fieldModel.get(f)
      fields.push({
        name: String(item.name || "").trim(),
        value: String(item.value || ""),
        type: item.type
      })
    }
    if (fields.length > 0) payload.fields = fields

    return payload
  }

  // Minimal dirty diff against the cipher being edited. An empty object means
  // the user changed nothing, so the caller can return to view mode without a
  // subprocess.
  function buildEditPayload(trimmedName) {
    var payload = {}
    var original = originalItem || {}

    if (trimmedName !== String(original.name || "")) payload.name = trimmedName

    var originalFolder = String(original.folder_id || "")
    var currentFolder = String(folderId || "")
    if (currentFolder !== originalFolder) payload.folder_id = currentFolder

    var originalNotes = String(original.notes || "")
    if (String(notes || "") !== originalNotes) payload.notes = String(notes || "")

    if (isLogin) {
      var login = original.login || {}

      if (String(username || "") !== String(login.username || "")) {
        payload.username = String(username || "")
      }
      if (String(password || "") !== String(login.password || "")) {
        payload.password = String(password || "")
      }

      var originalUris = originalUriValues()
      var currentUris = []
      for (var u = 0; u < uriModel.count; u++) {
        var uri = String(uriModel.get(u).uri || "").trim()
        if (uri.length > 0) currentUris.push(uri)
      }
      var urisMatch = originalUris.length === currentUris.length
      if (urisMatch) {
        for (var c = 0; c < currentUris.length; c++) {
          if (currentUris[c] !== originalUris[c]) {
            urisMatch = false
            break
          }
        }
      }
      if (!urisMatch) {
        if (currentUris.length === 0 && originalUris.length > 0) payload.clear_uris = true
        else payload.uris = currentUris
      }
    } else if (isCard) {
      var origCard = original.card || {}
      var cardDiff = {}
      var cardPairs = [
        ["cardholderName", String(cardholderName || "")],
        ["brand", String(cardBrand || "")],
        ["number", String(cardNumber || "")],
        ["expMonth", String(cardExpMonth || "")],
        ["expYear", String(cardExpYear || "").trim()],
        ["code", String(cardCode || "")]
      ]
      for (var ci = 0; ci < cardPairs.length; ci++) {
        var ck = cardPairs[ci][0]
        var cv = cardPairs[ci][1]
        if (cv !== String(origCard[ck] || "")) {
          cardDiff[ck] = cv
        }
      }
      if (Object.keys(cardDiff).length > 0) {
        payload.card = cardDiff
      }
    } else if (isIdentity) {
      var origId = original.identity || {}
      var idDiff = {}
      var idPairs = identityFieldPairs()
      for (var ii = 0; ii < idPairs.length; ii++) {
        var ik = idPairs[ii][0]
        var iv = idPairs[ii][1]
        if (iv !== String(origId[ik] || "")) {
          idDiff[ik] = iv
        }
      }
      if (Object.keys(idDiff).length > 0) {
        payload.identity = idDiff
      }
    }

    // Linked (type 3) fields are deliberately absent from both `fields` and
    // `remove_fields`, so the daemon preserves them untouched.
    var originalEditable = []
    var originalFieldList = originalFields()
    for (var o = 0; o < originalFieldList.length; o++) {
      if (originalFieldList[o].type !== 3) originalEditable.push(originalFieldList[o])
    }

    var currentNames = {}
    var upserts = []
    for (var i = 0; i < fieldModel.count; i++) {
      var item = fieldModel.get(i)
      var name = String(item.name || "").trim()
      var value = String(item.value || "")
      currentNames[name] = true

      var match = null
      for (var m = 0; m < originalEditable.length; m++) {
        if (originalEditable[m].name === name) {
          match = originalEditable[m]
          break
        }
      }
      if (!match || match.type !== item.type || match.value !== value) {
        upserts.push({ name: name, value: value, type: item.type })
      }
    }

    var removals = []
    for (var r = 0; r < originalEditable.length; r++) {
      if (!currentNames[originalEditable[r].name]) removals.push(originalEditable[r].name)
    }

    if (removals.length > 0) payload.remove_fields = removals
    if (upserts.length > 0) payload.fields = upserts

    return payload
  }

  function submit() {
    if (isBusy || discardPromptVisible) return
    errorMessage = ""
    var payload = buildPayload()
    if (!payload) return
    if (isEdit && Object.keys(payload).length === 0) {
      // Nothing changed: return to Inspector view mode without a subprocess.
      cancelRequested()
      return
    }
    submitRequested(payload)
  }

  // ----------------------------------------------------------------
  // Cancellation & draft protection
  // ----------------------------------------------------------------

  function requestCancel() {
    if (isBusy) return
    if (isDirty) {
      discardPromptVisible = true
      return
    }
    cancelRequested()
  }

  function confirmDiscard() {
    discardPromptVisible = false
    cancelRequested()
  }

  function keepEditing() {
    discardPromptVisible = false
  }

  // ----------------------------------------------------------------
  // Keyboard seam (dispatched by the Overlay's window-level Shortcuts and
  // exercised directly by the test runner)
  // ----------------------------------------------------------------

  function handleKey(key, modifiers) {
    if (discardPromptVisible) {
      if (key === Qt.Key_Escape) {
        keepEditing()
        return true
      }
      if (key === Qt.Key_Return || key === Qt.Key_Enter) {
        confirmDiscard()
        return true
      }
      return false
    }
    if (key === Qt.Key_Escape) {
      requestCancel()
      return true
    }
    if ((modifiers & Qt.ControlModifier) && key === Qt.Key_S) {
      submit()
      return true
    }
    if ((modifiers & Qt.ControlModifier) && key === Qt.Key_G) {
      requestGeneratePassword()
      return true
    }
    return false
  }

  // `handleKey` is the single source of truth for the form's keyboard
  // bindings. The Overlay's window-level Shortcuts (Ctrl+S / Ctrl+G / Esc)
  // dispatch into it, so the form owns no live Keys handler of its own: that
  // would be a second, racing source of truth for the same bindings.

  // ----------------------------------------------------------------
  // Embedded form
  // ----------------------------------------------------------------

  ColumnLayout {
    width: Math.max(0, editorRoot.availableWidth - 16)
    spacing: 12

    // Header
    RowLayout {
      Layout.fillWidth: true
      spacing: 8

      Text {
        text: editorRoot.isSshKey ? "\uf084" : (editorRoot.isCard ? "\uf09d" : (editorRoot.isIdentity ? "\uf2c2" : (editorRoot.isLogin ? "\uf023" : "\uf0f6")))
        font.family: editorRoot.fontFamily
        font.pixelSize: Style.font.subtitle
        color: editorRoot.accent
      }

      Text {
        text: editorRoot.title
        color: editorRoot.foreground
        font.pixelSize: Style.font.subtitle
        font.weight: Font.DemiBold
        Layout.fillWidth: true
        elide: Text.ElideRight
      }

      Text {
        text: "Ctrl+S"
        color: editorRoot.muted
        font.pixelSize: Style.font.caption
      }
    }

    Rectangle {
      Layout.fillWidth: true
      height: 1
      color: editorRoot.borderColor
    }

    // SSH Key immutability notice
    Rectangle {
      objectName: "sshKeyImmutableNotice"
      visible: editorRoot.isSshKey
      Layout.fillWidth: true
      implicitHeight: sshNoticeText.implicitHeight + 12
      radius: 4
      color: StatusPalette.tint(editorRoot.accent, 0.12)
      border.color: StatusPalette.tint(editorRoot.accent, 0.35)
      border.width: 1

      RowLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 6

        Text {
          text: "\uf05a"
          font.family: editorRoot.fontFamily
          font.pixelSize: Style.font.bodySmall
          color: editorRoot.accent
          Layout.alignment: Qt.AlignTop
        }

        Text {
          id: sshNoticeText
          text: "SSH key material is immutable here; only metadata, custom fields, and notes are editable."
          color: editorRoot.foreground
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
          Layout.fillWidth: true
        }
      }
    }

    // Error Alert Banner
    Rectangle {
      visible: Boolean(editorRoot.errorMessage)
      Layout.fillWidth: true
      implicitHeight: errText.implicitHeight + 12
      radius: 4
      color: StatusPalette.tint(StatusPalette.error, 0.15)
      border.color: StatusPalette.error
      border.width: 1

      RowLayout {
        anchors.fill: parent
        anchors.margins: 6
        spacing: 6

        Text {
          text: "\uf06a"
          font.family: editorRoot.fontFamily
          font.pixelSize: Style.font.bodySmall
          color: StatusPalette.danger
        }

        Text {
          id: errText
          text: editorRoot.errorMessage
          color: StatusPalette.invalidInput
          font.pixelSize: Style.font.bodySmall
          Layout.fillWidth: true
          wrapMode: Text.Wrap
        }
      }
    }

    // Discard draft confirmation
    Rectangle {
      visible: editorRoot.discardPromptVisible
      Layout.fillWidth: true
      implicitHeight: discardColumn.implicitHeight + 16
      radius: 4
      color: StatusPalette.tint(StatusPalette.warn, 0.15)
      border.color: StatusPalette.warn
      border.width: 1

      ColumnLayout {
        id: discardColumn
        anchors.fill: parent
        anchors.margins: 8
        spacing: 8

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          Text {
            text: "\uf071"
            font.family: editorRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: StatusPalette.warn
          }

          Text {
            text: "Discard this unsaved draft?"
            color: editorRoot.foreground
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: 8

          Item { Layout.fillWidth: true }

          Rectangle {
            implicitHeight: 26
            implicitWidth: keepRow.implicitWidth + 16
            radius: 4
            color: keepMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.1) : "transparent"
            border.color: editorRoot.borderColor
            border.width: 1

            Text {
              id: keepRow
              anchors.centerIn: parent
              text: "Keep Editing"
              color: editorRoot.foreground
              font.pixelSize: Style.font.caption
            }

            MouseArea {
              id: keepMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.keepEditing()
            }
          }

          Rectangle {
            implicitHeight: 26
            implicitWidth: discardRow.implicitWidth + 16
            radius: 4
            color: discardMouse.containsMouse ? Qt.lighter(StatusPalette.danger, 1.1) : StatusPalette.danger

            Text {
              id: discardRow
              anchors.centerIn: parent
              text: "Discard"
              color: StatusPalette.textOn(StatusPalette.danger)
              font.pixelSize: Style.font.caption
              font.weight: Font.DemiBold
            }

            MouseArea {
              id: discardMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.confirmDiscard()
            }
          }
        }
      }
    }

    // Name / Title
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 4

      Text {
        text: editorRoot.isLogin ? "Name *" : "Name *"
        color: editorRoot.muted
        font.pixelSize: Style.font.bodySmall
        font.weight: Font.Medium
      }

      Rectangle {
        Layout.fillWidth: true
        height: 32
        radius: 4
        color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
        border.color: titleInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
        border.width: 1

        TextInput {
          id: titleInput
          anchors.fill: parent
          anchors.leftMargin: 8
          anchors.rightMargin: 8
          verticalAlignment: Text.AlignVCenter
          color: editorRoot.foreground
          font.pixelSize: Style.font.body
          selectByMouse: true
          clip: true
          activeFocusOnTab: true
          text: editorRoot.cipherName
          onTextChanged: editorRoot.cipherName = text
        }
      }
    }

    // Folder
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 4

      Text {
        text: "Folder"
        color: editorRoot.muted
        font.pixelSize: Style.font.bodySmall
        font.weight: Font.Medium
      }

      Item {
        Layout.fillWidth: true
        Layout.preferredHeight: 32

        Rectangle {
          anchors.fill: parent
          radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: folderMouse.containsMouse ? editorRoot.accent : editorRoot.borderColor
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 8
            spacing: 6

            Text {
              text: "\uf07b"
              font.family: editorRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
              color: editorRoot.muted
            }

            Text {
              text: editorRoot.folderLabel()
              color: editorRoot.foreground
              font.pixelSize: Style.font.body
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            Text {
              text: "\uf0d7"
              font.family: editorRoot.fontFamily
              font.pixelSize: Style.font.caption
              color: editorRoot.muted
            }
          }

          MouseArea {
            id: folderMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (folderPopup.opened) folderPopup.close()
              else folderPopup.open()
            }
          }
        }

        Popup {
          id: folderPopup
          y: 38
          width: parent.width
          implicitHeight: Math.min(260, (editorRoot.folderOptions().length * 30) + 12)
          padding: 6
          modal: true
          focus: true
          closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

          background: Rectangle {
            color: editorRoot.cardBackground
            border.color: editorRoot.borderColor
            border.width: 1
            radius: 6
          }

          contentItem: ListView {
            id: folderList
            focus: true
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            model: editorRoot.folderOptions()
            spacing: 2

            delegate: Rectangle {
              required property int index
              required property var modelData
              width: folderList.width
              implicitHeight: 28
              radius: 4
              property bool isSelected: (modelData.id === "__none__" && editorRoot.folderId === "") ||
                                        modelData.id === editorRoot.folderId
              color: isSelected ? Qt.rgba(editorRoot.accent.r, editorRoot.accent.g, editorRoot.accent.b, 0.2) : (optionMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08) : "transparent")

              RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                spacing: 6

                Text {
                  text: modelData.icon || "\uf07b"
                  font.family: editorRoot.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  color: isSelected ? editorRoot.accent : editorRoot.muted
                }

                Text {
                  text: modelData.name || ""
                  color: isSelected ? editorRoot.accent : editorRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: isSelected ? Font.DemiBold : Font.Normal
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                }
              }

              MouseArea {
                id: optionMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  editorRoot.folderId = modelData.id === "__none__" ? "" : modelData.id
                  folderPopup.close()
                }
              }
            }
          }
        }
      }
    }

    // Login-only fields
    ColumnLayout {
      visible: editorRoot.isLogin
      Layout.fillWidth: true
      spacing: 12

      // Username
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Username"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        Rectangle {
          Layout.fillWidth: true
          height: 32
          radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: usernameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
          border.width: 1

          TextInput {
            id: usernameInput
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 8
            verticalAlignment: Text.AlignVCenter
            color: editorRoot.foreground
            font.pixelSize: Style.font.body
            selectByMouse: true
            clip: true
            activeFocusOnTab: true
            text: editorRoot.username
            onTextChanged: editorRoot.username = text
          }
        }
      }

      // Password
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Password"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          Rectangle {
            Layout.fillWidth: true
            height: 32
            radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: passwordInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
            border.width: 1

            TextInput {
              id: passwordInput
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter
              color: editorRoot.foreground
              font.pixelSize: Style.font.body
              selectByMouse: true
              clip: true
              activeFocusOnTab: true
              echoMode: editorRoot.passwordRevealed ? TextInput.Normal : TextInput.Password
              text: editorRoot.password
              onTextChanged: editorRoot.password = text
            }
          }

          // Reveal toggle
          Rectangle {
            Layout.preferredWidth: 32
            Layout.preferredHeight: 32
            radius: 4
            color: revealMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.15) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.05)
            border.color: editorRoot.borderColor
            border.width: 1

            Text {
              anchors.centerIn: parent
              text: editorRoot.passwordRevealed ? "\uf070" : "\uf06e"
              font.family: editorRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
              color: editorRoot.accent
            }

            MouseArea {
              id: revealMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.passwordRevealed = !editorRoot.passwordRevealed
            }
          }

          // Generate (Ctrl+G)
          Rectangle {
            Layout.preferredHeight: 32
            Layout.preferredWidth: generateRow.implicitWidth + 18
            radius: 4
            opacity: editorRoot.isEngineOutdated ? 0.4 : 1.0
            color: generateMouse.containsMouse ? Qt.lighter(editorRoot.accent, 1.12) : editorRoot.accent

            RowLayout {
              id: generateRow
              anchors.centerIn: parent
              spacing: 5

              Text {
                text: editorRoot.isGeneratingPassword ? "\uf110" : "\uf021"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.textOnAccent
              }

              Text {
                text: "Generate"
                font.pixelSize: Style.font.caption
                font.weight: Font.DemiBold
                color: editorRoot.textOnAccent
              }
            }

            MouseArea {
              id: generateMouse
              anchors.fill: parent
              enabled: !editorRoot.isEngineOutdated && !editorRoot.isGeneratingPassword
              hoverEnabled: true
              cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
              onClicked: editorRoot.requestGeneratePassword()
            }
          }
        }
      }

      // Login URIs
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          Text {
            text: "Websites"
            color: editorRoot.muted
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
          }

          Item { Layout.fillWidth: true }

          Rectangle {
            implicitHeight: 24
            implicitWidth: addUriRow.implicitWidth + 12
            radius: 4
            color: addUriMouse.containsMouse ? Qt.rgba(editorRoot.accent.r, editorRoot.accent.g, editorRoot.accent.b, 0.18) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.06)
            border.color: editorRoot.borderColor
            border.width: 1

            RowLayout {
              id: addUriRow
              anchors.centerIn: parent
              spacing: 4

              Text {
                text: "\uf067"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.accent
              }

              Text {
                text: "Add URI"
                font.pixelSize: Style.font.caption
                color: editorRoot.accent
              }
            }

            MouseArea {
              id: addUriMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.addUri()
            }
          }
        }

        Repeater {
          model: uriModel

          delegate: RowLayout {
            required property int index
            required property string uri
            Layout.fillWidth: true
            spacing: 6

            Rectangle {
              Layout.fillWidth: true
              height: 30
              radius: 4
              color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
              border.color: uriInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
              border.width: 1

              TextInput {
                id: uriInput
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                verticalAlignment: Text.AlignVCenter
                color: editorRoot.foreground
                font.pixelSize: Style.font.bodySmall
                selectByMouse: true
                clip: true
                activeFocusOnTab: true
                text: uri
                onTextChanged: {
                  if (uri !== text) {
                    uriModel.setProperty(index, "uri", text)
                    editorRoot.recomputeDirty()
                  }
                }
              }
            }

            Rectangle {
              Layout.preferredWidth: 26
              Layout.preferredHeight: 30
              radius: 4
              color: removeUriMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.15) : "transparent"
              border.color: editorRoot.borderColor
              border.width: 1

              Text {
                anchors.centerIn: parent
                text: "\uf00d"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.muted
              }

              MouseArea {
                id: removeUriMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: editorRoot.removeUri(index)
              }
            }
          }
        }
      }
    }

    // Card-only fields
    ColumnLayout {
      visible: editorRoot.isCard
      Layout.fillWidth: true
      spacing: 12

      // Cardholder Name
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Cardholder Name"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        Rectangle {
          Layout.fillWidth: true
          height: 32
          radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: cardholderInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
          border.width: 1

          TextInput {
            id: cardholderInput
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 8
            verticalAlignment: Text.AlignVCenter
            color: editorRoot.foreground
            font.pixelSize: Style.font.body
            selectByMouse: true
            clip: true
            activeFocusOnTab: true
            text: editorRoot.cardholderName
            onTextChanged: editorRoot.cardholderName = text
          }
        }
      }

      // Brand selector
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Brand"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        ComboBox {
          id: cardBrandCombo
          Layout.fillWidth: true
          height: 32
          model: [""].concat(CardFormatter.STANDARD_BRANDS)
          currentIndex: Math.max(0, model.indexOf(editorRoot.cardBrand))
          onActivated: {
            editorRoot.cardBrandManual = true
            editorRoot.cardBrand = currentText
          }
          displayText: editorRoot.cardBrand ? editorRoot.cardBrand : "Select brand"
          background: Rectangle {
            radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: cardBrandCombo.activeFocus ? editorRoot.accent : editorRoot.borderColor
            border.width: 1
          }
          contentItem: Text {
            leftPadding: 8
            rightPadding: 24
            text: cardBrandCombo.displayText
            color: editorRoot.cardBrand ? editorRoot.foreground : editorRoot.muted
            font.pixelSize: Style.font.body
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
          }
          delegate: ItemDelegate {
            width: cardBrandCombo.width
            height: 28
            highlighted: cardBrandCombo.highlightedIndex === index
            background: Rectangle {
              color: highlighted ? Commons.Color.menu.selectedBackground : "transparent"
            }
            contentItem: Text {
              text: modelData ? modelData : "Select brand"
              color: highlighted ? Commons.Color.menu.selectedText : (modelData ? editorRoot.foreground : editorRoot.muted)
              font.pixelSize: Style.font.bodySmall
              verticalAlignment: Text.AlignVCenter
              elide: Text.ElideRight
            }
          }
          popup: Popup {
            y: cardBrandCombo.height + 2
            width: cardBrandCombo.width
            padding: 2
            background: Rectangle {
              radius: 4
              color: Commons.Color.popups.background
              border.color: Commons.Color.popups.border
              border.width: 1
            }
            contentItem: ListView {
              clip: true
              implicitHeight: Math.min(contentHeight, 200)
              model: cardBrandCombo.popup.visible ? cardBrandCombo.delegateModel : null
              currentIndex: cardBrandCombo.highlightedIndex
            }
          }
        }
      }

      // Card Number (masked with reveal toggle)
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Number"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        Rectangle {
          Layout.fillWidth: true
          height: 32
          radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: cardNumberInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 4
            spacing: 4

            TextInput {
              id: cardNumberInput
              Layout.fillWidth: true
              verticalAlignment: Text.AlignVCenter
              color: editorRoot.foreground
              font.pixelSize: Style.font.body
              echoMode: editorRoot.cardNumberRevealed ? TextInput.Normal : TextInput.Password
              selectByMouse: true
              clip: true
              activeFocusOnTab: true
              text: editorRoot.cardNumber
              onTextChanged: editorRoot.cardNumber = text
            }

            GhostIconButton {
              iconText: editorRoot.cardNumberRevealed ? "\uf070" : "\uf06e"
              tooltip: editorRoot.cardNumberRevealed ? "Hide card number" : "Show card number"
              fontFamily: editorRoot.fontFamily
              onClicked: editorRoot.cardNumberRevealed = !editorRoot.cardNumberRevealed
            }
          }
        }
      }

      // Expiration Month & Year (2-column compact row)
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4

          Text {
            text: "Expiration Month"
            color: editorRoot.muted
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
          }

          ComboBox {
            id: cardMonthCombo
            Layout.fillWidth: true
            height: 32
            model: ["", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
            currentIndex: Math.max(0, model.indexOf(editorRoot.cardExpMonth))
            onActivated: editorRoot.cardExpMonth = currentText
            displayText: editorRoot.cardExpMonth ? editorRoot.cardExpMonth : "Month"
            background: Rectangle {
              radius: 4
              color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
              border.color: cardMonthCombo.activeFocus ? editorRoot.accent : editorRoot.borderColor
              border.width: 1
            }
            contentItem: Text {
              leftPadding: 8
              rightPadding: 24
              text: cardMonthCombo.displayText
              color: editorRoot.cardExpMonth ? editorRoot.foreground : editorRoot.muted
              font.pixelSize: Style.font.body
              verticalAlignment: Text.AlignVCenter
              elide: Text.ElideRight
            }
            delegate: ItemDelegate {
              width: cardMonthCombo.width
              height: 28
              highlighted: cardMonthCombo.highlightedIndex === index
              background: Rectangle {
                color: highlighted ? Commons.Color.menu.selectedBackground : "transparent"
              }
              contentItem: Text {
                text: modelData ? modelData : "Month"
                color: highlighted ? Commons.Color.menu.selectedText : (modelData ? editorRoot.foreground : editorRoot.muted)
                font.pixelSize: Style.font.bodySmall
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
              }
            }
            popup: Popup {
              y: cardMonthCombo.height + 2
              width: cardMonthCombo.width
              padding: 2
              background: Rectangle {
                radius: 4
                color: Commons.Color.popups.background
                border.color: Commons.Color.popups.border
                border.width: 1
              }
              contentItem: ListView {
                clip: true
                implicitHeight: Math.min(contentHeight, 200)
                model: cardMonthCombo.popup.visible ? cardMonthCombo.delegateModel : null
                currentIndex: cardMonthCombo.highlightedIndex
              }
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4

          Text {
            text: "Expiration Year"
            color: editorRoot.muted
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
          }

          Rectangle {
            Layout.fillWidth: true
            height: 32
            radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: cardYearInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
            border.width: 1

            TextInput {
              id: cardYearInput
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter
              color: editorRoot.foreground
              font.pixelSize: Style.font.body
              selectByMouse: true
              clip: true
              maximumLength: 4
              activeFocusOnTab: true
              text: editorRoot.cardExpYear
              onTextChanged: editorRoot.cardExpYear = text
            }
          }
        }
      }

      // Security Code / CVV (masked with reveal toggle)
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4

        Text {
          text: "Security Code (CVV)"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        Rectangle {
          Layout.fillWidth: true
          height: 32
          radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: cardCodeInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 4
            spacing: 4

            TextInput {
              id: cardCodeInput
              Layout.fillWidth: true
              verticalAlignment: Text.AlignVCenter
              color: editorRoot.foreground
              font.pixelSize: Style.font.body
              echoMode: editorRoot.cardCodeRevealed ? TextInput.Normal : TextInput.Password
              selectByMouse: true
              clip: true
              activeFocusOnTab: true
              text: editorRoot.cardCode
              onTextChanged: editorRoot.cardCode = text
            }

            GhostIconButton {
              iconText: editorRoot.cardCodeRevealed ? "\uf070" : "\uf06e"
              tooltip: editorRoot.cardCodeRevealed ? "Hide security code" : "Show security code"
              fontFamily: editorRoot.fontFamily
              onClicked: editorRoot.cardCodeRevealed = !editorRoot.cardCodeRevealed
            }
          }
        }
      }
    }

    // Identity-only fields (4 flat sections: Personal, Identification, Contact, Address)
    ColumnLayout {
      visible: editorRoot.isIdentity
      Layout.fillWidth: true
      spacing: 12

      // Section 1: Personal
      Text {
        text: "PERSONAL"
        color: editorRoot.accent
        font.pixelSize: Style.font.caption
        font.weight: Font.DemiBold
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.preferredWidth: 110
          spacing: 4
          Text { text: "Title"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          ComboBox {
            id: idTitleCombo
            Layout.fillWidth: true
            height: 32
            model: ["", "Mr", "Mrs", "Ms", "Mx", "Dr"]
            currentIndex: Math.max(0, model.indexOf(editorRoot.idTitle))
            onActivated: editorRoot.idTitle = currentText
            displayText: editorRoot.idTitle ? editorRoot.idTitle : "Title"
            background: Rectangle {
              radius: 4
              color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
              border.color: idTitleCombo.activeFocus ? editorRoot.accent : editorRoot.borderColor
              border.width: 1
            }
            contentItem: Text {
              leftPadding: 8
              rightPadding: 24
              text: idTitleCombo.displayText
              color: editorRoot.idTitle ? editorRoot.foreground : editorRoot.muted
              font.pixelSize: Style.font.body
              verticalAlignment: Text.AlignVCenter
              elide: Text.ElideRight
            }
            delegate: ItemDelegate {
              width: idTitleCombo.width
              height: 28
              highlighted: idTitleCombo.highlightedIndex === index
              background: Rectangle { color: highlighted ? Commons.Color.menu.selectedBackground : "transparent" }
              contentItem: Text {
                text: modelData ? modelData : "None"
                color: highlighted ? Commons.Color.menu.selectedText : (modelData ? editorRoot.foreground : editorRoot.muted)
                font.pixelSize: Style.font.bodySmall
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
              }
            }
            popup: Popup {
              y: idTitleCombo.height + 2
              width: idTitleCombo.width
              padding: 2
              background: Rectangle {
                radius: 4
                color: Commons.Color.popups.background
                border.color: Commons.Color.popups.border
                border.width: 1
              }
              contentItem: ListView {
                clip: true
                implicitHeight: Math.min(contentHeight, 200)
                model: idTitleCombo.popup.visible ? idTitleCombo.delegateModel : null
                currentIndex: idTitleCombo.highlightedIndex
              }
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "First Name"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idFirstNameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idFirstNameInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idFirstName; onTextChanged: editorRoot.idFirstName = text
            }
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Middle Name"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idMiddleNameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idMiddleNameInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idMiddleName; onTextChanged: editorRoot.idMiddleName = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Last Name"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idLastNameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idLastNameInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idLastName; onTextChanged: editorRoot.idLastName = text
            }
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Username"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idUsernameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idUsernameInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idUsername; onTextChanged: editorRoot.idUsername = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Company"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idCompanyInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idCompanyInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idCompany; onTextChanged: editorRoot.idCompany = text
            }
          }
        }
      }

      // Section 2: Identification
      Text {
        text: "IDENTIFICATION"
        color: editorRoot.accent
        font.pixelSize: Style.font.caption
        font.weight: Font.DemiBold
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4
        Text { text: "SSN"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
        Rectangle {
          Layout.fillWidth: true; height: 32; radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: idSsnInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
          RowLayout {
            anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 4; spacing: 4
            TextInput {
              id: idSsnInput; Layout.fillWidth: true; verticalAlignment: Text.AlignVCenter
              color: editorRoot.foreground; font.pixelSize: Style.font.body
              echoMode: editorRoot.idSsnRevealed ? TextInput.Normal : TextInput.Password
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idSsn; onTextChanged: editorRoot.idSsn = text
            }
            GhostIconButton {
              iconText: editorRoot.idSsnRevealed ? "\uf070" : "\uf06e"
              tooltip: editorRoot.idSsnRevealed ? "Hide SSN" : "Show SSN"
              fontFamily: editorRoot.fontFamily
              onClicked: editorRoot.idSsnRevealed = !editorRoot.idSsnRevealed
            }
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Passport Number"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idPassportInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idPassportInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idPassportNumber; onTextChanged: editorRoot.idPassportNumber = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "License Number"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idLicenseInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idLicenseInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idLicenseNumber; onTextChanged: editorRoot.idLicenseNumber = text
            }
          }
        }
      }

      // Section 3: Contact
      Text {
        text: "CONTACT"
        color: editorRoot.accent
        font.pixelSize: Style.font.caption
        font.weight: Font.DemiBold
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Email"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idEmailInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idEmailInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idEmail; onTextChanged: editorRoot.idEmail = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Phone"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idPhoneInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idPhoneInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idPhone; onTextChanged: editorRoot.idPhone = text
            }
          }
        }
      }

      // Section 4: Address
      Text {
        text: "ADDRESS"
        color: editorRoot.accent
        font.pixelSize: Style.font.caption
        font.weight: Font.DemiBold
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 4
        Text { text: "Address 1"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
        Rectangle {
          Layout.fillWidth: true; height: 32; radius: 4
          color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
          border.color: idAddress1Input.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
          TextInput {
            id: idAddress1Input; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
            verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
            selectByMouse: true; clip: true; activeFocusOnTab: true
            text: editorRoot.idAddress1; onTextChanged: editorRoot.idAddress1 = text
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Address 2"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idAddress2Input.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idAddress2Input; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idAddress2; onTextChanged: editorRoot.idAddress2 = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Address 3"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idAddress3Input.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idAddress3Input; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idAddress3; onTextChanged: editorRoot.idAddress3 = text
            }
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "City / Town"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idCityInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idCityInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idCity; onTextChanged: editorRoot.idCity = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "State / Province"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idStateInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idStateInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idState; onTextChanged: editorRoot.idState = text
            }
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Zip / Postal Code"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idPostalCodeInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idPostalCodeInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idPostalCode; onTextChanged: editorRoot.idPostalCode = text
            }
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4
          Text { text: "Country"; color: editorRoot.muted; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
            border.color: idCountryInput.activeFocus ? editorRoot.accent : editorRoot.borderColor; border.width: 1
            TextInput {
              id: idCountryInput; anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter; color: editorRoot.foreground; font.pixelSize: Style.font.body
              selectByMouse: true; clip: true; activeFocusOnTab: true
              text: editorRoot.idCountry; onTextChanged: editorRoot.idCountry = text
            }
          }
        }
      }
    }

    // Notes / note body
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 4

      Text {
        text: (editorRoot.isLogin || editorRoot.isCard || editorRoot.isIdentity || editorRoot.isSshKey) ? "Notes (optional)" : "Note"
        color: editorRoot.muted
        font.pixelSize: Style.font.bodySmall
        font.weight: Font.Medium
      }

      Rectangle {
        Layout.fillWidth: true
        height: 84
        radius: 4
        color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
        border.color: notesInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
        border.width: 1

        Flickable {
          anchors.fill: parent
          anchors.margins: 6
          clip: true

          TextArea.flickable: TextArea {
            id: notesInput
            color: editorRoot.foreground
            background: null
            padding: 0
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WrapAnywhere
            selectByMouse: true
            activeFocusOnTab: true
            text: editorRoot.notes
            onTextChanged: editorRoot.notes = text
          }
        }
      }
    }

    // Custom Fields
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 6

      RowLayout {
        Layout.fillWidth: true
        spacing: 6

        Text {
          text: "Custom Fields"
          color: editorRoot.muted
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
        }

        Item { Layout.fillWidth: true }

        Repeater {
          model: [
            { label: "Text", type: 0 },
            { label: "Hidden", type: 1 },
            { label: "Boolean", type: 2 }
          ]

          Rectangle {
            required property var modelData
            objectName: "editorAddFieldButton_" + modelData.type
            implicitHeight: 24
            implicitWidth: addFieldRow.implicitWidth + 12
            radius: 4
            color: addFieldMouse.containsMouse ? Qt.rgba(editorRoot.accent.r, editorRoot.accent.g, editorRoot.accent.b, 0.18) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.06)
            border.color: editorRoot.borderColor
            border.width: 1

            RowLayout {
              id: addFieldRow
              objectName: "editorAddFieldRow_" + modelData.type
              anchors.centerIn: parent
              spacing: 4

              Text {
                text: "\uf067"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.accent
              }

              Text {
                text: modelData.label
                font.pixelSize: Style.font.caption
                color: editorRoot.accent
              }
            }

            MouseArea {
              id: addFieldMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.addCustomField(modelData.type)
            }
          }
        }
      }

      Repeater {
        model: fieldModel

        delegate: ColumnLayout {
          required property int index
          required property string name
          required property string value
          required property int type
          required property bool revealed
          Layout.fillWidth: true
          spacing: 4

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Rectangle {
              implicitHeight: 22
              implicitWidth: typeLabel.implicitWidth + 10
              radius: 3
              color: StatusPalette.tint(StatusPalette.info, 0.15)
              border.color: StatusPalette.info
              border.width: 1

              Text {
                id: typeLabel
                anchors.centerIn: parent
                text: type === 0 ? "Text" : (type === 1 ? "Hidden" : "Boolean")
                color: StatusPalette.labelOnTint(StatusPalette.info, 0.15, editorRoot.cardBackground)
                font.pixelSize: Style.font.caption
              }
            }

            Rectangle {
              Layout.fillWidth: true
              height: 30
              radius: 4
              color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
              border.color: fieldNameInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
              border.width: 1

              TextInput {
                id: fieldNameInput
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                verticalAlignment: Text.AlignVCenter
                color: editorRoot.foreground
                font.pixelSize: Style.font.bodySmall
                selectByMouse: true
                clip: true
                activeFocusOnTab: true
                text: name
                onTextChanged: {
                  if (name !== text) {
                    fieldModel.setProperty(index, "name", text)
                    editorRoot.recomputeDirty()
                  }
                }
              }
            }

            Rectangle {
              Layout.preferredWidth: 26
              Layout.preferredHeight: 30
              radius: 4
              color: removeFieldMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.15) : "transparent"
              border.color: editorRoot.borderColor
              border.width: 1

              Text {
                anchors.centerIn: parent
                text: "\uf00d"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.muted
              }

              MouseArea {
                id: removeFieldMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: editorRoot.removeCustomField(index)
              }
            }
          }

          // Boolean toggle
          Rectangle {
            visible: type === 2
            Layout.fillWidth: true
            height: 28
            radius: 4
            color: value === "true" ? StatusPalette.tint(StatusPalette.success, 0.2) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.06)
            border.color: value === "true" ? StatusPalette.success : editorRoot.borderColor
            border.width: 1

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              spacing: 6

              Text {
                text: value === "true" ? "\uf00c" : "\uf00d"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: value === "true" ? StatusPalette.labelOnTint(StatusPalette.success, 0.2, editorRoot.cardBackground) : editorRoot.muted
              }

              Text {
                text: value === "true" ? "true" : "false"
                color: value === "true" ? StatusPalette.labelOnTint(StatusPalette.success, 0.2, editorRoot.cardBackground) : editorRoot.foreground
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: editorRoot.toggleFieldBoolean(index)
            }
          }

          // Text / Hidden value
          RowLayout {
            visible: type !== 2
            Layout.fillWidth: true
            spacing: 6

            Rectangle {
              Layout.fillWidth: true
              height: 30
              radius: 4
              color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08)
              border.color: fieldValueInput.activeFocus ? editorRoot.accent : editorRoot.borderColor
              border.width: 1

              TextInput {
                id: fieldValueInput
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                verticalAlignment: Text.AlignVCenter
                color: editorRoot.foreground
                font.pixelSize: Style.font.bodySmall
                selectByMouse: true
                clip: true
                activeFocusOnTab: true
                echoMode: (type === 1 && !revealed) ? TextInput.Password : TextInput.Normal
                text: value
                onTextChanged: {
                  if (value !== text) {
                    fieldModel.setProperty(index, "value", text)
                    editorRoot.recomputeDirty()
                  }
                }
              }
            }

            Rectangle {
              visible: type === 1
              Layout.preferredWidth: 30
              Layout.preferredHeight: 30
              radius: 4
              color: fieldRevealMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.15) : Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.05)
              border.color: editorRoot.borderColor
              border.width: 1

              Text {
                anchors.centerIn: parent
                text: revealed ? "\uf070" : "\uf06e"
                font.family: editorRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: editorRoot.accent
              }

              MouseArea {
                id: fieldRevealMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: editorRoot.toggleFieldRevealed(index)
              }
            }
          }
        }
      }

      // Linked (type 3) fields are read-only: they reference other item
      // properties and must never be rewritten by the edit diff.
      Repeater {
        model: editorRoot.linkedFields

        delegate: ColumnLayout {
          required property var modelData
          Layout.fillWidth: true
          spacing: 4

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Rectangle {
              implicitHeight: 22
              implicitWidth: linkedTypeLabel.implicitWidth + 10
              radius: 3
              color: StatusPalette.tint(StatusPalette.trace, 0.15)
              border.color: StatusPalette.trace
              border.width: 1

              Text {
                id: linkedTypeLabel
                anchors.centerIn: parent
                text: "Linked"
                color: StatusPalette.labelOnTint(StatusPalette.trace, 0.15, editorRoot.cardBackground)
                font.pixelSize: Style.font.caption
              }
            }

            Text {
              text: modelData.name || "Field"
              color: editorRoot.muted
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            Text {
              text: "read-only"
              color: editorRoot.muted
              font.pixelSize: Style.font.caption
            }
          }

          Rectangle {
            Layout.fillWidth: true
            height: 30
            radius: 4
            color: Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.04)
            border.color: editorRoot.borderColor
            border.width: 1

            Text {
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              verticalAlignment: Text.AlignVCenter
              text: modelData.value || ""
              color: editorRoot.muted
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
            }
          }
        }
      }
    }

    // Footer actions
    RowLayout {
      Layout.fillWidth: true
      Layout.topMargin: 4
      spacing: 8

      Text {
        text: "Esc to cancel"
        color: editorRoot.muted
        font.pixelSize: Style.font.caption
      }

      Item { Layout.fillWidth: true }

      Rectangle {
        implicitHeight: 30
        implicitWidth: 76
        radius: 4
        color: cancelMouse.containsMouse ? Qt.rgba(editorRoot.foreground.r, editorRoot.foreground.g, editorRoot.foreground.b, 0.08) : "transparent"
        border.color: editorRoot.borderColor
        border.width: 1

        Text {
          anchors.centerIn: parent
          text: "Cancel"
          color: cancelMouse.containsMouse ? editorRoot.foreground : editorRoot.muted
          font.pixelSize: Style.font.bodySmall
        }

        MouseArea {
          id: cancelMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: editorRoot.requestCancel()
        }
      }

      Rectangle {
        implicitHeight: 30
        implicitWidth: 100
        radius: 4
        color: submitMouse.containsMouse ? Qt.lighter(editorRoot.accent, 1.1) : editorRoot.accent
        opacity: editorRoot.isBusy ? 0.6 : 1.0

        RowLayout {
          anchors.centerIn: parent
          spacing: 6

          Text {
            visible: editorRoot.isBusy
            text: "\uf110"
            font.family: editorRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: editorRoot.textOnAccent
          }

          Text {
            text: editorRoot.isBusy ? (editorRoot.isEdit ? "Saving..." : "Creating...") : (editorRoot.isEdit ? "Save Changes" : "Save")
            color: editorRoot.textOnAccent
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.DemiBold
          }
        }

        MouseArea {
          id: submitMouse
          anchors.fill: parent
          enabled: !editorRoot.isBusy
          hoverEnabled: true
          cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
          onClicked: editorRoot.submit()
        }
      }
    }
  }
}
