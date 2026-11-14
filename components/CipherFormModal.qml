import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQml.Models
import qs.Commons
import qs.Commons as Commons

// Create/edit form for personal Login and Secure Note ciphers.
// Secrets are only ever emitted through `submitRequested`; the Overlay pipes
// the payload to `omawarden vault create/edit --stdin --json`, never via argv.
Rectangle {
  id: modalRoot

  property bool active: false
  property string mode: "create" // "create" | "edit"
  property string cipherType: "login" // "login" | "note"
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
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  property bool isBusy: false
  property string errorMessage: ""
  property bool isGeneratingPassword: false
  property bool isEngineOutdated: false
  property string engineVersion: ""
  property string requiredVersion: "0.9.0"

  readonly property color textOnAccent: StatusPalette.textOn(accent)
  readonly property bool isLogin: cipherType === "login"
  readonly property bool isEdit: mode === "edit"
  readonly property string title: isEdit ? "Edit Item" : (isLogin ? "New Login" : "New Secure Note")

  // Editable form state.
  property string cipherName: ""
  property string folderId: ""
  property string username: ""
  property string password: ""
  property bool passwordRevealed: false
  property string notes: ""

  signal submitRequested(var payload)
  signal generatePasswordRequested()
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 120

  ListModel {
    id: uriModel
  }

  ListModel {
    id: fieldModel
  }

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

  function resetForm() {
    errorMessage = ""
    isBusy = false
    isGeneratingPassword = false
    cipherName = ""
    folderId = ""
    username = ""
    password = ""
    passwordRevealed = false
    notes = ""
    uriModel.clear()
    fieldModel.clear()

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
      folderId = normalizeFolderId(defaultFolderId)
    }

    if (uriModel.count === 0) uriModel.append({ uri: "" })
    linkedFields = linked
  }

  onActiveChanged: {
    if (active) {
      resetForm()
      Qt.callLater(function() {
        if (nameInput) nameInput.forceActiveFocus()
      })
    }
  }

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
  }

  function removeUri(index) {
    if (index < 0 || index >= uriModel.count) return
    uriModel.remove(index)
    if (uriModel.count === 0) uriModel.append({ uri: "" })
  }

  function addCustomField(fieldType) {
    fieldModel.append({
      name: "",
      value: fieldType === 2 ? "false" : "",
      type: fieldType,
      revealed: false
    })
  }

  function removeCustomField(index) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.remove(index)
  }

  function customFieldAt(index) {
    if (index < 0 || index >= fieldModel.count) return null
    return fieldModel.get(index)
  }

  function setFieldName(index, value) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.setProperty(index, "name", String(value || ""))
  }

  function setFieldValue(index, value) {
    if (index < 0 || index >= fieldModel.count) return
    fieldModel.setProperty(index, "value", String(value || ""))
  }

  function toggleFieldBoolean(index) {
    if (index < 0 || index >= fieldModel.count) return
    var current = fieldModel.get(index)
    fieldModel.setProperty(index, "value", current.value === "true" ? "false" : "true")
  }

  function toggleFieldRevealed(index) {
    if (index < 0 || index >= fieldModel.count) return
    var current = fieldModel.get(index)
    fieldModel.setProperty(index, "revealed", !current.revealed)
  }

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

  function setGeneratedPassword(value) {
    isGeneratingPassword = false
    password = String(value || "")
    passwordRevealed = true
  }

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
  // the user changed nothing, so the caller can dismiss without a subprocess.
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
    if (isBusy) return
    errorMessage = ""
    var payload = buildPayload()
    if (!payload) return
    if (isEdit && Object.keys(payload).length === 0) {
      closeRequested()
      return
    }
    submitRequested(payload)
  }

  MouseArea {
    anchors.fill: parent
    onClicked: {
      if (!modalRoot.isBusy) modalRoot.closeRequested()
    }
  }

  // Modal Dialog Card
  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 560)
    height: Math.min(parent.height - 48, 620)
    radius: 10
    color: modalRoot.cardBackground
    border.color: modalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 18
      spacing: 12

      // Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: modalRoot.isLogin ? "\uf023" : "\uf0f6"
          font.family: modalRoot.fontFamily
          font.pixelSize: Style.font.subtitle
          color: modalRoot.accent
        }

        Text {
          text: modalRoot.title
          color: modalRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.DemiBold
        }

        Item { Layout.fillWidth: true }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: modalRoot.borderColor
      }

      // Error Alert Banner
      Rectangle {
        visible: Boolean(modalRoot.errorMessage)
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
            font.family: modalRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: StatusPalette.danger
          }

          Text {
            id: errText
            text: modalRoot.errorMessage
            color: StatusPalette.invalidInput
            font.pixelSize: Style.font.bodySmall
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }
      }

      // Form Area (Scrollable)
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        ColumnLayout {
          width: modalCard.width - 36
          spacing: 12

          // Name
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            Text {
              text: "Name *"
              color: modalRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }

            Rectangle {
              Layout.fillWidth: true
              height: 32
              radius: 4
              color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
              border.color: nameInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
              border.width: 1

              TextInput {
                id: nameInput
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                verticalAlignment: Text.AlignVCenter
                color: modalRoot.foreground
                font.pixelSize: Style.font.body
                selectByMouse: true
                clip: true
                activeFocusOnTab: true
                text: modalRoot.cipherName
                onTextChanged: modalRoot.cipherName = text
                Keys.onReturnPressed: modalRoot.submit()
              }
            }
          }

          // Folder
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            Text {
              text: "Folder"
              color: modalRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }

            Item {
              Layout.fillWidth: true
              Layout.preferredHeight: 32

              Rectangle {
                anchors.fill: parent
                radius: 4
                color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                border.color: folderMouse.containsMouse ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  spacing: 6

                  Text {
                    text: "\uf07b"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    color: modalRoot.muted
                  }

                  Text {
                    text: modalRoot.folderLabel()
                    color: modalRoot.foreground
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                  }

                  Text {
                    text: "\uf0d7"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: Style.font.caption
                    color: modalRoot.muted
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
                implicitHeight: Math.min(260, (modalRoot.folderOptions().length * 30) + 12)
                padding: 6
                modal: true
                focus: true
                closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

                background: Rectangle {
                  color: modalRoot.cardBackground
                  border.color: modalRoot.borderColor
                  border.width: 1
                  radius: 6
                }

                contentItem: ListView {
                  id: folderList
                  focus: true
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  model: modalRoot.folderOptions()
                  spacing: 2

                  delegate: Rectangle {
                    required property int index
                    required property var modelData
                    width: folderList.width
                    implicitHeight: 28
                    radius: 4
                    property bool isSelected: (modelData.id === "__none__" && modalRoot.folderId === "") ||
                                              modelData.id === modalRoot.folderId
                    color: isSelected ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.2) : (optionMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08) : "transparent")

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: 8
                      anchors.rightMargin: 8
                      spacing: 6

                      Text {
                        text: modelData.icon || "\uf07b"
                        font.family: modalRoot.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        color: isSelected ? modalRoot.accent : modalRoot.muted
                      }

                      Text {
                        text: modelData.name || ""
                        color: isSelected ? modalRoot.accent : modalRoot.foreground
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
                        modalRoot.folderId = modelData.id === "__none__" ? "" : modelData.id
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
            visible: modalRoot.isLogin
            Layout.fillWidth: true
            spacing: 12

            // Username
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Username"
                color: modalRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 32
                radius: 4
                color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                border.color: usernameInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: usernameInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: Style.font.body
                  selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  text: modalRoot.username
                  onTextChanged: modalRoot.username = text
                  Keys.onReturnPressed: modalRoot.submit()
                }
              }
            }

            // Password
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Password"
                color: modalRoot.muted
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
                  color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                  border.color: passwordInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                  border.width: 1

                  TextInput {
                    id: passwordInput
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    verticalAlignment: Text.AlignVCenter
                    color: modalRoot.foreground
                    font.pixelSize: Style.font.body
                    selectByMouse: true
                    clip: true
                    activeFocusOnTab: true
                    echoMode: modalRoot.passwordRevealed ? TextInput.Normal : TextInput.Password
                    text: modalRoot.password
                    onTextChanged: modalRoot.password = text
                    Keys.onReturnPressed: modalRoot.submit()
                  }
                }

                // Reveal toggle
                Rectangle {
                  Layout.preferredWidth: 32
                  Layout.preferredHeight: 32
                  radius: 4
                  color: revealMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.15) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.05)
                  border.color: modalRoot.borderColor
                  border.width: 1

                  Text {
                    anchors.centerIn: parent
                    text: modalRoot.passwordRevealed ? "\uf070" : "\uf06e"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    color: modalRoot.accent
                  }

                  MouseArea {
                    id: revealMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: modalRoot.passwordRevealed = !modalRoot.passwordRevealed
                  }
                }

                // Inline Generate
                Rectangle {
                  Layout.preferredHeight: 32
                  Layout.preferredWidth: generateRow.implicitWidth + 18
                  radius: 4
                  opacity: modalRoot.isEngineOutdated ? 0.4 : 1.0
                  color: generateMouse.containsMouse ? Qt.lighter(modalRoot.accent, 1.12) : modalRoot.accent

                  RowLayout {
                    id: generateRow
                    anchors.centerIn: parent
                    spacing: 5

                    Text {
                      text: modalRoot.isGeneratingPassword ? "\uf110" : "\uf021"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.textOnAccent
                    }

                    Text {
                      text: "Generate"
                      font.pixelSize: Style.font.caption
                      font.weight: Font.DemiBold
                      color: modalRoot.textOnAccent
                    }
                  }

                  MouseArea {
                    id: generateMouse
                    anchors.fill: parent
                    enabled: !modalRoot.isEngineOutdated && !modalRoot.isGeneratingPassword
                    hoverEnabled: true
                    cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                    onClicked: modalRoot.requestGeneratePassword()
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
                  color: modalRoot.muted
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.Medium
                }

                Item { Layout.fillWidth: true }

                Rectangle {
                  implicitHeight: 24
                  implicitWidth: addUriRow.implicitWidth + 12
                  radius: 4
                  color: addUriMouse.containsMouse ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.18) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06)
                  border.color: modalRoot.borderColor
                  border.width: 1

                  RowLayout {
                    id: addUriRow
                    anchors.centerIn: parent
                    spacing: 4

                    Text {
                      text: "\uf067"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.accent
                    }

                    Text {
                      text: "Add URI"
                      font.pixelSize: Style.font.caption
                      color: modalRoot.accent
                    }
                  }

                  MouseArea {
                    id: addUriMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: modalRoot.addUri()
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
                    color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                    border.color: uriInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                    border.width: 1

                    TextInput {
                      id: uriInput
                      anchors.fill: parent
                      anchors.leftMargin: 8
                      anchors.rightMargin: 8
                      verticalAlignment: Text.AlignVCenter
                      color: modalRoot.foreground
                      font.pixelSize: Style.font.bodySmall
                      selectByMouse: true
                      clip: true
                      activeFocusOnTab: true
                      text: uri
                      onTextChanged: {
                        if (uri !== text) uriModel.setProperty(index, "uri", text)
                      }
                      Keys.onReturnPressed: modalRoot.submit()
                    }
                  }

                  Rectangle {
                    Layout.preferredWidth: 26
                    Layout.preferredHeight: 30
                    radius: 4
                    color: removeUriMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.15) : "transparent"
                    border.color: modalRoot.borderColor
                    border.width: 1

                    Text {
                      anchors.centerIn: parent
                      text: "\uf00d"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.muted
                    }

                    MouseArea {
                      id: removeUriMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: modalRoot.removeUri(index)
                    }
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
              text: modalRoot.isLogin ? "Notes (optional)" : "Note"
              color: modalRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }

            Rectangle {
              Layout.fillWidth: true
              height: 84
              radius: 4
              color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
              border.color: notesInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
              border.width: 1

              Flickable {
                anchors.fill: parent
                anchors.margins: 6
                clip: true

                TextArea.flickable: TextArea {
                  id: notesInput
                  color: modalRoot.foreground
                  background: null
                  padding: 0
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WrapAnywhere
                  selectByMouse: true
                  activeFocusOnTab: true
                  text: modalRoot.notes
                  onTextChanged: modalRoot.notes = text
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
                color: modalRoot.muted
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
                  objectName: "addFieldButton_" + modelData.type
                  implicitHeight: 24
                  implicitWidth: addFieldRow.implicitWidth + 12
                  radius: 4
                  color: addFieldMouse.containsMouse ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.18) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06)
                  border.color: modalRoot.borderColor
                  border.width: 1

                  RowLayout {
                    id: addFieldRow
                    objectName: "addFieldRow_" + modelData.type
                    anchors.centerIn: parent
                    spacing: 4

                    Text {
                      text: "\uf067"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.accent
                    }

                    Text {
                      id: addFieldText
                      text: modelData.label
                      font.pixelSize: Style.font.caption
                      color: modalRoot.accent
                    }
                  }

                  MouseArea {
                    id: addFieldMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: modalRoot.addCustomField(modelData.type)
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
                      color: StatusPalette.labelOnTint(StatusPalette.info, 0.15, modalRoot.cardBackground)
                      font.pixelSize: Style.font.caption
                    }
                  }

                  // Field name
                  Rectangle {
                    Layout.fillWidth: true
                    height: 30
                    radius: 4
                    color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                    border.color: fieldNameInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                    border.width: 1

                    TextInput {
                      id: fieldNameInput
                      anchors.fill: parent
                      anchors.leftMargin: 8
                      anchors.rightMargin: 8
                      verticalAlignment: Text.AlignVCenter
                      color: modalRoot.foreground
                      font.pixelSize: Style.font.bodySmall
                      selectByMouse: true
                      clip: true
                      activeFocusOnTab: true
                      text: name
                      onTextChanged: {
                        if (name !== text) fieldModel.setProperty(index, "name", text)
                      }
                    }
                  }

                  // Remove
                  Rectangle {
                    Layout.preferredWidth: 26
                    Layout.preferredHeight: 30
                    radius: 4
                    color: removeFieldMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.15) : "transparent"
                    border.color: modalRoot.borderColor
                    border.width: 1

                    Text {
                      anchors.centerIn: parent
                      text: "\uf00d"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.muted
                    }

                    MouseArea {
                      id: removeFieldMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: modalRoot.removeCustomField(index)
                    }
                  }
                }

                // Boolean toggle
                Rectangle {
                  visible: type === 2
                  Layout.fillWidth: true
                  height: 28
                  radius: 4
                  color: value === "true" ? StatusPalette.tint(StatusPalette.success, 0.2) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06)
                  border.color: value === "true" ? StatusPalette.success : modalRoot.borderColor
                  border.width: 1

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    spacing: 6

                    Text {
                      text: value === "true" ? "\uf00c" : "\uf00d"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: value === "true" ? StatusPalette.labelOnTint(StatusPalette.success, 0.2, modalRoot.cardBackground) : modalRoot.muted
                    }

                    Text {
                      text: value === "true" ? "true" : "false"
                      color: value === "true" ? StatusPalette.labelOnTint(StatusPalette.success, 0.2, modalRoot.cardBackground) : modalRoot.foreground
                      font.pixelSize: Style.font.bodySmall
                      font.weight: Font.Medium
                    }
                  }

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: modalRoot.toggleFieldBoolean(index)
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
                    color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
                    border.color: fieldValueInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                    border.width: 1

                    TextInput {
                      id: fieldValueInput
                      anchors.fill: parent
                      anchors.leftMargin: 8
                      anchors.rightMargin: 8
                      verticalAlignment: Text.AlignVCenter
                      color: modalRoot.foreground
                      font.pixelSize: Style.font.bodySmall
                      selectByMouse: true
                      clip: true
                      activeFocusOnTab: true
                      echoMode: (type === 1 && !revealed) ? TextInput.Password : TextInput.Normal
                      text: value
                      onTextChanged: {
                        if (value !== text) fieldModel.setProperty(index, "value", text)
                      }
                    }
                  }

                  // Per-field reveal for Hidden fields
                  Rectangle {
                    visible: type === 1
                    Layout.preferredWidth: 30
                    Layout.preferredHeight: 30
                    radius: 4
                    color: fieldRevealMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.15) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.05)
                    border.color: modalRoot.borderColor
                    border.width: 1

                    Text {
                      anchors.centerIn: parent
                      text: revealed ? "\uf070" : "\uf06e"
                      font.family: modalRoot.fontFamily
                      font.pixelSize: Style.font.caption
                      color: modalRoot.accent
                    }

                    MouseArea {
                      id: fieldRevealMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: modalRoot.toggleFieldRevealed(index)
                    }
                  }
                }
              }
            }

            // Linked (Type 3) fields are read-only: they reference other item
            // properties and must never be rewritten by the edit diff.
            Repeater {
              model: modalRoot.linkedFields

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
                      color: StatusPalette.labelOnTint(StatusPalette.trace, 0.15, modalRoot.cardBackground)
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Text {
                    text: modelData.name || "Field"
                    color: modalRoot.muted
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                  }

                  Text {
                    text: "read-only"
                    color: modalRoot.muted
                    font.pixelSize: Style.font.caption
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: 30
                  radius: 4
                  color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.04)
                  border.color: modalRoot.borderColor
                  border.width: 1

                  Text {
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    verticalAlignment: Text.AlignVCenter
                    text: modelData.value || ""
                    color: modalRoot.muted
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }
                }
              }
            }
          }
        }
      }

      // Footer
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Item { Layout.fillWidth: true }

        Rectangle {
          implicitHeight: 30
          implicitWidth: 76
          radius: 4
          color: cancelMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08) : "transparent"
          border.color: modalRoot.borderColor
          border.width: 1

          Text {
            anchors.centerIn: parent
            text: "Cancel"
            color: cancelMouse.containsMouse ? modalRoot.foreground : modalRoot.muted
            font.pixelSize: Style.font.bodySmall
          }

          MouseArea {
            id: cancelMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (!modalRoot.isBusy) modalRoot.closeRequested()
            }
          }
        }

        Rectangle {
          implicitHeight: 30
          implicitWidth: 100
          radius: 4
          color: submitMouse.containsMouse ? Qt.lighter(modalRoot.accent, 1.1) : modalRoot.accent
          opacity: modalRoot.isBusy ? 0.6 : 1.0

          RowLayout {
            anchors.centerIn: parent
            spacing: 6

            Text {
              visible: modalRoot.isBusy
              text: "\uf110"
              font.family: modalRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
              color: modalRoot.textOnAccent
            }

            Text {
              text: modalRoot.isBusy ? (modalRoot.isEdit ? "Saving..." : "Creating...") : (modalRoot.isEdit ? "Save Changes" : "Create")
              color: modalRoot.textOnAccent
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.DemiBold
            }
          }

          MouseArea {
            id: submitMouse
            anchors.fill: parent
            enabled: !modalRoot.isBusy
            hoverEnabled: true
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.submit()
          }
        }
      }
    }
  }
}
