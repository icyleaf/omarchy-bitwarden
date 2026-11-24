import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Lightweight Folder CRUD modal launched from the Folder ScopeDropdown footer
// and Action Palette (Ctrl+K). Follows ADR-0026 Theme Tokens and modal focus rules.
Rectangle {
  id: modalRoot

  property bool active: false
  property var folders: [] // [{ id: string, name: string, count: int }]
  property bool isBusy: false
  property string errorMessage: ""

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  property string newFolderName: ""
  property string editingFolderId: ""
  property string editingFolderName: ""
  property string deletingFolderId: ""
  property string deletingFolderName: ""
  property int deletingFolderCount: 0

  readonly property color textOnAccent: StatusPalette.textOn(accent)
  readonly property color textOnDanger: StatusPalette.textOn(StatusPalette.danger)
  readonly property string deleteConfirmationCopy: {
    if (!deletingFolderId) return ""
    var label = deletingFolderName || "Untitled"
    var impact = deletingFolderCount === 0
      ? "empty folder"
      : (deletingFolderCount === 1
          ? "1 cipher will be moved to No Folder"
          : (deletingFolderCount + " ciphers will be moved to No Folder"))
    return "Delete \"" + label + "\" (" + impact + ")?"
  }

  signal createRequested(string name)
  signal renameRequested(string folderId, string newName)
  signal deleteRequested(string folderId)
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 126

  function resetTransientState() {
    errorMessage = ""
    newFolderName = ""
    editingFolderId = ""
    editingFolderName = ""
    deletingFolderId = ""
    deletingFolderName = ""
    deletingFolderCount = 0
  }

  function submitCreate() {
    if (isBusy) return
    var trimmed = String(newFolderName || "").trim()
    if (!trimmed) {
      errorMessage = "Folder name cannot be empty."
      return
    }
    errorMessage = ""
    createRequested(trimmed)
  }

  function startRename(folderId, currentName) {
    if (isBusy) return
    deletingFolderId = ""
    errorMessage = ""
    editingFolderId = String(folderId || "")
    editingFolderName = String(currentName || "")
  }

  function cancelRename() {
    editingFolderId = ""
    editingFolderName = ""
    errorMessage = ""
  }

  function submitRename() {
    if (isBusy || !editingFolderId) return
    var trimmed = String(editingFolderName || "").trim()
    if (!trimmed) {
      errorMessage = "Folder name cannot be empty."
      return
    }
    errorMessage = ""
    renameRequested(editingFolderId, trimmed)
  }

  function requestDelete(folderId, folderName, count) {
    if (isBusy) return
    editingFolderId = ""
    errorMessage = ""
    deletingFolderId = String(folderId || "")
    deletingFolderName = String(folderName || "")
    deletingFolderCount = Number(count || 0)
  }

  function cancelDelete() {
    deletingFolderId = ""
    deletingFolderName = ""
    deletingFolderCount = 0
  }

  function confirmDelete() {
    if (isBusy || !deletingFolderId) return
    errorMessage = ""
    deleteRequested(deletingFolderId)
  }

  function requestClose() {
    if (isBusy) return
    closeRequested()
  }

  onActiveChanged: {
    if (active) {
      resetTransientState()
      Qt.callLater(function() {
        if (createInput) createInput.forceActiveFocus()
      })
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: modalRoot.requestClose()
  }

  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 480)
    height: Math.min(parent.height - 64, contentColumn.implicitHeight + 36)
    radius: 10
    color: modalRoot.cardBackground
    border.color: modalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      id: contentColumn
      anchors.fill: parent
      anchors.margins: 18
      spacing: 12

      // Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: "\uf07b"
          font.family: modalRoot.fontFamily
          font.pixelSize: Style.font.subtitle
          color: modalRoot.accent
        }

        Text {
          text: "Manage Folders"
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
            color: StatusPalette.textOnTint(StatusPalette.error, 0.15, modalRoot.cardBackground)
            font.pixelSize: Style.font.bodySmall
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }
      }

      // Create new folder row
      RowLayout {
        Layout.fillWidth: true
        spacing: 6

        Rectangle {
          Layout.fillWidth: true
          height: 32
          radius: 4
          color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08)
          border.color: createInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
          border.width: 1

          TextInput {
            id: createInput
            anchors.fill: parent
            anchors.leftMargin: 8
            anchors.rightMargin: 8
            verticalAlignment: Text.AlignVCenter
            color: modalRoot.foreground
            font.pixelSize: Style.font.body
            selectByMouse: true
            clip: true
            enabled: !modalRoot.isBusy
            text: modalRoot.newFolderName
            onTextChanged: modalRoot.newFolderName = text
            Keys.onReturnPressed: modalRoot.submitCreate()
            Keys.onEnterPressed: modalRoot.submitCreate()

            Text {
              anchors.fill: parent
              verticalAlignment: Text.AlignVCenter
              text: "New folder name (e.g. Work/Prod)…"
              color: modalRoot.muted
              font.pixelSize: Style.font.body
              visible: !createInput.text
            }
          }
        }

        Rectangle {
          Layout.preferredHeight: 32
          Layout.preferredWidth: createBtnText.implicitWidth + 20
          radius: 4
          opacity: modalRoot.isBusy ? 0.5 : 1.0
          color: createBtnMouse.containsMouse ? Qt.lighter(modalRoot.accent, 1.12) : modalRoot.accent

          Text {
            id: createBtnText
            anchors.centerIn: parent
            text: "Create"
            color: modalRoot.textOnAccent
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.DemiBold
          }

          MouseArea {
            id: createBtnMouse
            anchors.fill: parent
            enabled: !modalRoot.isBusy
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: modalRoot.submitCreate()
          }
        }
      }

      // Inline delete confirmation banner
      Rectangle {
        visible: Boolean(modalRoot.deletingFolderId)
        Layout.fillWidth: true
        implicitHeight: delConfirmCol.implicitHeight + 16
        radius: 6
        color: StatusPalette.tint(StatusPalette.danger, 0.12)
        border.color: StatusPalette.danger
        border.width: 1

        ColumnLayout {
          id: delConfirmCol
          anchors.fill: parent
          anchors.margins: 8
          spacing: 8

          Text {
            Layout.fillWidth: true
            text: modalRoot.deleteConfirmationCopy
            color: modalRoot.foreground
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.Wrap
          }

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Item { Layout.fillWidth: true }

            Rectangle {
              implicitHeight: 26
              implicitWidth: cancelDelText.implicitWidth + 16
              radius: 4
              color: cancelDelMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.14) : "transparent"
              border.color: modalRoot.borderColor
              border.width: 1

              Text {
                id: cancelDelText
                anchors.centerIn: parent
                text: "Cancel"
                color: modalRoot.foreground
                font.pixelSize: Style.font.caption
              }

              MouseArea {
                id: cancelDelMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.cancelDelete()
              }
            }

            Rectangle {
              implicitHeight: 26
              implicitWidth: confirmDelText.implicitWidth + 16
              radius: 4
              color: confirmDelMouse.containsMouse ? Qt.lighter(StatusPalette.danger, 1.1) : StatusPalette.danger

              Text {
                id: confirmDelText
                anchors.centerIn: parent
                text: "Delete Folder"
                color: modalRoot.textOnDanger
                font.pixelSize: Style.font.caption
                font.weight: Font.DemiBold
              }

              MouseArea {
                id: confirmDelMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.confirmDelete()
              }
            }
          }
        }
      }

      // Folder list
      ListView {
        id: folderListView
        Layout.fillWidth: true
        Layout.preferredHeight: Math.min(240, Math.max(44, (modalRoot.folders ? modalRoot.folders.length : 0) * 38))
        clip: true
        spacing: 4
        model: modalRoot.folders || []

        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        delegate: Rectangle {
          required property var modelData
          width: folderListView.width
          height: 34
          radius: 4
          property bool isEditing: modalRoot.editingFolderId === modelData.id
          color: Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, isEditing ? 0.10 : 0.04)
          border.color: isEditing ? modalRoot.accent : modalRoot.borderColor
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
              color: modalRoot.accent
            }

            // Static display
            Text {
              visible: !isEditing
              Layout.fillWidth: true
              text: modelData.name || ""
              color: modalRoot.foreground
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
            }

            Text {
              visible: !isEditing
              text: String(modelData.count || 0)
              color: modalRoot.muted
              font.pixelSize: Style.font.caption
            }

            // Inline rename input
            TextInput {
              id: renameInput
              visible: isEditing
              Layout.fillWidth: true
              verticalAlignment: Text.AlignVCenter
              color: modalRoot.foreground
              font.pixelSize: Style.font.bodySmall
              selectByMouse: true
              clip: true
              text: isEditing ? modalRoot.editingFolderName : ""
              onTextChanged: {
                if (isEditing && modalRoot.editingFolderName !== text) {
                  modalRoot.editingFolderName = text
                }
              }
              Keys.onReturnPressed: modalRoot.submitRename()
              Keys.onEnterPressed: modalRoot.submitRename()
              Keys.onEscapePressed: modalRoot.cancelRename()
            }

            // Action buttons (normal mode)
            Rectangle {
              visible: !isEditing
              Layout.preferredWidth: 24
              Layout.preferredHeight: 24
              radius: 4
              color: renameIconMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.14) : "transparent"

              Text {
                anchors.centerIn: parent
                text: "\uf044"
                font.family: modalRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: modalRoot.muted
              }

              MouseArea {
                id: renameIconMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.startRename(modelData.id, modelData.name)
              }
            }

            Rectangle {
              visible: !isEditing
              Layout.preferredWidth: 24
              Layout.preferredHeight: 24
              radius: 4
              color: deleteIconMouse.containsMouse ? StatusPalette.tint(StatusPalette.danger, 0.18) : "transparent"

              Text {
                anchors.centerIn: parent
                text: "\uf1f8"
                font.family: modalRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: deleteIconMouse.containsMouse ? StatusPalette.danger : modalRoot.muted
              }

              MouseArea {
                id: deleteIconMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.requestDelete(modelData.id, modelData.name, modelData.count || 0)
              }
            }

            // Action buttons (rename mode)
            Rectangle {
              visible: isEditing
              Layout.preferredWidth: 24
              Layout.preferredHeight: 24
              radius: 4
              color: saveRenameMouse.containsMouse ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.25) : "transparent"

              Text {
                anchors.centerIn: parent
                text: "\uf00c"
                font.family: modalRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: modalRoot.accent
              }

              MouseArea {
                id: saveRenameMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.submitRename()
              }
            }

            Rectangle {
              visible: isEditing
              Layout.preferredWidth: 24
              Layout.preferredHeight: 24
              radius: 4
              color: cancelRenameMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.14) : "transparent"

              Text {
                anchors.centerIn: parent
                text: "\uf00d"
                font.family: modalRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: modalRoot.muted
              }

              MouseArea {
                id: cancelRenameMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: modalRoot.cancelRename()
              }
            }
          }
        }
      }

      Text {
        visible: !modalRoot.folders || modalRoot.folders.length === 0
        Layout.fillWidth: true
        text: "No folders yet. Create one above."
        color: modalRoot.muted
        font.pixelSize: Style.font.bodySmall
        horizontalAlignment: Text.AlignHCenter
      }

      // Footer
      RowLayout {
        Layout.fillWidth: true
        Item { Layout.fillWidth: true }

        Rectangle {
          implicitHeight: 30
          implicitWidth: closeBtnText.implicitWidth + 24
          radius: 4
          color: closeBtnMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.14) : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06)
          border.color: modalRoot.borderColor
          border.width: 1

          Text {
            id: closeBtnText
            anchors.centerIn: parent
            text: "Close"
            color: modalRoot.foreground
            font.pixelSize: Style.font.bodySmall
          }

          MouseArea {
            id: closeBtnMouse
            anchors.fill: parent
            enabled: !modalRoot.isBusy
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: modalRoot.requestClose()
          }
        }
      }
    }
  }
}
