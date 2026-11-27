import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Confirmation dialog for permanently deleting an Attachment from a Cipher.
Rectangle {
  id: modalRoot

  property bool active: false
  property string itemName: ""
  property string attachmentName: ""
  property string attachmentSize: ""
  property bool isBusy: false
  property string errorMessage: ""

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  readonly property color warningRole: StatusPalette.danger
  readonly property color confirmRole: StatusPalette.danger
  readonly property color textOnConfirm: StatusPalette.textOnTint(confirmRole, 1.0, cardBackground)
  readonly property string title: "Delete Attachment"
  readonly property string headline: "Delete \"" + (attachmentName || "attachment") + "\" from \"" + (itemName || "Untitled") + "\"?"
  readonly property string warningMessage: "This action cannot be undone. The attachment will be permanently deleted from the server and any local preview will be purged."
  readonly property string confirmLabel: isBusy ? "Deleting..." : "Delete Attachment"

  signal confirmRequested()
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 125

  function confirm() {
    if (isBusy) return
    confirmRequested()
  }

  function requestClose() {
    if (isBusy) return
    closeRequested()
  }

  onActiveChanged: {
    if (active) {
      errorMessage = ""
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: modalRoot.requestClose()
  }

  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 460)
    height: contentColumn.implicitHeight + 36
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
          text: "\uf1f8"
          font.family: modalRoot.fontFamily
          font.pixelSize: Style.font.subtitle
          color: modalRoot.warningRole
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
        objectName: "deleteAttachmentErrorBanner"
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
            color: StatusPalette.labelOnTint(StatusPalette.error, 0.15, modalRoot.cardBackground)
            font.pixelSize: Style.font.bodySmall
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }
      }

      // Headline
      Text {
        Layout.fillWidth: true
        text: modalRoot.headline
        color: modalRoot.foreground
        font.pixelSize: Style.font.body
        font.weight: Font.Medium
        wrapMode: Text.Wrap
      }

      // Size metadata when available
      Text {
        visible: Boolean(modalRoot.attachmentSize)
        Layout.fillWidth: true
        text: "File size: " + modalRoot.attachmentSize
        color: modalRoot.muted
        font.pixelSize: Style.font.caption
      }

      // Irreversibility warning banner
      Rectangle {
        Layout.fillWidth: true
        implicitHeight: warningRow.implicitHeight + 16
        radius: 5
        color: StatusPalette.tint(modalRoot.warningRole, 0.15)
        border.color: modalRoot.warningRole
        border.width: 1

        RowLayout {
          id: warningRow
          anchors.fill: parent
          anchors.margins: 8
          spacing: 8

          Text {
            text: "\uf071"
            font.family: modalRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: modalRoot.warningRole
          }

          Text {
            Layout.fillWidth: true
            text: modalRoot.warningMessage
            color: StatusPalette.labelOnTint(modalRoot.warningRole, 0.15, modalRoot.cardBackground)
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.Wrap
          }
        }
      }

      // Footer buttons
      RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: 4
        spacing: 8

        Item { Layout.fillWidth: true }

        // Cancel button
        Rectangle {
          objectName: "cancelDeleteAttachmentButton"
          implicitWidth: cancelLabel.implicitWidth + 24
          implicitHeight: 32
          radius: 5
          opacity: modalRoot.isBusy ? 0.5 : 1.0
          color: cancelMouse.containsMouse && !modalRoot.isBusy
            ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.1)
            : "transparent"
          border.color: modalRoot.borderColor
          border.width: 1

          Text {
            id: cancelLabel
            anchors.centerIn: parent
            text: "Cancel"
            color: modalRoot.foreground
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
          }

          MouseArea {
            id: cancelMouse
            anchors.fill: parent
            hoverEnabled: true
            enabled: !modalRoot.isBusy
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.requestClose()
          }
        }

        // Confirm Delete button
        Rectangle {
          objectName: "confirmDeleteAttachmentButton"
          implicitWidth: confirmLabelText.implicitWidth + 24
          implicitHeight: 32
          radius: 5
          opacity: modalRoot.isBusy ? 0.65 : (confirmMouse.containsMouse ? 0.9 : 1.0)
          color: modalRoot.confirmRole

          Text {
            id: confirmLabelText
            anchors.centerIn: parent
            text: modalRoot.confirmLabel
            color: modalRoot.textOnConfirm
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.DemiBold
          }

          MouseArea {
            id: confirmMouse
            anchors.fill: parent
            hoverEnabled: true
            enabled: !modalRoot.isBusy
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.confirm()
          }
        }
      }
    }
  }
}
