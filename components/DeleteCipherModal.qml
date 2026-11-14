import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Confirmation for deleting a personal Login or Secure Note cipher.
// `permanent` starts false (soft delete to Trash); toggling it switches the
// warning banner and confirm action to irreversible danger styling.
Rectangle {
  id: modalRoot

  property bool active: false
  property string itemName: ""
  property bool isBusy: false
  property string errorMessage: ""

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  // Soft delete (move to Trash) by default.
  property bool permanent: false

  readonly property color warningRole: permanent ? StatusPalette.danger : StatusPalette.warn
  readonly property color confirmRole: permanent ? StatusPalette.danger : StatusPalette.warn
  readonly property color textOnConfirm: StatusPalette.textOn(confirmRole)
  readonly property string title: "Delete Item"
  readonly property string headline: permanent
    ? ("Permanently delete \"" + (itemName || "Untitled") + "\"?")
    : ("Move \"" + (itemName || "Untitled") + "\" to Trash?")
  readonly property string warningMessage: permanent
    ? "This action cannot be undone. The cipher will be permanently destroyed."
    : "The cipher will be moved to Trash and can be restored later."
  readonly property string confirmLabel: permanent ? "Delete Permanently" : "Move to Trash"

  signal confirmRequested(bool permanent)
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 125

  function togglePermanent() {
    if (isBusy) return
    permanent = !permanent
  }

  function confirm() {
    if (isBusy) return
    confirmRequested(permanent)
  }

  function requestClose() {
    if (isBusy) return
    closeRequested()
  }

  onActiveChanged: {
    if (active) {
      permanent = false
      errorMessage = ""
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: modalRoot.requestClose()
  }

  // Modal Dialog Card
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

      // Headline
      Text {
        Layout.fillWidth: true
        text: modalRoot.headline
        color: modalRoot.foreground
        font.pixelSize: Style.font.body
        font.weight: Font.Medium
        wrapMode: Text.Wrap
      }

      // Irreversibility / recoverability warning banner
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
            text: modalRoot.permanent ? "\uf071" : "\uf1f8"
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

      // Permanent toggle
      Rectangle {
        Layout.fillWidth: true
        implicitHeight: 34
        radius: 5
        color: toggleMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06) : "transparent"
        border.color: modalRoot.borderColor
        border.width: 1

        RowLayout {
          anchors.fill: parent
          anchors.leftMargin: 8
          anchors.rightMargin: 8
          spacing: 8

          Text {
            Layout.fillWidth: true
            text: "Delete permanently (skip Trash)"
            color: modalRoot.foreground
            font.pixelSize: Style.font.bodySmall
          }

          // Switch track
          Rectangle {
            id: toggleTrack
            implicitWidth: 34
            implicitHeight: 18
            radius: 9
            color: modalRoot.permanent ? modalRoot.confirmRole : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.2)
            border.color: modalRoot.permanent ? modalRoot.confirmRole : modalRoot.borderColor
            border.width: 1

            Rectangle {
              id: toggleKnob
              width: 14
              height: 14
              radius: 7
              y: 2
              x: modalRoot.permanent ? (toggleTrack.width - width - 2) : 2
              color: modalRoot.permanent ? modalRoot.textOnConfirm : modalRoot.cardBackground

              Behavior on x {
                NumberAnimation { duration: 120; easing.type: Easing.OutQuad }
              }
            }
          }
        }

        MouseArea {
          id: toggleMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: modalRoot.isBusy ? Qt.ArrowCursor : Qt.PointingHandCursor
          onClicked: modalRoot.togglePermanent()
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
            onClicked: modalRoot.requestClose()
          }
        }

        Rectangle {
          implicitHeight: 30
          implicitWidth: Math.max(100, confirmText.implicitWidth + 24)
          radius: 4
          color: confirmMouse.containsMouse ? Qt.lighter(modalRoot.confirmRole, 1.1) : modalRoot.confirmRole
          opacity: modalRoot.isBusy ? 0.6 : 1.0

          RowLayout {
            anchors.centerIn: parent
            spacing: 6

            Text {
              visible: modalRoot.isBusy
              text: "\uf110"
              font.family: modalRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
              color: modalRoot.textOnConfirm
            }

            Text {
              id: confirmText
              text: modalRoot.isBusy ? "Deleting..." : modalRoot.confirmLabel
              color: modalRoot.textOnConfirm
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.DemiBold
            }
          }

          MouseArea {
            id: confirmMouse
            anchors.fill: parent
            enabled: !modalRoot.isBusy
            hoverEnabled: true
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.confirm()
          }
        }
      }
    }
  }
}
