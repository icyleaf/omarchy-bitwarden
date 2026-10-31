import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Confirmation for an SSH agent signature request. The daemon summons the
// overlay with an `ssh-approval` payload; the prompt fields come from
// `omawarden ssh-agent pending`.
Rectangle {
  id: approvalRoot

  property bool active: false
  property var prompt: null
  property int remaining: 0
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""
  // The card opens by itself, possibly mid-typing: hold off Allow briefly so
  // an Enter meant for another window can't approve.
  property bool armed: false

  readonly property color mutedForeground: approvalRoot.muted
  readonly property color dangerColor: "#f87171"
  readonly property color textOnAccent: StatusPalette.textOn(accent)

  signal replyRequested(bool approve)

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.65)
  visible: active && prompt !== null
  z: 120

  Keys.onPressed: function(event) {
    if (event.key === Qt.Key_Escape) {
      approvalRoot.replyRequested(false)
      event.accepted = true
    } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
      approvalRoot.allow()
      event.accepted = true
    }
  }

  // Id of the prompt on screen, so polling refreshes of it don't re-arm.
  property var shownId: null

  function allow() {
    if (armed) replyRequested(true)
  }

  function present() {
    approvalRoot.forceActiveFocus()
    if (prompt.id === shownId) return
    shownId = prompt.id
    armed = false
    armTimer.restart()
  }

  onVisibleChanged: visible ? approvalRoot.present() : (shownId = null)
  onPromptChanged: if (visible) approvalRoot.present()

  Timer {
    id: armTimer
    interval: 600
    onTriggered: approvalRoot.armed = true
  }

  // Clicking outside denies, like Esc: a stray click must never approve.
  MouseArea {
    anchors.fill: parent
    onClicked: approvalRoot.replyRequested(false)
  }

  Rectangle {
    id: card
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 520)
    implicitHeight: content.implicitHeight + 32
    height: implicitHeight
    radius: 8
    color: approvalRoot.cardBackground
    border.color: approvalRoot.prompt && approvalRoot.prompt.forwarded ? approvalRoot.dangerColor : approvalRoot.borderColor
    border.width: 1

    MouseArea { anchors.fill: parent }

    ColumnLayout {
      id: content
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: 16
      spacing: 12

      // Header: key icon, question, countdown
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: ""
          font.family: approvalRoot.fontFamily
          font.pixelSize: Style.font.title
          color: approvalRoot.accent
        }

        Text {
          text: approvalRoot.prompt ? approvalRoot.prompt.title : ""
          textFormat: Text.PlainText
          color: approvalRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.DemiBold
          elide: Text.ElideRight
          Layout.fillWidth: true
          Layout.preferredWidth: 0
        }

        Text {
          visible: approvalRoot.remaining > 0
          text: approvalRoot.remaining + "s"
          color: approvalRoot.remaining <= 10 ? approvalRoot.dangerColor : approvalRoot.mutedForeground
          font.pixelSize: Style.font.caption
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: approvalRoot.borderColor
      }

      // Forwarded requests come from a remote host: say so loudly.
      Rectangle {
        visible: approvalRoot.prompt !== null && approvalRoot.prompt.forwarded === true
        Layout.fillWidth: true
        implicitHeight: forwardedText.implicitHeight + 12
        radius: 4
        color: Qt.rgba(0.97, 0.44, 0.44, 0.12)
        border.color: Qt.rgba(0.97, 0.44, 0.44, 0.4)
        border.width: 1

        Text {
          id: forwardedText
          anchors.fill: parent
          anchors.margins: 6
          text: "  Forwarded from a remote host. Only allow this if you just ran something there that needs your key."
          font.family: approvalRoot.fontFamily
          color: approvalRoot.dangerColor
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }
      }

      // What is being signed
      Text {
        Layout.fillWidth: true
        text: approvalRoot.prompt ? approvalRoot.prompt.action : ""
        textFormat: Text.PlainText
        color: approvalRoot.foreground
        font.pixelSize: Style.font.body
        font.weight: Font.Medium
        wrapMode: Text.WordWrap
      }

      // Key and requesting program
      GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: 12
        rowSpacing: 4

        Text { text: "Key"; color: approvalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: approvalRoot.prompt ? approvalRoot.prompt.key_name : ""
          textFormat: Text.PlainText
          color: approvalRoot.foreground
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        Text { text: "Fingerprint"; color: approvalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: approvalRoot.prompt ? approvalRoot.prompt.fingerprint : ""
          textFormat: Text.PlainText
          color: approvalRoot.mutedForeground
          font.pixelSize: Style.font.caption
          font.family: "monospace"
          elide: Text.ElideMiddle
        }

        Text { text: "Requested by"; color: approvalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: approvalRoot.prompt ? approvalRoot.prompt.client : ""
          textFormat: Text.PlainText
          color: approvalRoot.foreground
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        Text { text: "Command"; color: approvalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: approvalRoot.prompt ? approvalRoot.prompt.command : ""
          textFormat: Text.PlainText
          color: approvalRoot.mutedForeground
          font.pixelSize: Style.font.caption
          font.family: "monospace"
          elide: Text.ElideRight
        }
      }

      // Actions
      RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: 4
        spacing: 8

        Text {
          text: approvalRoot.prompt && approvalRoot.prompt.remembered
                ? "Enter allow · Esc deny · remembered for this program and app until you log out"
                : "Enter allow · Esc deny"
          color: approvalRoot.muted
          font.pixelSize: Style.font.caption
          Layout.fillWidth: true
          elide: Text.ElideRight
        }

        Rectangle {
          implicitHeight: 28
          implicitWidth: 70
          radius: 4
          color: denyMouse.containsMouse ? Qt.rgba(approvalRoot.foreground.r, approvalRoot.foreground.g, approvalRoot.foreground.b, 0.08) : "transparent"
          border.color: approvalRoot.borderColor
          border.width: 1
          Text {
            anchors.centerIn: parent
            text: "Deny"
            color: denyMouse.containsMouse ? approvalRoot.foreground : approvalRoot.muted
            font.pixelSize: Style.font.bodySmall
          }
          MouseArea {
            id: denyMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: approvalRoot.replyRequested(false)
          }
        }

        Rectangle {
          implicitHeight: 28
          implicitWidth: 80
          radius: 4
          opacity: approvalRoot.armed ? 1 : 0.4
          color: allowMouse.containsMouse ? Qt.lighter(approvalRoot.accent, 1.1) : approvalRoot.accent
          Text {
            anchors.centerIn: parent
            text: "Allow"
            color: approvalRoot.textOnAccent
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.DemiBold
          }
          MouseArea {
            id: allowMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: approvalRoot.allow()
          }
        }
      }
    }
  }
}
