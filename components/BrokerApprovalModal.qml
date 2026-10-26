import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons

// Confirmation card for a VaultBroker destination binding request.
// Shown when a command tries to execute with vault secrets without an existing whitelist policy.
Rectangle {
  id: brokerApprovalRoot

  property bool active: false
  property var prompt: null
  property int remaining: 0
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""
  property bool armed: false

  readonly property color mutedForeground: Qt.darker(foreground, 1.5)
  readonly property color dangerColor: "#f87171"

  signal replyRequested(string decision)

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.65)
  visible: active && prompt !== null
  z: 125

  Keys.onPressed: function(event) {
    if (event.key === Qt.Key_Escape) {
      brokerApprovalRoot.replyRequested("deny")
      event.accepted = true
    } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
      brokerApprovalRoot.allowOnce()
      event.accepted = true
    }
  }

  property var shownId: null

  function allowOnce() {
    if (armed) replyRequested("allow_once")
  }

  function allowAlways() {
    if (armed) replyRequested("allow_always")
  }

  function deny() {
    replyRequested("deny")
  }

  function present() {
    brokerApprovalRoot.forceActiveFocus()
    if (prompt && prompt.id === shownId) return
    shownId = prompt ? prompt.id : null
    armed = false
    armTimer.restart()
  }

  onVisibleChanged: visible ? brokerApprovalRoot.present() : (shownId = null)
  onPromptChanged: if (visible) brokerApprovalRoot.present()

  Timer {
    id: armTimer
    interval: 600
    onTriggered: brokerApprovalRoot.armed = true
  }

  // Clicking outside denies execution
  MouseArea {
    anchors.fill: parent
    onClicked: brokerApprovalRoot.deny()
  }

  Rectangle {
    id: card
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 540)
    implicitHeight: content.implicitHeight + 32
    height: implicitHeight
    radius: 8
    color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
    border.color: brokerApprovalRoot.borderColor
    border.width: 1

    MouseArea { anchors.fill: parent }

    ColumnLayout {
      id: content
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: 16
      spacing: 12

      // Header: Shield/Vault icon, title, countdown
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: ""
          font.family: brokerApprovalRoot.fontFamily
          font.pixelSize: Style.font.title
          color: brokerApprovalRoot.accent
        }

        Text {
          text: brokerApprovalRoot.prompt ? brokerApprovalRoot.prompt.title : "Authorize Secret Access"
          textFormat: Text.PlainText
          color: brokerApprovalRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.DemiBold
          elide: Text.ElideRight
          Layout.fillWidth: true
          Layout.preferredWidth: 0
        }

        Text {
          visible: brokerApprovalRoot.remaining > 0
          text: brokerApprovalRoot.remaining + "s"
          color: brokerApprovalRoot.remaining <= 10 ? brokerApprovalRoot.dangerColor : brokerApprovalRoot.mutedForeground
          font.pixelSize: Style.font.caption
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: brokerApprovalRoot.borderColor
      }

      // Security Context Grid
      GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: 12
        rowSpacing: 6

        Text { text: "Vault Secret"; color: brokerApprovalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: brokerApprovalRoot.prompt ? brokerApprovalRoot.prompt.cipher_ref : ""
          textFormat: Text.PlainText
          color: brokerApprovalRoot.foreground
          font.pixelSize: Style.font.bodySmall
          font.weight: Font.Medium
          elide: Text.ElideRight
        }

        Text { text: "Binary Path"; color: brokerApprovalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: brokerApprovalRoot.prompt ? brokerApprovalRoot.prompt.binary_path : ""
          textFormat: Text.PlainText
          color: brokerApprovalRoot.mutedForeground
          font.pixelSize: Style.font.caption
          font.family: "monospace"
          elide: Text.ElideMiddle
        }

        Text { text: "Command"; color: brokerApprovalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: brokerApprovalRoot.prompt ? brokerApprovalRoot.prompt.command : ""
          textFormat: Text.PlainText
          color: brokerApprovalRoot.mutedForeground
          font.pixelSize: Style.font.caption
          font.family: "monospace"
          elide: Text.ElideRight
        }

        Text { text: "Caller App"; color: brokerApprovalRoot.mutedForeground; font.pixelSize: Style.font.caption }
        Text {
          Layout.fillWidth: true
          text: brokerApprovalRoot.prompt ? brokerApprovalRoot.prompt.caller_app : ""
          textFormat: Text.PlainText
          color: brokerApprovalRoot.foreground
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }
      }

      // Action buttons: Deny, Allow Once, Allow Always
      RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: 6
        spacing: 8

        Text {
          text: "Enter allow once · Esc deny"
          color: Qt.darker(brokerApprovalRoot.foreground, 2.0)
          font.pixelSize: Style.font.caption
          Layout.fillWidth: true
          elide: Text.ElideRight
        }

        // Deny button
        Rectangle {
          implicitHeight: 28
          implicitWidth: 64
          radius: 4
          color: denyMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : "transparent"
          border.color: brokerApprovalRoot.borderColor
          border.width: 1
          Text {
            anchors.centerIn: parent
            text: "Deny"
            color: denyMouse.containsMouse ? brokerApprovalRoot.foreground : Qt.darker(brokerApprovalRoot.foreground, 1.3)
            font.pixelSize: Style.font.bodySmall
          }
          MouseArea {
            id: denyMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: brokerApprovalRoot.deny()
          }
        }

        // Allow Once button
        Rectangle {
          implicitHeight: 28
          implicitWidth: 84
          radius: 4
          opacity: brokerApprovalRoot.armed ? 1 : 0.4
          color: allowOnceMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.15) : Qt.rgba(1, 1, 1, 0.08)
          border.color: brokerApprovalRoot.borderColor
          border.width: 1
          Text {
            anchors.centerIn: parent
            text: "Allow Once"
            color: brokerApprovalRoot.foreground
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.Medium
          }
          MouseArea {
            id: allowOnceMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: brokerApprovalRoot.allowOnce()
          }
        }

        // Allow Always button
        Rectangle {
          implicitHeight: 28
          implicitWidth: 96
          radius: 4
          opacity: brokerApprovalRoot.armed ? 1 : 0.4
          color: allowAlwaysMouse.containsMouse ? Qt.lighter(brokerApprovalRoot.accent, 1.1) : brokerApprovalRoot.accent
          Text {
            anchors.centerIn: parent
            text: "Allow Always"
            color: "#ffffff"
            font.pixelSize: Style.font.bodySmall
            font.weight: Font.DemiBold
          }
          MouseArea {
            id: allowAlwaysMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: brokerApprovalRoot.allowAlways()
          }
        }
      }
    }
  }
}
