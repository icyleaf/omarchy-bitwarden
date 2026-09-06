import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ScrollView {
  id: emptyInspectorRoot

  property var rawVaultItems: []
  property var authState: ({})
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  clip: true
  ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
  ScrollBar.vertical: ScrollBar {
    id: emptyVScrollBar
    policy: ScrollBar.AsNeeded
    contentItem: Rectangle {
      implicitWidth: 4
      radius: 2
      color: emptyVScrollBar.pressed ? Qt.rgba(1, 1, 1, 0.4) : (emptyVScrollBar.hovered ? Qt.rgba(1, 1, 1, 0.25) : Qt.rgba(1, 1, 1, 0.15))
    }
  }

  ColumnLayout {
    width: emptyInspectorRoot.width - 16
    spacing: 12

    // Shortcuts Cheat Sheet Header
    Text {
      text: "KEYBOARD SHORTCUTS"
      color: Qt.darker(emptyInspectorRoot.foreground, 1.8)
      font.pixelSize: 9
      font.weight: Font.DemiBold
    }

    GridLayout {
      columns: 2
      rowSpacing: 6
      columnSpacing: 10
      Layout.fillWidth: true

      // Tab
      Rectangle {
        implicitHeight: 20
        implicitWidth: k3.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k3
          anchors.centerIn: parent
          text: "Tab"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Switch Category Filter (Logins, Cards, Secure Note, SSH)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Alt+V
      Rectangle {
        implicitHeight: 20
        implicitWidth: kAltV.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kAltV
          anchors.centerIn: parent
          text: "Alt + V"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Switch Vault Scope (All Vaults, Personal, Organizations)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Alt+F
      Rectangle {
        implicitHeight: 20
        implicitWidth: kAltF.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kAltF
          anchors.centerIn: parent
          text: "Alt + F"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Switch Folder Scope (All Folders, Specific Folder)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Enter
      Rectangle {
        implicitHeight: 20
        implicitWidth: k1.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k1
          anchors.centerIn: parent
          text: "↵ "
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Copy Primary Credential (Password / Card / Key)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+↵
      Rectangle {
        implicitHeight: 20
        implicitWidth: kEnterTotp.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kEnterTotp
          anchors.centerIn: parent
          text: "Ctrl + ↵"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Copy Live TOTP Code"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+U
      Rectangle {
        implicitHeight: 20
        implicitWidth: kU.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kU
          anchors.centerIn: parent
          text: "Ctrl + U"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Copy Username"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+T
      Rectangle {
        implicitHeight: 20
        implicitWidth: kT.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kT
          anchors.centerIn: parent
          text: "Ctrl + T"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Toggle Field / Secret Visibility"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+H
      Rectangle {
        implicitHeight: 20
        implicitWidth: kH.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kH
          anchors.centerIn: parent
          text: "Ctrl + H"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Password History Modal"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+O
      Rectangle {
        implicitHeight: 20
        implicitWidth: kO.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: kO
          anchors.centerIn: parent
          text: "Ctrl + O"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Primary Website in Default Browser"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+K
      Rectangle {
        implicitHeight: 20
        implicitWidth: k2.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k2
          anchors.centerIn: parent
          text: "Ctrl + K"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Action Palette (Copy Attributes, PIN, Attachments)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+R
      Rectangle {
        implicitHeight: 20
        implicitWidth: k4.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k4
          anchors.centerIn: parent
          text: "Ctrl + R"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Sync Vault with Server"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+L
      Rectangle {
        implicitHeight: 20
        implicitWidth: k5.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k5
          anchors.centerIn: parent
          text: "Ctrl + L"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Lock Vault Immediately"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }

      // Ctrl+,
      Rectangle {
        implicitHeight: 20
        implicitWidth: k6.implicitWidth + 10
        radius: 3
        color: Qt.rgba(0, 0, 0, 0.25)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k6
          anchors.centerIn: parent
          text: "Ctrl + ,"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 10
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Settings & Configuration"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 10
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
      }
    }
  }
}
