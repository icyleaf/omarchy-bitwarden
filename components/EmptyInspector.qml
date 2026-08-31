import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: emptyInspectorRoot

  property var rawVaultItems: []
  property var authState: ({})
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  readonly property string fontFamily: Style.font.menuFamily

  ColumnLayout {
    anchors.fill: parent
    anchors.margins: 20
    spacing: 14

    // Header Hero
    RowLayout {
      spacing: 12

      Rectangle {
        width: 38
        height: 38
        radius: 8
        color: Qt.rgba(emptyInspectorRoot.accent.r, emptyInspectorRoot.accent.g, emptyInspectorRoot.accent.b, 0.15)
        border.color: Qt.rgba(emptyInspectorRoot.accent.r, emptyInspectorRoot.accent.g, emptyInspectorRoot.accent.b, 0.4)
        border.width: 1

        Text {
          anchors.centerIn: parent
          text: "\uf132"
          font.family: emptyInspectorRoot.fontFamily
          font.pixelSize: 20
          color: emptyInspectorRoot.accent
        }
      }

      ColumnLayout {
        spacing: 2
        Text {
          text: "Bitwarden Vault"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 13
          font.weight: Font.DemiBold
        }
        Text {
          text: (emptyInspectorRoot.rawVaultItems ? emptyInspectorRoot.rawVaultItems.length : 0) + " items synced • Ready for search"
          color: Qt.darker(emptyInspectorRoot.foreground, 1.6)
          font.pixelSize: 11
        }
      }
    }

    // Divider
    Rectangle {
      Layout.fillWidth: true
      height: 1
      color: emptyInspectorRoot.borderColor
    }

    // Shortcuts Cheat Sheet
    Text {
      text: "KEYBOARD SHORTCUTS"
      color: Qt.darker(emptyInspectorRoot.foreground, 1.8)
      font.pixelSize: 10
      font.weight: Font.DemiBold
    }

    GridLayout {
      columns: 2
      rowSpacing: 8
      columnSpacing: 14
      Layout.fillWidth: true

      // Enter
      Rectangle {
        implicitHeight: 22
        implicitWidth: k1.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k1
          anchors.centerIn: parent
          text: "↵ Enter"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Copy primary credential (password / card / key)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }

      // Ctrl+K
      Rectangle {
        implicitHeight: 22
        implicitWidth: k2.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k2
          anchors.centerIn: parent
          text: "Ctrl + K"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Action Palette (copy TOTP, username, PIN)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }

      // Tab
      Rectangle {
        implicitHeight: 22
        implicitWidth: k3.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k3
          anchors.centerIn: parent
          text: "Tab"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Switch category filter (Logins, Cards, Notes, SSH)"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }

      // Ctrl+R
      Rectangle {
        implicitHeight: 22
        implicitWidth: k4.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k4
          anchors.centerIn: parent
          text: "Ctrl + R"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Sync vault with server"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }

      // Ctrl+L
      Rectangle {
        implicitHeight: 22
        implicitWidth: k5.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k5
          anchors.centerIn: parent
          text: "Ctrl + L"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Lock vault immediately"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }

      // Ctrl+,
      Rectangle {
        implicitHeight: 22
        implicitWidth: k6.implicitWidth + 12
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.2)
        border.color: emptyInspectorRoot.borderColor
        border.width: 1
        Text {
          id: k6
          anchors.centerIn: parent
          text: "Ctrl + ,"
          color: emptyInspectorRoot.foreground
          font.pixelSize: 11
          font.weight: Font.Medium
        }
      }
      Text {
        text: "Open Settings & configuration"
        color: Qt.darker(emptyInspectorRoot.foreground, 1.3)
        font.pixelSize: 11
        Layout.fillWidth: true
      }
    }

    Item { Layout.fillHeight: true }

    // Footer Hint
    Rectangle {
      Layout.fillWidth: true
      implicitHeight: 26
      radius: 4
      color: Qt.rgba(0, 0, 0, 0.15)
      border.color: emptyInspectorRoot.borderColor
      border.width: 1

      RowLayout {
        anchors.centerIn: parent
        spacing: 6
        RowLayout {
          spacing: 3
          Text {
            text: "\uf0eb"
            font.family: emptyInspectorRoot.fontFamily
            color: emptyInspectorRoot.accent
            font.pixelSize: 10
          }
          Text {
            text: "Tip:"
            color: emptyInspectorRoot.accent
            font.pixelSize: 10
            font.weight: Font.Medium
          }
        }
        Text {
          text: "Select any item from the left list to inspect credentials and attachments."
          color: Qt.darker(emptyInspectorRoot.foreground, 1.5)
          font.pixelSize: 10
        }
      }
    }
  }
}
