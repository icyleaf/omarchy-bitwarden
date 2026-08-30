import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: footerRoot

  property string overlayVersion: ""
  property string backendVersion: ""
  property bool isUnlocked: true
  property bool isBusy: false
  property color background: "transparent"
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: "transparent"

  signal actionPaletteTriggered()
  signal syncTriggered()
  signal lockTriggered()
  signal settingsTriggered()

  height: 28
  Layout.fillWidth: true
  color: footerRoot.background
  border.width: 0
  radius: 0

  RowLayout {
    anchors.fill: parent
    anchors.leftMargin: 4
    anchors.rightMargin: 4
    spacing: 4

    // 1. Bottom Left: Ghost Actions, Sync, Lock, Settings
    RowLayout {
      spacing: 2
      visible: footerRoot.isUnlocked

      // Actions Ghost Button
      Rectangle {
        implicitHeight: 24
        implicitWidth: actionsBtnRow.implicitWidth + 12
        radius: 4
        color: actionsMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: actionsBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text {
            text: "⚡ Actions"
            color: actionsMouse.containsMouse ? footerRoot.foreground : Qt.darker(footerRoot.foreground, 1.3)
            font.pixelSize: 11
            font.weight: Font.Medium
          }
          Text {
            text: "Ctrl+K"
            color: Qt.darker(footerRoot.foreground, 1.8)
            font.pixelSize: 9
          }
        }

        MouseArea {
          id: actionsMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.actionPaletteTriggered()
        }
      }

      // Sync Ghost Button
      Rectangle {
        implicitHeight: 24
        implicitWidth: syncBtnRow.implicitWidth + 12
        radius: 4
        color: syncMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: syncBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text {
            text: "🔄 Sync"
            color: syncMouse.containsMouse ? footerRoot.foreground : Qt.darker(footerRoot.foreground, 1.3)
            font.pixelSize: 11
            font.weight: Font.Medium
          }
          Text {
            text: "Ctrl+R"
            color: Qt.darker(footerRoot.foreground, 1.8)
            font.pixelSize: 9
          }
        }

        MouseArea {
          id: syncMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.syncTriggered()
        }
      }

      // Lock Ghost Button
      Rectangle {
        implicitHeight: 24
        implicitWidth: lockBtnRow.implicitWidth + 12
        radius: 4
        color: lockMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: lockBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text {
            text: "🔒 Lock"
            color: lockMouse.containsMouse ? footerRoot.foreground : Qt.darker(footerRoot.foreground, 1.3)
            font.pixelSize: 11
            font.weight: Font.Medium
          }
          Text {
            text: "Ctrl+L"
            color: Qt.darker(footerRoot.foreground, 1.8)
            font.pixelSize: 9
          }
        }

        MouseArea {
          id: lockMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.lockTriggered()
        }
      }

      // Settings Ghost Button
      Rectangle {
        implicitHeight: 24
        implicitWidth: settingsBtnRow.implicitWidth + 12
        radius: 4
        color: settingsMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: settingsBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text {
            text: "⚙️ Settings"
            color: settingsMouse.containsMouse ? footerRoot.foreground : Qt.darker(footerRoot.foreground, 1.3)
            font.pixelSize: 11
            font.weight: Font.Medium
          }
          Text {
            text: "Ctrl+,"
            color: Qt.darker(footerRoot.foreground, 1.8)
            font.pixelSize: 9
          }
        }

        MouseArea {
          id: settingsMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.settingsTriggered()
        }
      }
    }

    Item { Layout.fillWidth: true }

    // 2. Bottom Right: Plain, uncolored version info
    RowLayout {
      spacing: 6

      Text {
        text: "Overlay " + (footerRoot.overlayVersion || "v0.4.0")
        color: Qt.darker(footerRoot.foreground, 1.8)
        font.pixelSize: 10
      }

      Text {
        text: "•"
        color: Qt.darker(footerRoot.foreground, 2.2)
        font.pixelSize: 10
      }

      Text {
        text: "Backend " + (footerRoot.backendVersion || "omawarden v0.1.0")
        color: Qt.darker(footerRoot.foreground, 1.8)
        font.pixelSize: 10
      }
    }
  }
}
