import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: footerRoot

  property string overlayVersion: "v0.4.0"
  property string backendVersion: "omawarden v0.1.0"
  property bool isUnlocked: true
  property bool isBusy: false
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)

  signal actionPaletteTriggered()
  signal syncTriggered()
  signal lockTriggered()
  signal settingsTriggered()

  height: 34
  Layout.fillWidth: true
  color: Qt.rgba(0, 0, 0, 0.2)
  border.color: footerRoot.borderColor
  border.width: 1
  radius: 6

  RowLayout {
    anchors.fill: parent
    anchors.leftMargin: 10
    anchors.rightMargin: 10
    spacing: 8

    // 1. Bottom Left: Actions, Sync, Lock, Settings
    RowLayout {
      spacing: 6
      visible: footerRoot.isUnlocked

      // Actions Button
      Rectangle {
        implicitHeight: 22
        implicitWidth: actionsBtnRow.implicitWidth + 12
        radius: 4
        color: actionsMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
        border.color: Qt.rgba(1, 1, 1, 0.15)
        border.width: 1

        RowLayout {
          id: actionsBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text { text: "⚡ Actions"; color: footerRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Text { text: "Ctrl+K"; color: Qt.darker(footerRoot.foreground, 1.8); font.pixelSize: 9 }
        }

        MouseArea {
          id: actionsMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.actionPaletteTriggered()
        }
      }

      // Sync Button
      Rectangle {
        implicitHeight: 22
        implicitWidth: syncBtnRow.implicitWidth + 12
        radius: 4
        color: syncMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
        border.color: Qt.rgba(1, 1, 1, 0.15)
        border.width: 1

        RowLayout {
          id: syncBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text { text: "🔄 Sync"; color: footerRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Text { text: "Ctrl+R"; color: Qt.darker(footerRoot.foreground, 1.8); font.pixelSize: 9 }
        }

        MouseArea {
          id: syncMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.syncTriggered()
        }
      }

      // Lock Button
      Rectangle {
        implicitHeight: 22
        implicitWidth: lockBtnRow.implicitWidth + 12
        radius: 4
        color: lockMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
        border.color: Qt.rgba(1, 1, 1, 0.15)
        border.width: 1

        RowLayout {
          id: lockBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text { text: "🔒 Lock"; color: footerRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Text { text: "Ctrl+L"; color: Qt.darker(footerRoot.foreground, 1.8); font.pixelSize: 9 }
        }

        MouseArea {
          id: lockMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.lockTriggered()
        }
      }

      // Settings Button
      Rectangle {
        implicitHeight: 22
        implicitWidth: settingsBtnRow.implicitWidth + 12
        radius: 4
        color: settingsMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
        border.color: Qt.rgba(1, 1, 1, 0.15)
        border.width: 1

        RowLayout {
          id: settingsBtnRow
          anchors.centerIn: parent
          spacing: 4
          Text { text: "⚙️ Settings"; color: footerRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Text { text: "Ctrl+,"; color: Qt.darker(footerRoot.foreground, 1.8); font.pixelSize: 9 }
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

    // 2. Bottom Right: Overlay and Backend Version Info
    RowLayout {
      spacing: 6

      // Overlay Version Badge
      Rectangle {
        implicitHeight: 18
        implicitWidth: overlayVerText.implicitWidth + 8
        radius: 3
        color: Qt.rgba(0.5, 0.5, 0.5, 0.15)

        Text {
          id: overlayVerText
          anchors.centerIn: parent
          text: "Overlay " + (footerRoot.overlayVersion || "v0.4.0")
          color: Qt.darker(footerRoot.foreground, 1.6)
          font.pixelSize: 10
        }
      }

      Text {
        text: "•"
        color: Qt.darker(footerRoot.foreground, 2.0)
        font.pixelSize: 10
      }

      // Backend Version Badge
      Rectangle {
        implicitHeight: 18
        implicitWidth: backendVerText.implicitWidth + 8
        radius: 3
        color: Qt.rgba(0.23, 0.51, 0.96, 0.15)

        Text {
          id: backendVerText
          anchors.centerIn: parent
          text: footerRoot.backendVersion || "omawarden v0.1.0"
          color: footerRoot.accent
          font.pixelSize: 10
        }
      }
    }
  }
}
