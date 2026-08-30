import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: footerRoot

  property string overlayVersion: ""
  property string backendVersion: ""
  property bool isEngineInstalled: true
  property bool isDownloadingCli: false
  property bool updateAvailable: false
  property string latestVersion: ""
  property bool isUnlocked: true
  property bool isBusy: false
  property color background: "transparent"
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)

  signal actionPaletteTriggered()
  signal syncTriggered()
  signal lockTriggered()
  signal settingsTriggered()
  signal downloadCliTriggered()

  height: 30
  Layout.fillWidth: true
  color: footerRoot.background
  border.width: 0
  radius: 0

  // 1. Top border matching Omarchy theme border
  Rectangle {
    anchors.top: parent.top
    anchors.left: parent.left
    anchors.right: parent.right
    height: 1
    color: footerRoot.borderColor
  }

  RowLayout {
    anchors.fill: parent
    anchors.topMargin: 3
    anchors.leftMargin: 2
    anchors.rightMargin: 2
    spacing: 4

    // 2. Bottom Left: Ghost Actions, Sync, Lock, Settings
    RowLayout {
      spacing: 2

      // Unlocked Actions Group
      RowLayout {
        spacing: 2
        visible: footerRoot.isUnlocked

        // Actions Ghost Button
        Rectangle {
          implicitHeight: 22
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
          implicitHeight: 22
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
          implicitHeight: 22
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
      }

      // Settings Ghost Button (Always visible on bottom-left)
      Rectangle {
        implicitHeight: 22
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

    // 3. Bottom Right: Plain version info + Engine Download / Update badges
    RowLayout {
      spacing: 3

      Text {
        text: "Overlay " + footerRoot.overlayVersion
        color: Qt.darker(footerRoot.foreground, 1.8)
        font.pixelSize: 10
      }

      Text {
        text: "•"
        color: Qt.darker(footerRoot.foreground, 2.2)
        font.pixelSize: 10
      }

      Text {
        visible: footerRoot.isEngineInstalled
        text: "Backend " + footerRoot.backendVersion
        color: Qt.darker(footerRoot.foreground, 1.8)
        font.pixelSize: 10
      }

      // Downloading Engine Indicator
      Rectangle {
        visible: footerRoot.isDownloadingCli
        implicitHeight: 18
        implicitWidth: dlProgRow.implicitWidth + 10
        radius: 4
        color: Qt.rgba(footerRoot.accent.r, footerRoot.accent.g, footerRoot.accent.b, 0.15)
        border.color: footerRoot.accent
        border.width: 1

        RowLayout {
          id: dlProgRow
          anchors.centerIn: parent
          spacing: 3
          Text {
            text: "⏳ Downloading Engine..."
            color: footerRoot.accent
            font.pixelSize: 10
            font.weight: Font.Medium
          }
        }
      }

      // Download Engine Button (When missing/not installed)
      Rectangle {
        visible: !footerRoot.isEngineInstalled && !footerRoot.isDownloadingCli
        implicitHeight: 18
        implicitWidth: dlBadgeRow.implicitWidth + 10
        radius: 4
        color: Qt.rgba(0.9, 0.2, 0.2, 0.15)
        border.color: "#f87171"
        border.width: 1

        RowLayout {
          id: dlBadgeRow
          anchors.centerIn: parent
          spacing: 3
          Text {
            text: "📥 Download Engine"
            color: "#f87171"
            font.pixelSize: 10
            font.weight: Font.DemiBold
          }
        }

        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          hoverEnabled: true
          onClicked: footerRoot.downloadCliTriggered()
        }
      }

      // Update Available Badge
      Rectangle {
        visible: footerRoot.isEngineInstalled && footerRoot.updateAvailable && Boolean(footerRoot.latestVersion)
        implicitHeight: 18
        implicitWidth: updateBadgeRow.implicitWidth + 10
        radius: 4
        color: Qt.rgba(0.2, 0.8, 0.4, 0.15)
        border.color: "#4ade80"
        border.width: 1

        RowLayout {
          id: updateBadgeRow
          anchors.centerIn: parent
          spacing: 3
          Text {
            text: "✨ v" + footerRoot.latestVersion + " Available"
            color: "#4ade80"
            font.pixelSize: 10
            font.weight: Font.Medium
          }
        }

        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          hoverEnabled: true
          onClicked: footerRoot.settingsTriggered()
        }
      }
    }
  }
}
