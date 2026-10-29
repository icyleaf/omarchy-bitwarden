import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: footerRoot

  property string overlayVersion: ""
  property string backendVersion: ""
  property bool isEngineInstalled: true
  property bool isInstallingDependencies: false
  property bool updateAvailable: false
  property string latestVersion: ""
  property bool isUnlocked: true
  property bool isBusy: false
  property color background: "transparent"
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.menu.border
  property string fontFamily: ""

  signal actionPaletteTriggered()
  signal generatePasswordTriggered()
  signal syncTriggered()
  signal lockTriggered()
  signal settingsTriggered()
  signal installCliTriggered()

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
          color: actionsMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: actionsBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                text: "\uf0e7"
                font.family: footerRoot.fontFamily
                color: actionsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                text: "Actions"
                color: actionsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              text: "Ctrl+K"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
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

        // Generate Password Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: generateBtnRow.implicitWidth + 12
          radius: 4
          color: generateMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: generateBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                text: "\uf084"
                font.family: footerRoot.fontFamily
                color: generateMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                text: "Generate"
                color: generateMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              text: "Ctrl+G"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
          }

          MouseArea {
            id: generateMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: footerRoot.generatePasswordTriggered()
          }
        }

        // Sync Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: syncBtnRow.implicitWidth + 12
          radius: 4
          color: syncMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: syncBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                text: "\uf021"
                font.family: footerRoot.fontFamily
                color: syncMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                text: "Sync"
                color: syncMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              text: "Ctrl+R"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
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
          color: lockMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: lockBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                text: "\uf023"
                font.family: footerRoot.fontFamily
                color: lockMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                text: "Lock"
                color: lockMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              text: "Ctrl+L"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
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
        color: settingsMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: settingsBtnRow
          anchors.centerIn: parent
          spacing: 4
          RowLayout {
            spacing: 3
            Text {
              text: "\uf013"
              font.family: footerRoot.fontFamily
              color: settingsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
              font.pixelSize: Style.font.bodySmall
            }
            Text {
              text: "Settings"
              color: settingsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }
          }
          Text {
            text: "Ctrl+,"
            color: footerRoot.muted
            font.pixelSize: Style.fontPx(0.75)
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
        text: "Omarchy Bitwarden " + footerRoot.overlayVersion
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      Text {
        text: "•"
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      Text {
        visible: footerRoot.isEngineInstalled && !footerRoot.updateAvailable
        text: "Omawarden " + footerRoot.backendVersion
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      // Installing Engine Indicator
      Rectangle {
        visible: footerRoot.isInstallingDependencies
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
            text: "\uf021"
            font.family: footerRoot.fontFamily
            color: footerRoot.accent
            font.pixelSize: Style.fontPx(0.75)
          }
          Text {
            text: "Installing Engine..."
            color: footerRoot.accent
            font.pixelSize: Style.font.caption
            font.weight: Font.Medium
          }
        }
      }

      // Install Engine Button (When missing/not installed)
      Rectangle {
        visible: !footerRoot.isEngineInstalled && !footerRoot.isInstallingDependencies
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
            text: "\uf019"
            font.family: footerRoot.fontFamily
            color: "#f87171"
            font.pixelSize: Style.fontPx(0.75)
          }
          Text {
            text: "Install Engine"
            color: "#f87171"
            font.pixelSize: Style.font.caption
            font.weight: Font.DemiBold
          }
        }

        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          hoverEnabled: true
          onClicked: footerRoot.installCliTriggered()
        }
      }

      // Update Available Badge
      Rectangle {
        visible: footerRoot.isEngineInstalled && footerRoot.updateAvailable && Boolean(footerRoot.latestVersion)
        implicitHeight: 18
        implicitWidth: updateBadgeRow.implicitWidth + 10
        radius: 4
        color: Qt.rgba(0.2, 0.8, 0.4, 0.15)
        border.width: 0

        RowLayout {
          id: updateBadgeRow
          anchors.centerIn: parent
          spacing: 3
          Text {
            text: "Omawarden"
            font.family: footerRoot.fontFamily
            color: "#4ade80"
            font.pixelSize: Style.fontPx(0.75)
          }
          Text {
            text: "\uf005 " + footerRoot.latestVersion + " Available"
            color: "#4ade80"
            font.pixelSize: Style.font.caption
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
