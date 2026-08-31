import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: settingsRoot

  property var config: ({})
  property var cliHealth: ({})
  property bool isDownloadingCli: false
  property bool isBusy: false
  property bool updateAvailable: false
  property string latestVersion: ""
  property bool isCheckingUpdate: false
  property string updateCheckStatus: ""
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  signal saveRequested(var newSettings)
  signal closeRequested()
  signal refreshHealthRequested()
  signal checkUpdateRequested()
  signal downloadCliRequested()

  ScrollView {
    anchors.fill: parent
    anchors.margins: 18
    clip: true
    ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
    ScrollBar.vertical: ScrollBar {
      id: settingsVScrollBar
      policy: ScrollBar.AsNeeded
      contentItem: Rectangle {
        implicitWidth: 4
        radius: 2
        color: settingsVScrollBar.pressed ? Qt.rgba(1, 1, 1, 0.4) : (settingsVScrollBar.hovered ? Qt.rgba(1, 1, 1, 0.25) : Qt.rgba(1, 1, 1, 0.15))
      }
    }

    ColumnLayout {
      width: settingsRoot.width - 36
      spacing: 14

      // Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Rectangle {
          implicitHeight: 24
          implicitWidth: backBtnText.implicitWidth + 12
          radius: 4
          color: Qt.rgba(0, 0, 0, 0.2)
          border.color: settingsRoot.borderColor
          border.width: 1

          RowLayout {
            id: backBtnText
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "\uf060"
              font.family: settingsRoot.fontFamily
              color: settingsRoot.foreground
              font.pixelSize: 10
            }
            Text {
              text: "Back to Vault"
              color: settingsRoot.foreground
              font.pixelSize: 11
              font.weight: Font.Medium
            }
          }
          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: settingsRoot.closeRequested()
          }
        }

        RowLayout {
          spacing: 6
          Layout.fillWidth: true
          Text {
            text: "\uf013"
            font.family: settingsRoot.fontFamily
            color: settingsRoot.accent
            font.pixelSize: 13
          }
          Text {
            text: "Plugin Settings & Engine Health"
            color: settingsRoot.foreground
            font.pixelSize: 13
            font.weight: Font.DemiBold
            Layout.fillWidth: true
          }
        }
      }

      Rectangle { Layout.fillWidth: true; height: 1; color: settingsRoot.borderColor }

      // 1. Engine Diagnostic Health Badges
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          Text { text: "ENGINE STATUS & DIAGNOSTICS"; color: Qt.darker(settingsRoot.foreground, 1.8); font.pixelSize: 10; font.weight: Font.DemiBold }
          Item { Layout.fillWidth: true }

          // Check Update Button
          Rectangle {
            implicitHeight: 20
            implicitWidth: chkUpText.implicitWidth + 10
            radius: 3
            color: Qt.rgba(0, 0, 0, 0.2)
            border.color: settingsRoot.borderColor
            border.width: 1

            Text {
              id: chkUpText
              anchors.centerIn: parent
              text: settingsRoot.isCheckingUpdate ? "Checking..." : "Check Update"
              color: settingsRoot.accent
              font.pixelSize: 10
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              enabled: !settingsRoot.isCheckingUpdate
              onClicked: settingsRoot.checkUpdateRequested()
            }
          }

          // Refresh Button
          Rectangle {
            implicitHeight: 20
            implicitWidth: refHText.implicitWidth + 8
            radius: 3
            color: Qt.rgba(0, 0, 0, 0.2)
            border.color: settingsRoot.borderColor
            border.width: 1

            Text { id: refHText; anchors.centerIn: parent; text: "Refresh"; color: settingsRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsRoot.refreshHealthRequested() }
          }
        }

        // Update Available Banner & Action
        Rectangle {
          visible: settingsRoot.updateAvailable && Boolean(settingsRoot.latestVersion)
          Layout.fillWidth: true
          implicitHeight: updateRow.implicitHeight + 16
          radius: 5
          color: Qt.rgba(0.2, 0.8, 0.4, 0.12)
          border.color: "#4ade80"
          border.width: 1

          RowLayout {
            id: updateRow
            anchors.fill: parent
            anchors.margins: 8
            spacing: 8

            Text {
              text: "\uf005"
              font.family: settingsRoot.fontFamily
              color: "#4ade80"
              font.pixelSize: 14
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 2
              Text {
                text: "New omawarden engine available: v" + settingsRoot.latestVersion
                color: "#4ade80"
                font.pixelSize: 11
                font.weight: Font.DemiBold
              }
              Text {
                text: "Current installed version: " + (settingsRoot.cliHealth.version || "unknown")
                color: Qt.darker(settingsRoot.foreground, 1.6)
                font.pixelSize: 10
              }
            }

            Rectangle {
              implicitHeight: 26
              implicitWidth: upBtnText.implicitWidth + 14
              radius: 4
              color: "#22c55e"

              Text {
                id: upBtnText
                anchors.centerIn: parent
                text: settingsRoot.isDownloadingCli ? "Updating..." : ("Update to v" + settingsRoot.latestVersion)
                color: "#ffffff"
                font.pixelSize: 10
                font.weight: Font.Medium
              }

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                enabled: !settingsRoot.isDownloadingCli
                onClicked: settingsRoot.downloadCliRequested()
              }
            }
          }
        }

        // Update Check Status Feedback (when manually checked and up-to-date or error)
        Text {
          visible: !settingsRoot.updateAvailable && Boolean(settingsRoot.updateCheckStatus)
          text: settingsRoot.updateCheckStatus
          color: Qt.darker(settingsRoot.foreground, 1.6)
          font.pixelSize: 10
          font.weight: Font.Medium
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          // CLI Engine Badge
          Rectangle {
            implicitHeight: 24
            implicitWidth: cliBadgeRow.implicitWidth + 10
            radius: 4
            color: settingsRoot.cliHealth.installed ? Qt.rgba(0.2, 0.8, 0.4, 0.15) : Qt.rgba(0.9, 0.2, 0.2, 0.15)
            border.color: settingsRoot.cliHealth.installed ? "#4ade80" : "#f87171"
            border.width: 1

            RowLayout {
              id: cliBadgeRow
              anchors.centerIn: parent
              spacing: 4
              Text {
                text: settingsRoot.cliHealth.installed ? "\uf00c" : "\uf00d"
                font.family: settingsRoot.fontFamily
                color: settingsRoot.cliHealth.installed ? "#4ade80" : "#f87171"
                font.pixelSize: 10
              }
              Text { text: "Engine: " + (settingsRoot.cliHealth.version || (settingsRoot.cliHealth.installed ? "Ready" : "Missing")); color: settingsRoot.foreground; font.pixelSize: 10 }
            }
          }

          // Download Engine Button (When missing or downloading)
          Rectangle {
            visible: !settingsRoot.cliHealth.installed
            implicitHeight: 24
            implicitWidth: dlBtnText.implicitWidth + 12
            radius: 4
            color: settingsRoot.accent

            Text {
              id: dlBtnText
              anchors.centerIn: parent
              text: settingsRoot.isDownloadingCli ? "Downloading..." : "Download Engine"
              color: "#ffffff"
              font.pixelSize: 10
              font.weight: Font.Medium
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              enabled: !settingsRoot.isDownloadingCli
              onClicked: settingsRoot.downloadCliRequested()
            }
          }

          // Keyring Badge
          Rectangle {
            implicitHeight: 24
            implicitWidth: krBadgeRow.implicitWidth + 10
            radius: 4
            color: settingsRoot.cliHealth.keyring_available ? Qt.rgba(0.2, 0.8, 0.4, 0.15) : Qt.rgba(0.9, 0.2, 0.2, 0.15)
            border.color: settingsRoot.cliHealth.keyring_available ? "#4ade80" : "#f87171"
            border.width: 1

            RowLayout {
              id: krBadgeRow
              anchors.centerIn: parent
              spacing: 4
              Text {
                text: settingsRoot.cliHealth.keyring_available ? "\uf00c" : "\uf00d"
                font.family: settingsRoot.fontFamily
                color: settingsRoot.cliHealth.keyring_available ? "#4ade80" : "#f87171"
                font.pixelSize: 10
              }
              Text { text: "Keyring: " + (settingsRoot.cliHealth.keyring_available ? "Ready" : "Unavailable"); color: settingsRoot.foreground; font.pixelSize: 10 }
            }
          }

          // Clipboard Badge
          Rectangle {
            implicitHeight: 24
            implicitWidth: clipBadgeRow.implicitWidth + 10
            radius: 4
            color: settingsRoot.cliHealth.clipboard_available ? Qt.rgba(0.2, 0.8, 0.4, 0.15) : Qt.rgba(0.9, 0.2, 0.2, 0.15)
            border.color: settingsRoot.cliHealth.clipboard_available ? "#4ade80" : "#f87171"
            border.width: 1

            RowLayout {
              id: clipBadgeRow
              anchors.centerIn: parent
              spacing: 4
              Text {
                text: settingsRoot.cliHealth.clipboard_available ? "\uf00c" : "\uf00d"
                font.family: settingsRoot.fontFamily
                color: settingsRoot.cliHealth.clipboard_available ? "#4ade80" : "#f87171"
                font.pixelSize: 10
              }
              Text { text: "Clipboard: " + (settingsRoot.cliHealth.clipboard_available ? "Ready" : "Missing"); color: settingsRoot.foreground; font.pixelSize: 10 }
            }
          }
        }
      }

      // 2. Form Settings
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 10

        // Server URL
        ColumnLayout {
          Layout.fillWidth: true
          spacing: 3
          Text { text: "Bitwarden / Vaultwarden Server URL:"; color: settingsRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: sUrlInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
            TextInput {
              id: sUrlInput
              anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; verticalAlignment: TextInput.AlignVCenter; color: settingsRoot.foreground; font.pixelSize: 12; selectByMouse: true
              text: (settingsRoot.config && settingsRoot.config.server_url) ? settingsRoot.config.server_url : "https://vault.bitwarden.com"
            }
          }
        }

        // Download Directory
        ColumnLayout {
          Layout.fillWidth: true
          spacing: 3
          Text { text: "Attachment Download Directory:"; color: settingsRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          Rectangle {
            Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: dlDirInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
            TextInput {
              id: dlDirInput
              anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; verticalAlignment: TextInput.AlignVCenter; color: settingsRoot.foreground; font.pixelSize: 12; selectByMouse: true
              text: (settingsRoot.config && settingsRoot.config.download_dir) ? settingsRoot.config.download_dir : "~/Downloads"
            }
          }
        }

        // Row of Numeric Settings
        RowLayout {
          Layout.fillWidth: true
          spacing: 12

          // Auto-Lock Minutes
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            Text { text: "Auto-lock Timeout (Minutes):"; color: settingsRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: lockMinInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: lockMinInput
                anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; verticalAlignment: TextInput.AlignVCenter; color: settingsRoot.foreground; font.pixelSize: 12; selectByMouse: true
                text: (settingsRoot.config && settingsRoot.config.auto_lock_minutes) ? String(settingsRoot.config.auto_lock_minutes) : "15"
              }
            }
          }

          // Clipboard TTL Seconds
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            Text { text: "Clipboard Auto-Clear (Seconds):"; color: settingsRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: clipSecInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: clipSecInput
                anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; verticalAlignment: TextInput.AlignVCenter; color: settingsRoot.foreground; font.pixelSize: 12; selectByMouse: true
                text: (settingsRoot.config && settingsRoot.config.clipboard_clear_seconds) ? String(settingsRoot.config.clipboard_clear_seconds) : "30"
              }
            }
          }
        }
      }

      // Save Button
      RowLayout {
        Layout.fillWidth: true
        Item { Layout.fillWidth: true }

        Rectangle {
          implicitHeight: 30
          implicitWidth: saveBtnText.implicitWidth + 20
          radius: 5
          color: settingsRoot.accent

          Text {
            id: saveBtnText
            anchors.centerIn: parent
            text: settingsRoot.isBusy ? "Saving..." : "Save Settings"
            color: "#ffffff"
            font.pixelSize: 11
            font.weight: Font.Medium
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              var payload = {
                server_url: sUrlInput.text.trim() || "https://vault.bitwarden.com",
                download_dir: dlDirInput.text.trim() || "~/Downloads",
                auto_lock_minutes: parseInt(lockMinInput.text.trim()) || 15,
                clipboard_clear_seconds: parseInt(clipSecInput.text.trim()) || 30
              }
              settingsRoot.saveRequested(payload)
            }
          }
        }
      }
    }
  }
}
