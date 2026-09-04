import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: settingsRoot

  property var config: ({})
  property var cliHealth: ({})
  property var logBuffer: []
  property bool isDownloadingCli: false
  property bool isBusy: false
  property bool updateAvailable: false
  property string latestVersion: ""
  property string latestReleaseNotes: ""
  property string latestReleaseUrl: ""
  property string latestReleaseTitle: ""
  property bool showReleaseNotes: false
  property bool isCheckingUpdate: false
  property string updateCheckStatus: ""
  property bool justCheckedLatest: false
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  Timer {
    id: latestTimer
    interval: 2500
    onTriggered: settingsRoot.justCheckedLatest = false
  }

  onIsCheckingUpdateChanged: {
    if (!isCheckingUpdate && !updateAvailable) {
      justCheckedLatest = true
      latestTimer.restart()
    }
  }

  onVisibleChanged: {
    if (!visible) {
      showReleaseNotes = false
    }
  }

  property string activeTab: "general" // "general" | "logs"
  property string logFilter: "all" // "all" | "error" | "warn"
  property string selectedLogLevel: (config && config.log_level) ? config.log_level.toLowerCase() : "error"

  signal saveRequested(var newSettings)
  signal closeRequested()
  signal refreshHealthRequested()
  signal checkUpdateRequested()
  signal downloadCliRequested()
  signal copyDiagnosticsRequested()
  signal clearLogsRequested()

  readonly property int errorCount: {
    var count = 0
    var buf = settingsRoot.logBuffer || []
    for (var i = 0; i < buf.length; i++) {
      if (buf[i].level === "ERROR") count++
    }
    return count
  }

  readonly property int warnCount: {
    var count = 0
    var buf = settingsRoot.logBuffer || []
    for (var i = 0; i < buf.length; i++) {
      if (buf[i].level === "WARN") count++
    }
    return count
  }

  readonly property int infoCount: {
    var count = 0
    var buf = settingsRoot.logBuffer || []
    for (var i = 0; i < buf.length; i++) {
      if (buf[i].level === "INFO") count++
    }
    return count
  }

  readonly property int debugCount: {
    var count = 0
    var buf = settingsRoot.logBuffer || []
    for (var i = 0; i < buf.length; i++) {
      if (buf[i].level === "DEBUG") count++
    }
    return count
  }

  function getFilteredLogs() {
    var buf = settingsRoot.logBuffer || []
    if (settingsRoot.logFilter === "all") return buf
    var filterLevel = settingsRoot.logFilter.toUpperCase()
    var res = []
    for (var i = 0; i < buf.length; i++) {
      if (buf[i].level === filterLevel) res.push(buf[i])
    }
    return res
  }

  ColumnLayout {
    anchors.fill: parent
    anchors.margins: 18
    spacing: 12

    // Header & Tab Switcher
    RowLayout {
      Layout.fillWidth: true
      spacing: 12

      RowLayout {
        spacing: 6
        Text {
          text: "\uf013"
          font.family: settingsRoot.fontFamily
          color: settingsRoot.accent
          font.pixelSize: 13
        }
        Text {
          text: "Settings & Diagnostics"
          color: settingsRoot.foreground
          font.pixelSize: 13
          font.weight: Font.DemiBold
        }
      }

      Item { Layout.fillWidth: true }

      // Tabs: General / Logs
      RowLayout {
        spacing: 4

        // General Tab Button
        Rectangle {
          id: genTabItem
          property bool isSelected: settingsRoot.activeTab === "general"
          implicitHeight: 24
          implicitWidth: genTabText.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (genMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1

          Text {
            id: genTabText
            anchors.centerIn: parent
            text: "General"
            color: genTabItem.isSelected ? settingsRoot.accent : (genMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
            font.pixelSize: 11
            font.weight: genTabItem.isSelected ? Font.DemiBold : Font.Normal
          }
          MouseArea {
            id: genMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.activeTab = "general" }
          }
        }

        // Logs & Diagnostics Tab Button
        Rectangle {
          id: logsTabItem
          property bool isSelected: settingsRoot.activeTab === "logs"
          implicitHeight: 24
          implicitWidth: logsTabRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (logsMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1

          RowLayout {
            id: logsTabRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Logs & Diagnostics"
              color: logsTabItem.isSelected ? settingsRoot.accent : (logsMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: logsTabItem.isSelected ? Font.DemiBold : Font.Normal
            }
            // Error Badge if any errors exist
            Rectangle {
              visible: settingsRoot.errorCount > 0
              implicitHeight: 14
              implicitWidth: Math.max(14, errBadgeText.implicitWidth + 6)
              radius: 7
              color: "#ef4444"
              Text {
                id: errBadgeText
                anchors.centerIn: parent
                text: String(settingsRoot.errorCount)
                color: "#ffffff"
                font.pixelSize: 9
                font.weight: Font.Bold
              }
            }
          }
          MouseArea {
            id: logsMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.activeTab = "logs" }
          }
        }
      }
    }

    Rectangle { Layout.fillWidth: true; height: 1; color: settingsRoot.borderColor }

    // ========================================================
    // TAB 1: GENERAL SETTINGS VIEW
    // ========================================================
    ScrollView {
      visible: settingsRoot.activeTab === "general"
      Layout.fillWidth: true
      Layout.fillHeight: true
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

      ColumnLayout {
        width: settingsRoot.width - 36
        spacing: 14

        // 1. Engine Diagnostic Health Badges
        ColumnLayout {
          Layout.fillWidth: true
          spacing: 8

          RowLayout {
            Layout.fillWidth: true
            Text { text: "ENGINE STATUS & HEALTH"; color: Qt.darker(settingsRoot.foreground, 1.8); font.pixelSize: 10; font.weight: Font.DemiBold }
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
                text: settingsRoot.isCheckingUpdate ? "Checking..." : (settingsRoot.justCheckedLatest ? "Latest" : "Check Update")
                color: settingsRoot.justCheckedLatest ? "#4ade80" : settingsRoot.accent
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

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            // Unified Engine Badge & Update Action
            Rectangle {
              id: engineBadgeBox
              implicitHeight: 24
              implicitWidth: cliBadgeRow.implicitWidth + 14
              radius: 4
              color: engineMouse.containsMouse ? Qt.rgba(0, 0, 0, 0.4) : Qt.rgba(0, 0, 0, 0.2)
              border.color: settingsRoot.borderColor
              border.width: 1

              readonly property bool isInstalled: Boolean(settingsRoot.cliHealth.installed)
              readonly property bool hasUpdate: isInstalled && settingsRoot.updateAvailable && Boolean(settingsRoot.latestVersion)

              RowLayout {
                id: cliBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Rectangle {
                  implicitWidth: 6
                  implicitHeight: 6
                  radius: 3
                  color: engineBadgeBox.isInstalled ? "#4ade80" : "#f87171"
                }

                Text {
                  text: "Engine: " + (settingsRoot.cliHealth.version || (engineBadgeBox.isInstalled ? "Ready" : "Missing"))
                  color: settingsRoot.foreground
                  font.pixelSize: 10
                }

                // Inline update tag when update is available
                Rectangle {
                  visible: engineBadgeBox.hasUpdate
                  implicitHeight: 16
                  implicitWidth: updateTagRow.implicitWidth + 8
                  radius: 3
                  color: Qt.rgba(0.2, 0.8, 0.4, 0.15)

                  RowLayout {
                    id: updateTagRow
                    anchors.centerIn: parent
                    spacing: 3
                    Text {
                      text: "\uf062"
                      font.family: settingsRoot.fontFamily
                      color: "#ffffff"
                      font.pixelSize: 8
                    }
                    Text {
                      text: "Update to v" + settingsRoot.latestVersion
                      color: "#ffffff"
                      font.pixelSize: 9
                      font.weight: Font.DemiBold
                    }
                  }
                }

                // Download pill when missing
                Rectangle {
                  visible: !engineBadgeBox.isInstalled
                  implicitHeight: 16
                  implicitWidth: dlTagText.implicitWidth + 8
                  radius: 3
                  color: settingsRoot.accent

                  Text {
                    id: dlTagText
                    anchors.centerIn: parent
                    text: settingsRoot.isDownloadingCli ? "Downloading..." : "Download"
                    color: "#ffffff"
                    font.pixelSize: 9
                    font.weight: Font.Medium
                  }
                }
              }

              MouseArea {
                id: engineMouse
                anchors.fill: parent
                hoverEnabled: engineBadgeBox.hasUpdate || !engineBadgeBox.isInstalled
                cursorShape: (engineBadgeBox.hasUpdate || !engineBadgeBox.isInstalled) ? Qt.PointingHandCursor : Qt.ArrowCursor
                enabled: !settingsRoot.isDownloadingCli
                onClicked: {
                  if (engineBadgeBox.hasUpdate) {
                    settingsRoot.showReleaseNotes = true
                  } else if (!engineBadgeBox.isInstalled) {
                    settingsRoot.downloadCliRequested()
                  }
                }
              }
            }

            // Keyring Badge
            Rectangle {
              implicitHeight: 24
              implicitWidth: krBadgeRow.implicitWidth + 14
              radius: 4
              color: Qt.rgba(0, 0, 0, 0.2)
              border.color: settingsRoot.borderColor
              border.width: 1

              RowLayout {
                id: krBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Rectangle {
                  implicitWidth: 6
                  implicitHeight: 6
                  radius: 3
                  color: settingsRoot.cliHealth.keyring_available ? "#4ade80" : "#f87171"
                }

                Text {
                  text: "Keyring: " + (settingsRoot.cliHealth.keyring_available ? "Ready" : "Unavailable")
                  color: settingsRoot.foreground
                  font.pixelSize: 10
                }
              }
            }

            // Clipboard Badge
            Rectangle {
              implicitHeight: 24
              implicitWidth: clipBadgeRow.implicitWidth + 14
              radius: 4
              color: Qt.rgba(0, 0, 0, 0.2)
              border.color: settingsRoot.borderColor
              border.width: 1

              RowLayout {
                id: clipBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Rectangle {
                  implicitWidth: 6
                  implicitHeight: 6
                  radius: 3
                  color: settingsRoot.cliHealth.clipboard_available ? "#4ade80" : "#f87171"
                }

                Text {
                  text: "Clipboard: " + (settingsRoot.cliHealth.clipboard_available ? "Ready" : "Missing")
                  color: settingsRoot.foreground
                  font.pixelSize: 10
                }
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
                anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
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
                anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
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
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
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
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
                  text: (settingsRoot.config && settingsRoot.config.clipboard_clear_seconds) ? String(settingsRoot.config.clipboard_clear_seconds) : "30"
                }
              }
            }
          }

          // Log Level Selection
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            Text { text: "Logging Severity Level:"; color: settingsRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
            RowLayout {
              spacing: 4
              Repeater {
                model: ["error", "warn", "info", "debug"]
                Rectangle {
                  id: lvlItem
                  property bool isSelected: settingsRoot.selectedLogLevel === modelData
                  implicitHeight: 24
                  implicitWidth: lvlText.implicitWidth + 14
                  radius: 4
                  color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (lvlMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
                  border.color: isSelected ? settingsRoot.accent : "transparent"
                  border.width: 1

                  Text {
                    id: lvlText
                    anchors.centerIn: parent
                    text: modelData.toUpperCase()
                    color: lvlItem.isSelected ? settingsRoot.accent : (lvlMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
                    font.pixelSize: 11
                    font.weight: lvlItem.isSelected ? Font.DemiBold : Font.Normal
                  }
                  MouseArea {
                    id: lvlMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: { settingsRoot.selectedLogLevel = modelData }
                  }
                }
              }
            }
          }
        }

        // Action Buttons Row
        RowLayout {
          Layout.fillWidth: true
          Item { Layout.fillWidth: true }
          spacing: 8

          // Cancel Button
          Rectangle {
            implicitHeight: 30
            implicitWidth: backBtnText.implicitWidth + 12
            radius: 5
            color: Qt.rgba(0, 0, 0, 0.2)
            border.color: settingsRoot.borderColor
            border.width: 1

            Text {
              id: backBtnText
              anchors.centerIn: parent
              text: "Cancel"
              color: settingsRoot.foreground
              font.pixelSize: 11
              font.weight: Font.Medium
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: settingsRoot.closeRequested()
            }
          }

          // Save Button
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
                  clipboard_clear_seconds: parseInt(clipSecInput.text.trim()) || 30,
                  log_level: settingsRoot.selectedLogLevel
                }
                settingsRoot.saveRequested(payload)
              }
            }
          }
        }
      }
    }

    // ========================================================
    // TAB 2: LOGS & DIAGNOSTICS VIEW
    // ========================================================
    ColumnLayout {
      visible: settingsRoot.activeTab === "logs"
      Layout.fillWidth: true
      Layout.fillHeight: true
      spacing: 8

      // Action Bar: Filter Pills + Copy Diagnostics
      RowLayout {
        Layout.fillWidth: true
        spacing: 6

        // Filter: All
        Rectangle {
          id: fAllItem
          property bool isSelected: settingsRoot.logFilter === "all"
          implicitHeight: 24
          implicitWidth: fAllRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (fAllMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1
          RowLayout {
            id: fAllRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "All"
              color: fAllItem.isSelected ? settingsRoot.accent : (fAllMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: fAllItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: (settingsRoot.logBuffer ? settingsRoot.logBuffer.length : 0)
              color: fAllItem.isSelected ? settingsRoot.accent : Qt.darker(settingsRoot.foreground, 1.8)
              font.pixelSize: 10
            }
          }
          MouseArea {
            id: fAllMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.logFilter = "all" }
          }
        }

        // Filter: Errors
        Rectangle {
          id: fErrItem
          property bool isSelected: settingsRoot.logFilter === "error"
          implicitHeight: 24
          implicitWidth: fErrRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(0.9, 0.2, 0.2, 0.2) : (fErrMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? "#ef4444" : "transparent"
          border.width: 1
          RowLayout {
            id: fErrRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Errors"
              color: fErrItem.isSelected ? "#ef4444" : (fErrMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: fErrItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.errorCount
              color: fErrItem.isSelected ? "#ef4444" : Qt.darker(settingsRoot.foreground, 1.8)
              font.pixelSize: 10
            }
          }
          MouseArea {
            id: fErrMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.logFilter = "error" }
          }
        }

        // Filter: Warnings
        Rectangle {
          id: fWarnItem
          property bool isSelected: settingsRoot.logFilter === "warn"
          implicitHeight: 24
          implicitWidth: fWarnRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(0.9, 0.6, 0.1, 0.2) : (fWarnMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? "#f59e0b" : "transparent"
          border.width: 1
          RowLayout {
            id: fWarnRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Warnings"
              color: fWarnItem.isSelected ? "#f59e0b" : (fWarnMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: fWarnItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.warnCount
              color: fWarnItem.isSelected ? "#f59e0b" : Qt.darker(settingsRoot.foreground, 1.8)
              font.pixelSize: 10
            }
          }
          MouseArea {
            id: fWarnMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.logFilter = "warn" }
          }
        }

        // Filter: Info
        Rectangle {
          id: fInfoItem
          property bool isSelected: settingsRoot.logFilter === "info"
          implicitHeight: 24
          implicitWidth: fInfoRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(0.2, 0.5, 1.0, 0.2) : (fInfoMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? "#3b82f6" : "transparent"
          border.width: 1
          RowLayout {
            id: fInfoRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Info"
              color: fInfoItem.isSelected ? "#3b82f6" : (fInfoMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: fInfoItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.infoCount
              color: fInfoItem.isSelected ? "#3b82f6" : Qt.darker(settingsRoot.foreground, 1.8)
              font.pixelSize: 10
            }
          }
          MouseArea {
            id: fInfoMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.logFilter = "info" }
          }
        }

        // Filter: Debug
        Rectangle {
          id: fDebugItem
          property bool isSelected: settingsRoot.logFilter === "debug"
          implicitHeight: 24
          implicitWidth: fDebugRow.implicitWidth + 14
          radius: 4
          color: isSelected ? Qt.rgba(0.6, 0.4, 0.9, 0.2) : (fDebugMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? "#a855f7" : "transparent"
          border.width: 1
          RowLayout {
            id: fDebugRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Debug"
              color: fDebugItem.isSelected ? "#a855f7" : (fDebugMouse.containsMouse ? settingsRoot.foreground : Qt.darker(settingsRoot.foreground, 1.3))
              font.pixelSize: 11
              font.weight: fDebugItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.debugCount
              color: fDebugItem.isSelected ? "#a855f7" : Qt.darker(settingsRoot.foreground, 1.8)
              font.pixelSize: 10
            }
          }
          MouseArea {
            id: fDebugMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { settingsRoot.logFilter = "debug" }
          }
        }

        Item { Layout.fillWidth: true }

        // Clear Logs Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: clrLogText.implicitWidth + 12
          radius: 3
          color: Qt.rgba(0, 0, 0, 0.2)
          border.color: settingsRoot.borderColor
          border.width: 1
          RowLayout {
            id: clrLogText
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "\uf1f8"
              font.family: settingsRoot.fontFamily
              color: Qt.darker(settingsRoot.foreground, 1.5)
              font.pixelSize: 9
            }
            Text {
              text: "Clear"
              color: Qt.darker(settingsRoot.foreground, 1.5)
              font.pixelSize: 10
            }
          }
          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: settingsRoot.clearLogsRequested()
          }
        }

        // Copy Diagnostics Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: copyDiagRow.implicitWidth + 14
          radius: 3
          color: Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2)
          border.color: settingsRoot.accent
          border.width: 1

          RowLayout {
            id: copyDiagRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "\uf0c5"
              font.family: settingsRoot.fontFamily
              color: settingsRoot.accent
              font.pixelSize: 10
            }
            Text {
              text: "Copy Diagnostics"
              color: settingsRoot.foreground
              font.pixelSize: 10
              font.weight: Font.Medium
            }
          }
          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: settingsRoot.copyDiagnosticsRequested()
          }
        }
      }

      // Log Messages List
      Rectangle {
        Layout.fillWidth: true
        Layout.fillHeight: true
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.3)
        border.color: settingsRoot.borderColor
        border.width: 1

        ListView {
          id: logListView
          anchors.fill: parent
          anchors.margins: 6
          clip: true
          model: settingsRoot.getFilteredLogs()
          spacing: 4
          ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
          }

          delegate: Rectangle {
            width: logListView.width - 8
            implicitHeight: Math.max(26, logMsgText.implicitHeight + 12)
            radius: 3
            color: (modelData.level === "ERROR") ? Qt.rgba(0.9, 0.2, 0.2, 0.12) : ((modelData.level === "WARN") ? Qt.rgba(0.9, 0.6, 0.1, 0.08) : Qt.rgba(1, 1, 1, 0.03))

            Row {
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.top: parent.top
              anchors.margins: 6
              spacing: 8

              // 1. Timestamp
              Text {
                width: 58
                text: (modelData.timestamp ? (modelData.timestamp.indexOf("T") !== -1 ? modelData.timestamp.split("T")[1].replace("Z", "") : modelData.timestamp) : "")
                color: Qt.darker(settingsRoot.foreground, 2.0)
                font.family: "monospace"
                font.pixelSize: 9
              }

              // 2. Badge
              Rectangle {
                width: 44
                height: 16
                radius: 2
                color: (modelData.level === "ERROR") ? "#ef4444" : ((modelData.level === "WARN") ? "#f59e0b" : ((modelData.level === "INFO") ? "#3b82f6" : "#6b7280"))
                Text {
                  anchors.centerIn: parent
                  text: modelData.level
                  color: "#ffffff"
                  font.family: "monospace"
                  font.pixelSize: 8
                  font.weight: Font.Bold
                }
              }

              // 3. Source Prefix
              Text {
                id: srcLabel
                text: "[" + modelData.source + "]"
                color: settingsRoot.accent
                font.family: "monospace"
                font.pixelSize: 9
                font.weight: Font.Bold
              }

              // 4. Message Content
              Text {
                id: logMsgText
                width: Math.max(80, parent.width - 58 - 44 - srcLabel.implicitWidth - 24)
                text: modelData.message
                color: settingsRoot.foreground
                font.family: "monospace"
                font.pixelSize: 10
                wrapMode: Text.WrapAnywhere
              }
            }
          }

          // Empty state placeholder
          Text {
            visible: settingsRoot.getFilteredLogs().length === 0
            anchors.centerIn: parent
            text: "No log entries recorded for this filter."
            color: Qt.darker(settingsRoot.foreground, 2.0)
            font.pixelSize: 11
          }
        }
      }
    }
  }

  // Release Notes Modal
  ReleaseNotesModal {
    active: settingsRoot.showReleaseNotes
    version: settingsRoot.latestVersion
    releaseTitle: settingsRoot.latestReleaseTitle
    releaseNotes: settingsRoot.latestReleaseNotes
    releaseUrl: settingsRoot.latestReleaseUrl
    isDownloadingCli: settingsRoot.isDownloadingCli
    foreground: settingsRoot.foreground
    accent: settingsRoot.accent
    borderColor: settingsRoot.borderColor
    fontFamily: settingsRoot.fontFamily
    onCloseRequested: settingsRoot.showReleaseNotes = false
    onUpdateRequested: {
      settingsRoot.showReleaseNotes = false
      settingsRoot.downloadCliRequested()
    }
  }
}

