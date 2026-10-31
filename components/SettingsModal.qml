import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import "./IconPolicy.js" as IconPolicy
import qs.Commons
import qs.Commons as Commons

Item {
  id: settingsRoot

  property var config: ({})
  property var cliHealth: ({})
  property string engineSource: "aur"
  property string enginePackage: ""
  property var logBuffer: []
  property bool isInstallingDependencies: false
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
  property color foreground: Commons.Color.menu.text
  property color accent: Commons.Color.menu.selectedText
  property color borderColor: Commons.Color.menu.border
  property color muted: Commons.Color.muted
  // Label/glyph color for accent-filled controls. The accent fill itself can
  // be light or dark per theme, so pick the contrasting pole by luminance —
  // Commons.Color.menu.selectedText cannot be used here because it is what
  // fills those controls (root maps accent := Color.menu.selectedText).
  readonly property color textOnAccent: StatusPalette.textOn(accent)
  property string fontFamily: ""
  property bool checkUpdatesChecked: true
  readonly property alias confirmRepeater: confirmRepeater
  readonly property alias logSeverityRepeater: logSeverityRepeater

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
  property bool showWebsiteIconsChecked: true
  property bool rememberLastSearchChecked: false
  property bool enableMtlsChecked: false

  readonly property string curServerUrl: (sUrlInput && sUrlInput.text.trim()) ? sUrlInput.text.trim() : ((config && config.server_url) ? config.server_url : "")
  readonly property bool isOfficialServer: IconPolicy.isOfficialServer(curServerUrl)
  readonly property bool certMatchesServer: {
    if (!config || !config.client_cert_server || !config.client_cert_path) return false
    if (isOfficialServer) return false
    return IconPolicy.isSameOrigin(curServerUrl, config.client_cert_server)
  }

  onCertMatchesServerChanged: {
    enableMtlsChecked = Boolean(config && config.client_cert_path && settingsRoot.certMatchesServer)
    if (clientCertInput) {
      clientCertInput.text = settingsRoot.certMatchesServer ? ((config && config.client_cert_path) || "") : ""
    }
    if (clientKeyInput) {
      clientKeyInput.text = settingsRoot.certMatchesServer ? ((config && config.client_key_path) || "") : ""
    }
  }
  property bool sshAgentChecked: false
  property string sshAgentConfirm: "first-use"

  onConfigChanged: {
    if (config) checkUpdatesChecked = (config.check_updates !== false)
    if (config) showWebsiteIconsChecked = (config.show_website_icons !== false)
    if (config) rememberLastSearchChecked = (config.remember_last_search === true)
    if (config) enableMtlsChecked = Boolean(config.client_cert_path && settingsRoot.certMatchesServer)
    if (sUrlInput && config && config.server_url) {
      sUrlInput.text = config.server_url
    }
    if (clientCertInput) {
      clientCertInput.text = settingsRoot.certMatchesServer ? ((config && config.client_cert_path) || "") : ""
    }
    if (clientKeyInput) {
      clientKeyInput.text = settingsRoot.certMatchesServer ? ((config && config.client_key_path) || "") : ""
    }
    if (config) sshAgentChecked = (config.ssh_agent_enabled === true)
    if (config && config.ssh_agent_confirm) sshAgentConfirm = config.ssh_agent_confirm
  }

  function buildPayload() {
    var isOfficial = settingsRoot.isOfficialServer
    var useMtls = !isOfficial && settingsRoot.enableMtlsChecked
    var certPath = useMtls ? (clientCertInput.visible ? clientCertInput.text.trim() : "") : ""
    var keyPath = useMtls ? (clientKeyInput.visible ? clientKeyInput.text.trim() : "") : ""

    return {
      server_url: sUrlInput.text.trim() || "https://vault.bitwarden.com",
      identity_url: idUrlInput.text.trim(),
      client_cert_path: certPath,
      client_key_path: keyPath,
      download_dir: dlDirInput.text.trim() || "~/Downloads",
      auto_lock_minutes: isNaN(parseInt(lockMinInput.text.trim())) ? 15 : Math.max(0, parseInt(lockMinInput.text.trim())),
      clipboard_clear_seconds: isNaN(parseInt(clipSecInput.text.trim())) ? 30 : Math.max(0, parseInt(clipSecInput.text.trim())),
      max_attachment_size_mb: isNaN(parseInt(maxAttSizeInput.text.trim())) || parseInt(maxAttSizeInput.text.trim()) <= 0 ? 500 : parseInt(maxAttSizeInput.text.trim()),
      log_level: settingsRoot.selectedLogLevel,
      show_website_icons: settingsRoot.showWebsiteIconsChecked,
      check_updates: settingsRoot.checkUpdatesChecked,
      remember_last_search: settingsRoot.rememberLastSearchChecked,
      ssh_agent_enabled: settingsRoot.sshAgentChecked,
      ssh_agent_confirm: settingsRoot.sshAgentConfirm
    }
  }

  signal saveRequested(var newSettings)
  signal closeRequested()
  signal refreshHealthRequested()
  signal checkUpdateRequested()
  signal installPackageRequested(string pkgName)
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
          font.pixelSize: Style.font.subtitle
        }
        Text {
          text: "Settings & Diagnostics"
          color: settingsRoot.foreground
          font.pixelSize: Style.font.subtitle
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
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (genMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1

          Text {
            id: genTabText
            anchors.centerIn: parent
            text: "General"
            color: genTabItem.isSelected ? settingsRoot.accent : (genMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
            font.pixelSize: Style.font.bodySmall
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
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (logsMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1

          RowLayout {
            id: logsTabRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Logs & Diagnostics"
              color: logsTabItem.isSelected ? settingsRoot.accent : (logsMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: logsTabItem.isSelected ? Font.DemiBold : Font.Normal
            }
            // Error Badge if any errors exist
            Rectangle {
              visible: settingsRoot.errorCount > 0
              implicitHeight: 14
              implicitWidth: Math.max(14, errBadgeText.implicitWidth + 6)
              radius: 7
              color: StatusPalette.danger
              Text {
                id: errBadgeText
                anchors.centerIn: parent
                text: String(settingsRoot.errorCount)
                color: StatusPalette.textOnTint(StatusPalette.danger, 1, Commons.Color.popups.background)
                font.pixelSize: Style.fontPx(0.75)
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
            Text { text: "ENGINE STATUS & HEALTH"; color: settingsRoot.muted; font.pixelSize: Style.font.caption; font.weight: Font.DemiBold }
            Item { Layout.fillWidth: true }

            // Check Update Button
            Rectangle {
              implicitHeight: 20
              implicitWidth: chkUpText.implicitWidth + 10
              radius: 3
              color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
              border.color: settingsRoot.borderColor
              border.width: 1

              Text {
                id: chkUpText
                anchors.centerIn: parent
                text: settingsRoot.isCheckingUpdate ? "Checking..." : (settingsRoot.justCheckedLatest ? "Latest" : "Check Update")
                color: settingsRoot.justCheckedLatest ? StatusPalette.ok : settingsRoot.accent
                font.pixelSize: Style.font.caption
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
              color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
              border.color: settingsRoot.borderColor
              border.width: 1

              Text { id: refHText; anchors.centerIn: parent; text: "Refresh"; color: settingsRoot.accent; font.pixelSize: Style.font.caption }
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
              color: engineMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.12) : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
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
                  color: engineBadgeBox.isInstalled ? StatusPalette.ok : StatusPalette.fail
                }

                Text {
                  text: "Engine: " + (!engineBadgeBox.isInstalled ? "Missing" : (settingsRoot.cliHealth.version || "Ready"))
                  color: settingsRoot.foreground
                  font.pixelSize: Style.font.caption
                }

                // Source badge (AUR vs System)
                Rectangle {
                  visible: engineBadgeBox.isInstalled && Boolean(settingsRoot.engineSource)
                  implicitHeight: 16
                  implicitWidth: engineSourceText.implicitWidth + 10
                  radius: 3
                  color: (settingsRoot.engineSource.toLowerCase() === "aur") ? StatusPalette.tint(StatusPalette.aur, 0.2) : StatusPalette.tint(StatusPalette.system, 0.2)
                  border.color: (settingsRoot.engineSource.toLowerCase() === "aur") ? StatusPalette.tint(StatusPalette.aur, 0.4) : StatusPalette.tint(StatusPalette.system, 0.4)
                  border.width: 1

                  Text {
                    id: engineSourceText
                    anchors.centerIn: parent
                    text: {
                      if (settingsRoot.engineSource.toLowerCase() === "aur") {
                        return settingsRoot.enginePackage ? ("AUR: " + settingsRoot.enginePackage) : "AUR"
                      }
                      return settingsRoot.engineSource ? (settingsRoot.engineSource.charAt(0).toUpperCase() + settingsRoot.engineSource.slice(1)) : "System"
                    }
                    color: (settingsRoot.engineSource.toLowerCase() === "aur") ? StatusPalette.aur : StatusPalette.system
                    font.pixelSize: Style.fontPx(0.75)
                    font.weight: Font.DemiBold
                  }
                }

                // Inline update tag when update is available
                Rectangle {
                  visible: engineBadgeBox.hasUpdate
                  implicitHeight: 16
                  implicitWidth: updateTagRow.implicitWidth + 8
                  radius: 3
                  color: StatusPalette.tint(StatusPalette.update, 0.15)

                  RowLayout {
                    id: updateTagRow
                    anchors.centerIn: parent
                    spacing: 3
                    Text {
                      text: "\uf062"
                      font.family: settingsRoot.fontFamily
                      color: StatusPalette.textOnTint(StatusPalette.update, 0.15, Commons.Color.popups.background)
                      font.pixelSize: Style.fontPx(0.667)
                    }
                    Text {
                      id: updateTagLabel
                      text: "Update (AUR)"
                      color: StatusPalette.textOnTint(StatusPalette.update, 0.15, Commons.Color.popups.background)
                      font.pixelSize: Style.fontPx(0.75)
                      font.weight: Font.DemiBold
                    }
                  }
                }

                // Install pill when missing
                Rectangle {
                  visible: !engineBadgeBox.isInstalled
                  implicitHeight: 16
                  implicitWidth: dlTagText.implicitWidth + 8
                  radius: 3
                  color: settingsRoot.accent

                  Text {
                    id: dlTagText
                    anchors.centerIn: parent
                    text: settingsRoot.isInstallingDependencies ? "Installing..." : "Install"
                    color: settingsRoot.textOnAccent
                    font.pixelSize: Style.fontPx(0.75)
                    font.weight: Font.Medium
                  }
                }
              }

              MouseArea {
                id: engineMouse
                anchors.fill: parent
                hoverEnabled: engineBadgeBox.hasUpdate || !engineBadgeBox.isInstalled
                cursorShape: (engineBadgeBox.hasUpdate || !engineBadgeBox.isInstalled) ? Qt.PointingHandCursor : Qt.ArrowCursor
                enabled: !settingsRoot.isInstallingDependencies
                onClicked: {
                  if (engineBadgeBox.hasUpdate) {
                    settingsRoot.installPackageRequested(settingsRoot.enginePackage || "omawarden")
                  } else if (!engineBadgeBox.isInstalled) {
                    settingsRoot.installPackageRequested("omawarden")
                  }
                }
              }
            }

            // Keyring Badge
            Rectangle {
              implicitHeight: 24
              implicitWidth: krBadgeRow.implicitWidth + 14
              radius: 4
              color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
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
                  color: settingsRoot.cliHealth.keyring_available ? StatusPalette.ok : StatusPalette.fail
                }

                Text {
                  text: "Keyring: " + (settingsRoot.cliHealth.keyring_available ? "Ready" : "Unavailable")
                  color: settingsRoot.foreground
                  font.pixelSize: Style.font.caption
                }
              }
            }

            // Clipboard Badge
            Rectangle {
              implicitHeight: 24
              implicitWidth: clipBadgeRow.implicitWidth + 14
              radius: 4
              color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
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
                  color: settingsRoot.cliHealth.clipboard_available ? StatusPalette.ok : StatusPalette.fail
                }

                Text {
                  text: "Clipboard: " + (settingsRoot.cliHealth.clipboard_available ? "Ready" : "Missing")
                  color: settingsRoot.foreground
                  font.pixelSize: Style.font.caption
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
            Text { text: "Bitwarden / Vaultwarden Server URL:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: sUrlInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: sUrlInput
                anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                clip: true
                activeFocusOnTab: true
                KeyNavigation.tab: idUrlInput
                KeyNavigation.backtab: maxAttSizeInput
                text: (settingsRoot.config && settingsRoot.config.server_url) ? settingsRoot.config.server_url : "https://vault.bitwarden.com"
              }
            }
          }

          // Identity URL
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 4
              Text { text: "Identity URL:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Text { text: "(Optional override, e.g. https://identity.bitwarden.com)"; color: settingsRoot.muted; font.pixelSize: Style.font.caption }
            }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: idUrlInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: idUrlInput
                anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                clip: true
                activeFocusOnTab: true
                KeyNavigation.tab: (!settingsRoot.isOfficialServer && settingsRoot.enableMtlsChecked) ? clientCertInput : dlDirInput
                KeyNavigation.backtab: sUrlInput
                text: (settingsRoot.config && settingsRoot.config.identity_url) ? settingsRoot.config.identity_url : ""
              }
              Text {
                anchors.left: parent.left; anchors.leftMargin: 10; anchors.verticalCenter: parent.verticalCenter
                text: "Auto (default: identity.bitwarden.com or /identity)"
                color: settingsRoot.muted
                font.family: "sans-serif"; font.pixelSize: Style.font.bodySmall
                visible: idUrlInput.text.length === 0
              }
            }
          }

          // Optional mTLS Toggle for Self-Hosted Servers
          RowLayout {
            visible: !settingsRoot.isOfficialServer
            spacing: 6
            Rectangle {
              width: 14; height: 14; radius: 3
              color: settingsRoot.enableMtlsChecked ? settingsRoot.accent : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10)
              border.color: settingsRoot.borderColor; border.width: 1
              Text {
                anchors.centerIn: parent
                visible: settingsRoot.enableMtlsChecked
                text: "\uf00c"
                font.family: settingsRoot.fontFamily
                color: settingsRoot.textOnAccent
                font.pixelSize: Style.fontPx(0.75)
              }
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: settingsRoot.enableMtlsChecked = !settingsRoot.enableMtlsChecked
              }
            }
            Text {
              text: "Use mTLS Client Certificate (for edge gateways)"
              color: settingsRoot.foreground
              font.pixelSize: Style.font.bodySmall
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: settingsRoot.enableMtlsChecked = !settingsRoot.enableMtlsChecked
              }
            }
          }

          // mTLS Client Certificate Path (Self-Hosted Only)
          ColumnLayout {
            visible: !settingsRoot.isOfficialServer && settingsRoot.enableMtlsChecked
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 4
              Text { text: "mTLS Client Certificate Path:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Text { text: "(Optional, for self-hosted instances with mTLS gateway)"; color: settingsRoot.muted; font.pixelSize: Style.font.caption }
            }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: clientCertInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: clientCertInput
                anchors.left: parent.left; anchors.right: settingsCertBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                clip: true
                activeFocusOnTab: true
                KeyNavigation.tab: clientKeyInput
                KeyNavigation.backtab: idUrlInput
                text: settingsRoot.certMatchesServer ? ((settingsRoot.config && settingsRoot.config.client_cert_path) || "") : ""
              }
              Text {
                anchors.left: parent.left; anchors.right: settingsCertBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                text: "e.g. /home/user/.certs/client.crt or client.pem"
                color: settingsRoot.muted
                font.family: "sans-serif"; font.pixelSize: Style.font.bodySmall
                elide: Text.ElideRight
                visible: clientCertInput.text.length === 0
              }
              GhostIconButton {
                id: settingsCertBrowseBtn
                anchors.right: parent.right
                anchors.rightMargin: 5
                anchors.verticalCenter: parent.verticalCenter
                iconText: "\uf07b"
                fontFamily: settingsRoot.fontFamily
                tooltip: "Browse certificate file"
                onClicked: settingsCertFileDialog.open()
              }
            }
          }

          // mTLS Client Private Key Path (Self-Hosted Only)
          ColumnLayout {
            visible: !settingsRoot.isOfficialServer && settingsRoot.enableMtlsChecked
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 4
              Text { text: "mTLS Client Private Key Path:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Text { text: "(Optional if merged in PEM, file permissions must be 0600 or 0400)"; color: settingsRoot.muted; font.pixelSize: Style.font.caption }
            }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: clientKeyInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: clientKeyInput
                anchors.left: parent.left; anchors.right: settingsKeyBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                clip: true
                activeFocusOnTab: true
                KeyNavigation.tab: dlDirInput
                KeyNavigation.backtab: clientCertInput
                text: settingsRoot.certMatchesServer ? ((settingsRoot.config && settingsRoot.config.client_key_path) || "") : ""
              }
              Text {
                anchors.left: parent.left; anchors.right: settingsKeyBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                text: "e.g. /home/user/.certs/client.key"
                color: settingsRoot.muted
                font.family: "sans-serif"; font.pixelSize: Style.font.bodySmall
                elide: Text.ElideRight
                visible: clientKeyInput.text.length === 0
              }
              GhostIconButton {
                id: settingsKeyBrowseBtn
                anchors.right: parent.right
                anchors.rightMargin: 5
                anchors.verticalCenter: parent.verticalCenter
                iconText: "\uf07b"
                fontFamily: settingsRoot.fontFamily
                tooltip: "Browse private key file"
                onClicked: settingsKeyFileDialog.open()
              }
            }
          }

          FileDialog {
            id: settingsCertFileDialog
            title: "Select Client Certificate (.pem / .crt)"
            fileMode: FileDialog.OpenFile
            nameFilters: ["Certificate files (*.crt *.pem)", "All files (*)"]
            onAccepted: {
              clientCertInput.text = IconPolicy.urlToLocalPath(selectedFile)
            }
          }

          FileDialog {
            id: settingsKeyFileDialog
            title: "Select Client Private Key (.key / .pem)"
            fileMode: FileDialog.OpenFile
            nameFilters: ["Private key files (*.key *.pem)", "All files (*)"]
            onAccepted: {
              clientKeyInput.text = IconPolicy.urlToLocalPath(selectedFile)
            }
          }

          // Download Directory
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            Text { text: "Attachment Download Directory:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: dlDirInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
              TextInput {
                id: dlDirInput
                anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                clip: true
                activeFocusOnTab: true
                KeyNavigation.tab: lockMinInput
                KeyNavigation.backtab: (!settingsRoot.isOfficialServer && settingsRoot.enableMtlsChecked) ? clientKeyInput : idUrlInput
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
              Text { text: "Auto-lock Timeout (Minutes):"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: lockMinInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
                TextInput {
                  id: lockMinInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: clipSecInput
                  KeyNavigation.backtab: dlDirInput
                  inputMethodHints: Qt.ImhDigitsOnly
                  validator: IntValidator { bottom: 0; top: 100000 }
                  text: (settingsRoot.config && settingsRoot.config.auto_lock_minutes !== undefined) ? String(settingsRoot.config.auto_lock_minutes) : "15"
                }
              }
            }

            // Clipboard TTL Seconds
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Clipboard Auto-Clear (Seconds):"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: clipSecInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
                TextInput {
                  id: clipSecInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: maxAttSizeInput
                  KeyNavigation.backtab: lockMinInput
                  inputMethodHints: Qt.ImhDigitsOnly
                  validator: IntValidator { bottom: 0; top: 100000 }
                  text: (settingsRoot.config && settingsRoot.config.clipboard_clear_seconds !== undefined) ? String(settingsRoot.config.clipboard_clear_seconds) : "30"
                }
              }
            }

            // Max Attachment Size (MB)
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Max Attachment (MB):"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.08); border.color: maxAttSizeInput.activeFocus ? settingsRoot.accent : settingsRoot.borderColor; border.width: 1
                TextInput {
                  id: maxAttSizeInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: settingsRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: sUrlInput
                  KeyNavigation.backtab: clipSecInput
                  inputMethodHints: Qt.ImhDigitsOnly
                  validator: IntValidator { bottom: 1; top: 100000 }
                  text: (settingsRoot.config && settingsRoot.config.max_attachment_size_mb !== undefined) ? String(settingsRoot.config.max_attachment_size_mb) : "500"
                }
              }
            }
          }

          // Show Website Icons Checkbox
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 6
              Rectangle {
                width: 14; height: 14; radius: 3; color: settingsRoot.showWebsiteIconsChecked ? settingsRoot.accent : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10); border.color: settingsRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: settingsRoot.showWebsiteIconsChecked
                  text: "\uf00c"
                  font.family: settingsRoot.fontFamily
                  color: settingsRoot.textOnAccent
                  font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsRoot.showWebsiteIconsChecked = !settingsRoot.showWebsiteIconsChecked }
              }
              Text { text: "Show Website Icons"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }
            Text {
              readonly property string curServerUrl: (sUrlInput && sUrlInput.text.trim()) ? sUrlInput.text.trim() : ((settingsRoot.config && settingsRoot.config.server_url) ? settingsRoot.config.server_url : "")
              readonly property bool isOfficial: IconPolicy.isOfficialServer(curServerUrl)
              readonly property string serverHost: IconPolicy.extractHost(curServerUrl)
              text: isOfficial
                    ? "Fetches icons from icons.bitwarden.net, revealing your saved sites to Bitwarden."
                    : ("Fetches icons directly from your vault server (" + (serverHost || "self-hosted") + ").")
              color: settingsRoot.muted
              font.pixelSize: Style.font.caption
              Layout.fillWidth: true
              wrapMode: Text.WordWrap
            }
          }

          // Automatic Update Check Toggle
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 6
              Rectangle {
                width: 14; height: 14; radius: 3; color: settingsRoot.checkUpdatesChecked ? settingsRoot.accent : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10); border.color: settingsRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: settingsRoot.checkUpdatesChecked
                  text: "\uf00c"
                  font.family: settingsRoot.fontFamily
                  color: settingsRoot.textOnAccent
                  font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsRoot.checkUpdatesChecked = !settingsRoot.checkUpdatesChecked }
              }
              Text { text: "Check For Updates"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }
            Text {
              Layout.fillWidth: true
              text: "Contacts github.com on startup. Turn off if omawarden is managed by a package manager."
              color: settingsRoot.muted
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // Remember Last Search Toggle
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 6
              Rectangle {
                width: 14; height: 14; radius: 3; color: settingsRoot.rememberLastSearchChecked ? settingsRoot.accent : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10); border.color: settingsRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: settingsRoot.rememberLastSearchChecked
                  text: "\uf00c"
                  font.family: settingsRoot.fontFamily
                  color: settingsRoot.textOnAccent
                  font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsRoot.rememberLastSearchChecked = !settingsRoot.rememberLastSearchChecked }
              }
              Text { text: "Remember Last Search State"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }
            Text {
              Layout.fillWidth: true
              text: "Retains previous search query, category, and selection when reopening while vault is unlocked."
              color: settingsRoot.muted
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // SSH Agent Toggle
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
              spacing: 6
              Rectangle {
                width: 14; height: 14; radius: 3; color: settingsRoot.sshAgentChecked ? settingsRoot.accent : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10); border.color: settingsRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: settingsRoot.sshAgentChecked
                  text: "\uf00c"
                  font.family: settingsRoot.fontFamily
                  color: settingsRoot.textOnAccent
                  font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: settingsRoot.sshAgentChecked = !settingsRoot.sshAgentChecked }
              }
              Text { text: "SSH Agent"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }
            Text {
              Layout.fillWidth: true
              text: "Serves your vault's SSH keys to ssh and git without writing them to disk. Point SSH_AUTH_SOCK at $XDG_RUNTIME_DIR/omawarden-ssh-agent.sock."
              color: settingsRoot.muted
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
            RowLayout {
              visible: settingsRoot.sshAgentChecked
              Layout.topMargin: 2
              spacing: 4
              Text { text: "Confirm signatures:"; color: settingsRoot.muted; font.pixelSize: Style.font.caption }
              Repeater {
                id: confirmRepeater
                model: [["always", "Every time"], ["first-use", "First use"], ["never", "Never"]]
                Rectangle {
                  id: confirmItem
                  required property var modelData
                  readonly property bool chosen: settingsRoot.sshAgentConfirm === modelData[0]
                  implicitHeight: 24
                  implicitWidth: confirmLabel.implicitWidth + 14
                  radius: 4
                  color: chosen ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (confirmMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
                  border.color: chosen ? settingsRoot.accent : "transparent"
                  border.width: 1
                  Text {
                    id: confirmLabel
                    anchors.centerIn: parent
                    text: modelData[1]
                    color: confirmItem.chosen ? settingsRoot.accent : (confirmMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
                    font.pixelSize: Style.font.bodySmall
                    font.weight: confirmItem.chosen ? Font.DemiBold : Font.Normal
                  }
                  MouseArea {
                    id: confirmMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: settingsRoot.sshAgentConfirm = modelData[0]
                  }
                }
              }
            }
          }

          // Log Level Selection
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            Text { text: "Logging Severity Level:"; color: settingsRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
            RowLayout {
              spacing: 4
              Repeater {
                id: logSeverityRepeater
                model: ["error", "warn", "info", "debug"]
                Rectangle {
                  id: lvlItem
                  property bool isSelected: settingsRoot.selectedLogLevel === modelData
                  implicitHeight: 24
                  implicitWidth: lvlText.implicitWidth + 14
                  radius: 4
                  color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (lvlMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
                  border.color: isSelected ? settingsRoot.accent : "transparent"
                  border.width: 1

                  Text {
                    id: lvlText
                    anchors.centerIn: parent
                    text: modelData.toUpperCase()
                    color: lvlItem.isSelected ? settingsRoot.accent : (lvlMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
                    font.pixelSize: Style.font.bodySmall
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
            color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
            border.color: settingsRoot.borderColor
            border.width: 1

            Text {
              id: backBtnText
              anchors.centerIn: parent
              text: "Cancel"
              color: settingsRoot.foreground
              font.pixelSize: Style.font.bodySmall
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
              color: settingsRoot.textOnAccent
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: settingsRoot.saveRequested(settingsRoot.buildPayload())
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
          color: isSelected ? Qt.rgba(settingsRoot.accent.r, settingsRoot.accent.g, settingsRoot.accent.b, 0.2) : (fAllMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? settingsRoot.accent : "transparent"
          border.width: 1
          RowLayout {
            id: fAllRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "All"
              color: fAllItem.isSelected ? settingsRoot.accent : (fAllMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: fAllItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: (settingsRoot.logBuffer ? settingsRoot.logBuffer.length : 0)
              color: fAllItem.isSelected ? settingsRoot.accent : settingsRoot.muted
              font.pixelSize: Style.font.caption
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
          color: isSelected ? StatusPalette.tint(StatusPalette.error, 0.2) : (fErrMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? StatusPalette.error : "transparent"
          border.width: 1
          RowLayout {
            id: fErrRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Errors"
              color: fErrItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.error, 0.2, Commons.Color.popups.background) : (fErrMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: fErrItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.errorCount
              color: fErrItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.error, 0.2, Commons.Color.popups.background) : settingsRoot.muted
              font.pixelSize: Style.font.caption
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
          color: isSelected ? StatusPalette.tint(StatusPalette.warn, 0.2) : (fWarnMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? StatusPalette.warn : "transparent"
          border.width: 1
          RowLayout {
            id: fWarnRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Warnings"
              color: fWarnItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.warn, 0.2, Commons.Color.popups.background) : (fWarnMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: fWarnItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.warnCount
              color: fWarnItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.warn, 0.2, Commons.Color.popups.background) : settingsRoot.muted
              font.pixelSize: Style.font.caption
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
          color: isSelected ? StatusPalette.tint(StatusPalette.info, 0.2) : (fInfoMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? StatusPalette.info : "transparent"
          border.width: 1
          RowLayout {
            id: fInfoRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Info"
              color: fInfoItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.info, 0.2, Commons.Color.popups.background) : (fInfoMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: fInfoItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.infoCount
              color: fInfoItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.info, 0.2, Commons.Color.popups.background) : settingsRoot.muted
              font.pixelSize: Style.font.caption
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
          color: isSelected ? StatusPalette.tint(StatusPalette.debug, 0.2) : (fDebugMouse.containsMouse ? Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? StatusPalette.debug : "transparent"
          border.width: 1
          RowLayout {
            id: fDebugRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "Debug"
              color: fDebugItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.debug, 0.2, Commons.Color.popups.background) : (fDebugMouse.containsMouse ? settingsRoot.foreground : settingsRoot.muted)
              font.pixelSize: Style.font.bodySmall
              font.weight: fDebugItem.isSelected ? Font.DemiBold : Font.Normal
            }
            Text {
              text: settingsRoot.debugCount
              color: fDebugItem.isSelected ? StatusPalette.labelOnTint(StatusPalette.debug, 0.2, Commons.Color.popups.background) : settingsRoot.muted
              font.pixelSize: Style.font.caption
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
          color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.06)
          border.color: settingsRoot.borderColor
          border.width: 1
          RowLayout {
            id: clrLogText
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "\uf1f8"
              font.family: settingsRoot.fontFamily
              color: settingsRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
            Text {
              text: "Clear"
              color: settingsRoot.muted
              font.pixelSize: Style.font.caption
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
              font.pixelSize: Style.font.caption
            }
            Text {
              text: "Copy Diagnostics"
              color: settingsRoot.foreground
              font.pixelSize: Style.font.caption
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
        color: Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.10)
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
            color: (modelData.level === "ERROR") ? StatusPalette.tint(StatusPalette.error, 0.12) : ((modelData.level === "WARN") ? StatusPalette.tint(StatusPalette.warn, 0.08) : Qt.rgba(settingsRoot.foreground.r, settingsRoot.foreground.g, settingsRoot.foreground.b, 0.03))

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
                color: settingsRoot.muted
                font.family: "monospace"
                font.pixelSize: Style.fontPx(0.75)
              }

              // 2. Badge
              Rectangle {
                width: 44
                height: 16
                radius: 2
                color: StatusPalette.levelColor(modelData.level)
                Text {
                  anchors.centerIn: parent
                  text: modelData.level
                  color: StatusPalette.textOnTint(StatusPalette.levelColor(modelData.level), 1, Commons.Color.popups.background)
                  font.family: "monospace"
                  font.pixelSize: Style.fontPx(0.667)
                  font.weight: Font.Bold
                }
              }

              // 3. Source Prefix
              Text {
                id: srcLabel
                text: "[" + modelData.source + "]"
                color: settingsRoot.accent
                font.family: "monospace"
                font.pixelSize: Style.fontPx(0.75)
                font.weight: Font.Bold
              }

              // 4. Message Content
              Text {
                id: logMsgText
                width: Math.max(80, parent.width - 58 - 44 - srcLabel.implicitWidth - 24)
                text: modelData.message
                color: settingsRoot.foreground
                font.family: "monospace"
                font.pixelSize: Style.font.caption
                wrapMode: Text.WrapAnywhere
              }
            }
          }

          // Empty state placeholder
          Text {
            visible: settingsRoot.getFilteredLogs().length === 0
            anchors.centerIn: parent
            text: "No log entries recorded for this filter."
            color: settingsRoot.muted
            font.pixelSize: Style.font.bodySmall
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
    engineSource: settingsRoot.engineSource
    enginePackage: settingsRoot.enginePackage
    isDownloadingCli: settingsRoot.isInstallingDependencies
    foreground: settingsRoot.foreground
    accent: settingsRoot.accent
    borderColor: settingsRoot.borderColor
    fontFamily: settingsRoot.fontFamily
    onCloseRequested: settingsRoot.showReleaseNotes = false
    onUpdateRequested: {
      settingsRoot.showReleaseNotes = false
      settingsRoot.installPackageRequested(settingsRoot.enginePackage || "omawarden")
    }
  }
}

