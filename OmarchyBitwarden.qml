import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui

Item {
  id: root

  property var shell: null
  property var manifest: null
  property bool opened: false
  property string helperPath: {
    var custom = Quickshell.env("OMARCHY_BITWARDEN_HELPER")
    if (custom) return custom
    var pluginDir = Quickshell.env("XDG_CONFIG_HOME") || (Quickshell.env("HOME") + "/.config")
    return pluginDir + "/omarchy/plugins/icyleaf.bitwarden/bin/bitwarden-helper"
  }

  // Configuration & CLI Health State
  property var config: ({
    server_url: "https://vault.bitwarden.com",
    bw_path: "bw",
    auto_lock_minutes: 15,
    clipboard_clear_seconds: 30
  })

  property var cliHealth: ({
    installed: false,
    ok: false,
    version: "",
    executable_path: "",
    error: null
  })

  property string currentView: "search" // "search" | "settings"
  property string statusMessage: ""
  property bool isBusy: false

  readonly property color background: Color.menu.background
  readonly property color foreground: Color.menu.text
  readonly property color border: Color.menu.border
  readonly property color accent: Color.menu.selectedText
  readonly property color selectedBackground: Color.menu.selectedBackground
  readonly property string fontFamily: Style.font.menuFamily

  function open(payloadJson) {
    root.opened = true
    root.refreshHealth()
    root.refreshConfig()
  }

  function close() {
    root.opened = false
  }

  function dismiss() {
    root.close()
    if (root.shell && typeof root.shell.hide === "function") {
      root.shell.hide((root.manifest && root.manifest.id) || "icyleaf.bitwarden")
    }
  }

  function toggle() {
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  function refreshConfig() {
    configGetProc.command = [root.helperPath, "config", "get"]
    configGetProc.running = true
  }

  function refreshHealth() {
    healthProc.command = [root.helperPath, "health"]
    healthProc.running = true
  }

  function saveSettings(settings) {
    root.isBusy = true
    root.statusMessage = "Saving configuration..."
    var cmd = [root.helperPath, "config", "set"]
    if (settings.server_url !== undefined) cmd.push("--server-url", settings.server_url)
    if (settings.bw_path !== undefined) cmd.push("--bw-path", settings.bw_path)
    if (settings.auto_lock_minutes !== undefined) cmd.push("--auto-lock", String(settings.auto_lock_minutes))
    if (settings.clipboard_clear_seconds !== undefined) cmd.push("--clipboard-clear", String(settings.clipboard_clear_seconds))
    
    configSetProc.command = cmd
    configSetProc.running = true
  }

  FloatingWindow {
    id: panel
    title: "Bitwarden"
    visible: root.opened
    color: root.background
    implicitWidth: 720
    implicitHeight: 520
    minimumSize: Qt.size(540, 400)

    FocusScope {
      id: focusRoot
      anchors.fill: parent
      focus: true

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Escape) {
          root.dismiss()
          event.accepted = true
        }
      }

      ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 12

        // Top Navigation Bar
        RowLayout {
          Layout.fillWidth: true
          spacing: 8

          Text {
            text: "Bitwarden"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading + 2
            font.bold: true
          }

          Item { Layout.fillWidth: true }

          // Health Status Badge
          Rectangle {
            implicitWidth: statusRow.implicitWidth + 12
            implicitHeight: 26
            radius: 13
            color: root.cliHealth.ok ? Qt.rgba(0.2, 0.8, 0.2, 0.15) : Qt.rgba(0.9, 0.2, 0.2, 0.15)
            border.color: root.cliHealth.ok ? Qt.rgba(0.2, 0.8, 0.2, 0.4) : Qt.rgba(0.9, 0.2, 0.2, 0.4)

            RowLayout {
              id: statusRow
              anchors.centerIn: parent
              spacing: 6
              Rectangle {
                width: 8
                height: 8
                radius: 4
                color: root.cliHealth.ok ? "#4ade80" : "#f87171"
              }
              Text {
                text: root.cliHealth.ok ? ("CLI v" + (root.cliHealth.version || "ok")) : "CLI Missing"
                color: root.foreground
                font.pixelSize: Style.font.caption
              }
            }
          }

          // View Toggle Button (Search / Settings)
          Button {
            text: root.currentView === "settings" ? "Back to Search" : "Settings"
            onClicked: {
              root.currentView = (root.currentView === "settings") ? "search" : "settings"
            }
          }
        }

        // Settings View
        ColumnLayout {
          visible: root.currentView === "settings"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 14

          Text {
            text: "Configuration & CLI Health"
            color: root.foreground
            font.pixelSize: Style.font.title
            font.bold: true
          }

          // Server URL setting
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            Text {
              text: "Server URL (Bitwarden or Vaultwarden):"
              color: root.foreground
              font.pixelSize: Style.font.bodySmall
            }
            TextField {
              id: inputServerUrl
              Layout.fillWidth: true
              text: root.config.server_url || "https://vault.bitwarden.com"
              font.pixelSize: Style.font.body
            }
          }

          // CLI Path setting
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            RowLayout {
              Layout.fillWidth: true
              Text {
                text: "Bitwarden CLI executable path:"
                color: root.foreground
                font.pixelSize: Style.font.bodySmall
              }
              Item { Layout.fillWidth: true }
              Text {
                text: root.cliHealth.executable_path ? ("Detected: " + root.cliHealth.executable_path) : "Not found in PATH"
                color: root.cliHealth.ok ? "#4ade80" : Qt.darker(root.foreground, 1.4)
                font.pixelSize: Style.font.caption
              }
            }
            TextField {
              id: inputBwPath
              Layout.fillWidth: true
              text: root.config.bw_path || "bw"
              placeholderText: "bw (auto-detected from $PATH)"
              font.pixelSize: Style.font.body
            }
          }

          // Auto-lock & Clipboard Timeouts
          RowLayout {
            Layout.fillWidth: true
            spacing: 16

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4
              Text {
                text: "Auto-lock Timeout (minutes):"
                color: root.foreground
                font.pixelSize: Style.font.bodySmall
              }
              TextField {
                id: inputAutoLock
                Layout.fillWidth: true
                text: String(root.config.auto_lock_minutes ?? 15)
                font.pixelSize: Style.font.body
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4
              Text {
                text: "Clipboard Clear (seconds):"
                color: root.foreground
                font.pixelSize: Style.font.bodySmall
              }
              TextField {
                id: inputClipClear
                Layout.fillWidth: true
                text: String(root.config.clipboard_clear_seconds ?? 30)
                font.pixelSize: Style.font.body
              }
            }
          }

          // Action Buttons
          RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Button {
              text: "Test CLI Connection"
              onClicked: root.refreshHealth()
            }
            Button {
              text: "Save Configuration"
              highlighted: true
              onClicked: {
                var autoLockVal = parseInt(inputAutoLock.text.trim())
                var clipClearVal = parseInt(inputClipClear.text.trim())
                root.saveSettings({
                  server_url: inputServerUrl.text.trim(),
                  bw_path: inputBwPath.text.trim(),
                  auto_lock_minutes: isNaN(autoLockVal) ? 15 : autoLockVal,
                  clipboard_clear_seconds: isNaN(clipClearVal) ? 30 : clipClearVal
                })
              }
            }
            Item { Layout.fillWidth: true }
            Text {
              text: root.statusMessage
              color: root.accent
              font.pixelSize: Style.font.bodySmall
            }
          }

          Item { Layout.fillHeight: true }
        }

        // Placeholder Search View (to be extended in Tickets 2-5)
        ColumnLayout {
          visible: root.currentView !== "settings"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 12

          Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: root.selectedBackground
            border.color: root.border

            ColumnLayout {
              anchors.centerIn: parent
              spacing: 10

              Text {
                text: root.cliHealth.ok ? "Bitwarden Plugin Ready" : "Bitwarden CLI Not Detected"
                color: root.foreground
                font.pixelSize: Style.font.title
                font.bold: true
                Layout.alignment: Qt.AlignHCenter
              }

              Text {
                text: root.cliHealth.ok 
                  ? ("Connected to: " + (root.config.server_url || "https://vault.bitwarden.com"))
                  : "Please click Settings above to configure bitwarden-cli path."
                color: Qt.darker(root.foreground, 1.3)
                font.pixelSize: Style.font.body
                Layout.alignment: Qt.AlignHCenter
              }
            }
          }
        }
      }
    }
  }

  // Quickshell IO Processes
  Process {
    id: configGetProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          root.config = data
        } catch (e) {
          console.error("Failed to parse config get response:", e)
        }
      }
    }
  }

  Process {
    id: configSetProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        try {
          var data = JSON.parse(text)
          root.config = data
          root.statusMessage = "Configuration saved successfully."
          root.refreshHealth()
        } catch (e) {
          root.statusMessage = "Failed to update config."
        }
      }
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0) {
        root.statusMessage = "Error saving configuration."
      }
    }
  }

  Process {
    id: healthProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          root.cliHealth = data
        } catch (e) {
          console.error("Failed to parse health response:", e)
        }
      }
    }
  }
}
