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

  property var authState: ({
    status: "unauthenticated", // "unauthenticated" | "locked" | "unlocked"
    server_url: "",
    user_email: "",
    has_session: false
  })

  property string currentView: "auto" // "auto" | "settings" | "login" | "unlock" | "search"
  property string loginMethod: "password" // "password" | "apikey"
  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false

  readonly property color background: Color.menu.background
  readonly property color foreground: Color.menu.text
  readonly property color border: Color.menu.border
  readonly property color accent: Color.menu.selectedText
  readonly property color selectedBackground: Color.menu.selectedBackground
  readonly property string fontFamily: Style.font.menuFamily

  readonly property string effectiveView: {
    if (currentView !== "auto") return currentView
    if (authState.status === "unlocked") return "search"
    if (authState.status === "locked") return "unlock"
    return "login"
  }

  function open(payloadJson) {
    root.opened = true
    root.errorMessage = ""
    root.statusMessage = ""
    root.currentView = "auto"
    root.refreshHealth()
    root.refreshConfig()
    root.refreshAuthStatus()
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

  function refreshAuthStatus() {
    authStatusProc.command = [root.helperPath, "auth", "status"]
    authStatusProc.running = true
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

  function doUnlock(password) {
    if (!password) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Unlocking vault..."
    authUnlockProc.command = [root.helperPath, "auth", "unlock", "--password", password]
    authUnlockProc.running = true
  }

  function doLock() {
    root.isBusy = true
    root.statusMessage = "Locking vault..."
    authLockProc.command = [root.helperPath, "auth", "lock"]
    authLockProc.running = true
  }

  function doLoginPassword(email, password, code) {
    if (!email || !password) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Logging in to Bitwarden..."
    var cmd = [root.helperPath, "auth", "login-password", "--email", email, "--password", password]
    if (code) cmd.push("--code", code)
    authLoginProc.command = cmd
    authLoginProc.running = true
  }

  function doLoginApiKey(clientId, clientSecret) {
    if (!clientId || !clientSecret) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Authenticating with API Key..."
    authLoginProc.command = [root.helperPath, "auth", "login-apikey", "--client-id", clientId, "--client-secret", clientSecret]
    authLoginProc.running = true
  }

  function doLogout() {
    root.isBusy = true
    root.statusMessage = "Logging out..."
    authLogoutProc.command = [root.helperPath, "auth", "logout"]
    authLogoutProc.running = true
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
        } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_L) {
          root.doLock()
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

          // Lock Status Badge
          Rectangle {
            implicitWidth: lockStatusRow.implicitWidth + 12
            implicitHeight: 24
            radius: 12
            color: (root.authState.status === "unlocked") 
              ? Qt.rgba(0.2, 0.8, 0.2, 0.15) 
              : Qt.rgba(0.8, 0.6, 0.2, 0.15)
            border.color: (root.authState.status === "unlocked")
              ? Qt.rgba(0.2, 0.8, 0.2, 0.4)
              : Qt.rgba(0.8, 0.6, 0.2, 0.4)

            RowLayout {
              id: lockStatusRow
              anchors.centerIn: parent
              spacing: 6
              Text {
                text: (root.authState.status === "unlocked") ? "Unlocked (Keyring)" : (root.authState.status === "locked" ? "Locked" : "Not Logged In")
                color: root.foreground
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }
          }

          Item { Layout.fillWidth: true }

          // Quick Action: Lock (if unlocked)
          Button {
            visible: root.authState.status === "unlocked"
            text: "Lock (Ctrl+L)"
            onClicked: root.doLock()
          }

          // View Toggle Button (Search / Settings)
          Button {
            text: root.effectiveView === "settings" ? "Back" : "Settings"
            onClicked: {
              root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
            }
          }
        }

        // Error message banner
        Rectangle {
          visible: root.errorMessage !== ""
          Layout.fillWidth: true
          implicitHeight: errorText.implicitHeight + 12
          radius: 6
          color: Qt.rgba(0.9, 0.2, 0.2, 0.15)
          border.color: Qt.rgba(0.9, 0.2, 0.2, 0.5)

          Text {
            id: errorText
            anchors.centerIn: parent
            width: parent.width - 24
            text: root.errorMessage
            color: "#f87171"
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.Wrap
          }
        }

        // ==========================================
        // 1. UNLOCK VIEW
        // ==========================================
        ColumnLayout {
          visible: root.effectiveView === "unlock"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 16

          Item { Layout.fillHeight: true }

          ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 380
            spacing: 12

            Text {
              text: "Unlock Bitwarden Vault"
              color: root.foreground
              font.pixelSize: Style.font.heading
              font.bold: true
              Layout.alignment: Qt.AlignHCenter
            }

            Text {
              text: root.authState.user_email ? ("Account: " + root.authState.user_email) : "Enter Master Password or PIN"
              color: Qt.darker(root.foreground, 1.3)
              font.pixelSize: Style.font.bodySmall
              Layout.alignment: Qt.AlignHCenter
            }

            TextField {
              id: inputUnlockPassword
              Layout.fillWidth: true
              echoMode: TextInput.Password
              placeholderText: "Master Password / PIN"
              font.pixelSize: Style.font.body
              focus: true
              onAccepted: root.doUnlock(text)
            }

            Button {
              Layout.fillWidth: true
              text: root.isBusy ? "Unlocking..." : "Unlock Vault"
              highlighted: true
              enabled: !root.isBusy && inputUnlockPassword.text.length > 0
              onClicked: root.doUnlock(inputUnlockPassword.text)
            }

            RowLayout {
              Layout.alignment: Qt.AlignHCenter
              Button {
                text: "Logout Account"
                flat: true
                onClicked: root.doLogout()
              }
            }
          }

          Item { Layout.fillHeight: true }
        }

        // ==========================================
        // 2. LOGIN VIEW
        // ==========================================
        ColumnLayout {
          visible: root.effectiveView === "login"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 14

          Item { Layout.fillHeight: true }

          ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 420
            spacing: 12

            Text {
              text: "Log in to Bitwarden"
              color: root.foreground
              font.pixelSize: Style.font.heading
              font.bold: true
              Layout.alignment: Qt.AlignHCenter
            }

            RowLayout {
              Layout.alignment: Qt.AlignHCenter
              spacing: 8
              Button {
                text: "Master Password"
                highlighted: root.loginMethod === "password"
                onClicked: { root.loginMethod = "password" }
              }
              Button {
                text: "API Key"
                highlighted: root.loginMethod === "apikey"
                onClicked: { root.loginMethod = "apikey" }
              }
            }

            // Password Login Fields
            ColumnLayout {
              visible: root.loginMethod === "password"
              Layout.fillWidth: true
              spacing: 8

              TextField {
                id: inputLoginEmail
                Layout.fillWidth: true
                placeholderText: "Email address"
                font.pixelSize: Style.font.body
              }

              TextField {
                id: inputLoginPassword
                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: "Master Password"
                font.pixelSize: Style.font.body
              }

              TextField {
                id: inputLogin2FA
                Layout.fillWidth: true
                placeholderText: "2FA Verification Code (optional)"
                font.pixelSize: Style.font.body
              }

              Button {
                Layout.fillWidth: true
                text: root.isBusy ? "Logging in..." : "Log In"
                highlighted: true
                enabled: !root.isBusy && inputLoginEmail.text.length > 0 && inputLoginPassword.text.length > 0
                onClicked: root.doLoginPassword(inputLoginEmail.text.trim(), inputLoginPassword.text, inputLogin2FA.text.trim())
              }
            }

            // API Key Login Fields
            ColumnLayout {
              visible: root.loginMethod === "apikey"
              Layout.fillWidth: true
              spacing: 8

              TextField {
                id: inputClientId
                Layout.fillWidth: true
                placeholderText: "client_id (e.g. user.xxxxx)"
                font.pixelSize: Style.font.body
              }

              TextField {
                id: inputClientSecret
                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: "client_secret"
                font.pixelSize: Style.font.body
              }

              Button {
                Layout.fillWidth: true
                text: root.isBusy ? "Authenticating..." : "Log In with API Key"
                highlighted: true
                enabled: !root.isBusy && inputClientId.text.length > 0 && inputClientSecret.text.length > 0
                onClicked: root.doLoginApiKey(inputClientId.text.trim(), inputClientSecret.text.trim())
              }
            }
          }

          Item { Layout.fillHeight: true }
        }

        // ==========================================
        // 3. SETTINGS VIEW
        // ==========================================
        ColumnLayout {
          visible: root.effectiveView === "settings"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 14

          Text {
            text: "Configuration & CLI Health"
            color: root.foreground
            font.pixelSize: Style.font.title
            font.bold: true
          }

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

        // ==========================================
        // 4. VAULT SEARCH VIEW (Unlocked)
        // ==========================================
        ColumnLayout {
          visible: root.effectiveView === "search"
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
                text: "Vault Unlocked & Ready"
                color: root.foreground
                font.pixelSize: Style.font.title
                font.bold: true
                Layout.alignment: Qt.AlignHCenter
              }

              Text {
                text: "Session active via Linux Keyring. Ready for Ticket 3 (Vault Sync & Search)."
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
        } catch (e) {}
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
      if (code !== 0) root.statusMessage = "Error saving configuration."
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
        } catch (e) {}
      }
    }
  }

  Process {
    id: authStatusProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          root.authState = data
        } catch (e) {}
      }
    }
  }

  Process {
    id: authUnlockProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = "Unlocked successfully."
            root.refreshAuthStatus()
          } else {
            root.errorMessage = data.error || "Unlock failed."
          }
        } catch (e) {
          root.errorMessage = "Failed to parse unlock response."
        }
      }
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) root.errorMessage = "Unlock command failed."
    }
  }

  Process {
    id: authLoginProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = "Logged in successfully."
            root.refreshAuthStatus()
          } else {
            root.errorMessage = data.error || "Login failed."
          }
        } catch (e) {
          root.errorMessage = "Failed to parse login response."
        }
      }
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) root.errorMessage = "Login command failed."
    }
  }

  Process {
    id: authLockProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        root.refreshAuthStatus()
      }
    }
    onExited: function(code) {
      root.isBusy = false
    }
  }

  Process {
    id: authLogoutProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        root.refreshAuthStatus()
      }
    }
  }
}
