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

  // Vault Items & Search State
  property var rawVaultItems: []
  property var filteredItems: []
  property string searchQuery: ""
  property var categoryList: ["all", "login", "card", "identity", "note"]
  property string activeCategory: "all"
  property int selectedIndex: 0

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

  function syncVault() {
    root.isBusy = true
    root.statusMessage = "Syncing vault with Bitwarden..."
    vaultSyncProc.command = [root.helperPath, "vault", "sync"]
    vaultSyncProc.running = true
  }

  function loadVaultItems() {
    vaultListProc.command = [root.helperPath, "vault", "list"]
    vaultListProc.running = true
  }

  function isFuzzyMatch(pattern, text) {
    if (!pattern) return true
    pattern = pattern.toLowerCase()
    text = text.toLowerCase()
    if (text.indexOf(pattern) !== -1) return true
    var pIdx = 0
    for (var i = 0; i < text.length; i++) {
      if (text[i] === pattern[pIdx]) {
        pIdx++
        if (pIdx === pattern.length) return true
      }
    }
    return false
  }

  function filterVaultItems() {
    var q = (root.searchQuery || "").trim().toLowerCase()
    var cat = root.activeCategory
    var items = root.rawVaultItems || []

    var res = []
    for (var i = 0; i < items.length; i++) {
      var item = items[i]
      if (cat !== "all" && item.type_name !== cat) continue

      if (q === "") {
        res.push(item)
      } else {
        var words = q.split(/\s+/)
        var searchText = (item.search_text || "").toLowerCase()
        var match = true
        for (var w = 0; w < words.length; w++) {
          if (words[w] && !root.isFuzzyMatch(words[w], searchText)) {
            match = false
            break
          }
        }
        if (match) res.push(item)
      }
    }

    // Sort: favorites first, then exact/prefix match
    res.sort(function(a, b) {
      var ptsA = a.favorite ? 100 : 0
      var ptsB = b.favorite ? 100 : 0
      if (q !== "") {
        var nameA = a.name.toLowerCase()
        var nameB = b.name.toLowerCase()
        if (nameA.indexOf(q) === 0) ptsA += 50
        if (nameB.indexOf(q) === 0) ptsB += 50
      }
      return ptsB - ptsA
    })

    root.filteredItems = res
    if (root.selectedIndex >= res.length) root.selectedIndex = Math.max(0, res.length - 1)
  }

  onSearchQueryChanged: filterVaultItems()
  onActiveCategoryChanged: filterVaultItems()

  function cycleCategory(forward) {
    var idx = root.categoryList.indexOf(root.activeCategory)
    if (idx === -1) idx = 0
    if (forward) {
      idx = (idx + 1) % root.categoryList.length
    } else {
      idx = (idx - 1 + root.categoryList.length) % root.categoryList.length
    }
    root.activeCategory = root.categoryList[idx]
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

  function getCategoryCount(cat) {
    if (!root.rawVaultItems) return 0
    if (cat === "all") return root.rawVaultItems.length
    var count = 0
    for (var i = 0; i < root.rawVaultItems.length; i++) {
      if (root.rawVaultItems[i].type_name === cat) count++
    }
    return count
  }

  function getItemIcon(typeName) {
    switch(typeName) {
      case "login": return "🔑"
      case "card": return "💳"
      case "identity": return "🪪"
      case "note": return "📝"
      default: return "🔒"
    }
  }

  FloatingWindow {
    id: panel
    title: "Bitwarden"
    visible: root.opened
    color: root.background
    implicitWidth: 780
    implicitHeight: 560
    minimumSize: Qt.size(600, 440)

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
        } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_R) {
          root.syncVault()
          event.accepted = true
        } else if (event.key === Qt.Key_Tab && root.effectiveView === "search") {
          root.cycleCategory(true)
          event.accepted = true
        } else if (event.key === Qt.Key_Backtab && root.effectiveView === "search") {
          root.cycleCategory(false)
          event.accepted = true
        } else if (event.key === Qt.Key_Down) {
          if (root.filteredItems.length > 0) {
            root.selectedIndex = (root.selectedIndex + 1) % root.filteredItems.length
          }
          event.accepted = true
        } else if (event.key === Qt.Key_Up) {
          if (root.filteredItems.length > 0) {
            root.selectedIndex = (root.selectedIndex - 1 + root.filteredItems.length) % root.filteredItems.length
          }
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

          // Quick Action: Sync (if unlocked)
          Button {
            visible: root.authState.status === "unlocked"
            text: "Sync (Ctrl+R)"
            enabled: !root.isBusy
            onClicked: root.syncVault()
          }

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
          spacing: 10

          // Search Input Bar
          TextField {
            id: searchInput
            Layout.fillWidth: true
            Layout.preferredHeight: 42
            placeholderText: "Search vault items (names, usernames, notes, cards)..."
            font.pixelSize: Style.font.body + 2
            text: root.searchQuery
            onTextChanged: root.searchQuery = text
            focus: root.effectiveView === "search"
          }

          // Category Filter Chips / Tabs
          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Button {
              text: "All (" + root.getCategoryCount("all") + ")"
              highlighted: root.activeCategory === "all"
              onClicked: root.activeCategory = "all"
            }
            Button {
              text: "Logins (" + root.getCategoryCount("login") + ")"
              highlighted: root.activeCategory === "login"
              onClicked: root.activeCategory = "login"
            }
            Button {
              text: "Cards (" + root.getCategoryCount("card") + ")"
              highlighted: root.activeCategory === "card"
              onClicked: root.activeCategory = "card"
            }
            Button {
              text: "Identities (" + root.getCategoryCount("identity") + ")"
              highlighted: root.activeCategory === "identity"
              onClicked: root.activeCategory = "identity"
            }
            Button {
              text: "Notes (" + root.getCategoryCount("note") + ")"
              highlighted: root.activeCategory === "note"
              onClicked: root.activeCategory = "note"
            }

            Item { Layout.fillWidth: true }

            Text {
              text: root.isBusy ? "Syncing..." : (root.filteredItems.length + " items")
              color: Qt.darker(root.foreground, 1.4)
              font.pixelSize: Style.font.caption
            }
          }

          // Items Result List
          Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: root.selectedBackground
            border.color: root.border
            clip: true

            ListView {
              id: itemsList
              anchors.fill: parent
              anchors.margins: 4
              model: root.filteredItems
              currentIndex: root.selectedIndex

              delegate: Rectangle {
                width: itemsList.width
                height: 52
                radius: 6
                color: (index === root.selectedIndex) ? Qt.rgba(1, 1, 1, 0.1) : "transparent"

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 12
                  anchors.rightMargin: 12
                  spacing: 12

                  Text {
                    text: root.getItemIcon(modelData.type_name)
                    font.pixelSize: 20
                  }

                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2

                    RowLayout {
                      spacing: 6
                      Text {
                        text: modelData.name || "Untitled"
                        color: root.foreground
                        font.pixelSize: Style.font.body
                        font.bold: true
                      }
                      Text {
                        visible: modelData.favorite
                        text: "★"
                        color: "#fbbf24"
                        font.pixelSize: Style.font.caption
                      }
                    }

                    Text {
                      text: modelData.sub_title || modelData.type_name
                      color: Qt.darker(root.foreground, 1.4)
                      font.pixelSize: Style.font.bodySmall
                      elide: Text.ElideRight
                      Layout.fillWidth: true
                    }
                  }

                  Rectangle {
                    implicitWidth: catBadgeText.implicitWidth + 8
                    implicitHeight: 20
                    radius: 4
                    color: Qt.rgba(1, 1, 1, 0.08)
                    Text {
                      id: catBadgeText
                      anchors.centerIn: parent
                      text: modelData.type_name.toUpperCase()
                      color: Qt.darker(root.foreground, 1.3)
                      font.pixelSize: Style.font.caption - 1
                    }
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  onClicked: root.selectedIndex = index
                }
              }

              Text {
                visible: root.filteredItems.length === 0 && !root.isBusy
                anchors.centerIn: parent
                text: root.rawVaultItems.length === 0 ? "Vault is empty or not synced. Click 'Sync' to load items." : "No matching items found."
                color: Qt.darker(root.foreground, 1.4)
                font.pixelSize: Style.font.body
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
          var wasLocked = (root.authState.status !== "unlocked")
          root.authState = data
          if (data.status === "unlocked" && wasLocked) {
            root.syncVault()
          }
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
            root.syncVault()
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
            if (data.session) root.syncVault()
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
        root.rawVaultItems = []
        root.filteredItems = []
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
        root.rawVaultItems = []
        root.filteredItems = []
        root.refreshAuthStatus()
      }
    }
  }

  Process {
    id: vaultSyncProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isBusy = false
        root.statusMessage = "Vault synchronized."
        root.loadVaultItems()
      }
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0) root.statusMessage = "Vault sync failed."
    }
  }

  Process {
    id: vaultListProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var items = JSON.parse(text)
          root.rawVaultItems = items || []
          root.filterVaultItems()
        } catch (e) {
          console.error("Failed to parse vault items:", e)
        }
      }
    }
  }
}
