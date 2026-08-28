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
  property var categoryList: ["all", "login", "card", "identity", "note", "ssh_key"]
  property string activeCategory: "all"
  property int selectedIndex: 0

  // Details Inspector State
  property bool showPasswordRevealed: false
  property bool showPrivateKeyRevealed: false
  property var currentTotp: ({ code: "", ttl: 30, period: 30 })
  property bool showActionPalette: false
  property int actionPaletteIndex: 0

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

  readonly property var selectedItem: {
    if (filteredItems && filteredItems.length > 0 && selectedIndex >= 0 && selectedIndex < filteredItems.length) {
      return filteredItems[selectedIndex]
    }
    return null
  }

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
    root.showActionPalette = false
    root.showPasswordRevealed = false
    root.showPrivateKeyRevealed = false
    root.refreshHealth()
    root.refreshConfig()
    root.refreshAuthStatus()
  }

  function close() {
    root.opened = false
    root.showActionPalette = false
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
    root.onSelectedItemChanged()
  }

  onSearchQueryChanged: filterVaultItems()
  onActiveCategoryChanged: filterVaultItems()
  onSelectedIndexChanged: onSelectedItemChanged()

  function onSelectedItemChanged() {
    root.showPasswordRevealed = false
    root.showPrivateKeyRevealed = false
    root.updateTotpForSelected()
  }

  function updateTotpForSelected() {
    var item = root.selectedItem
    if (item && item.login && item.login.totp) {
      totpGenProc.command = [root.helperPath, "totp", "generate", "--secret", item.login.totp]
      totpGenProc.running = true
    } else {
      root.currentTotp = ({ code: "", ttl: 30, period: 30 })
    }
  }

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

  function copyToClipboard(text, isSensitive, label) {
    if (!text) return
    var cmd = [root.helperPath, "clipboard", "copy", "--text", text]
    if (isSensitive) {
      cmd.push("--sensitive")
    }
    clipCopyProc.command = cmd
    clipCopyProc.running = true
    root.statusMessage = "Copied " + (label || "value") + " to clipboard" + (isSensitive ? " (clears in 30s)" : "") + "."
  }

  function executePrimaryAction(item) {
    if (!item) return
    switch (item.type_name) {
      case "login":
        if (item.login && item.login.password) {
          copyToClipboard(item.login.password, true, "password")
        } else if (item.login && item.login.username) {
          copyToClipboard(item.login.username, false, "username")
        }
        break
      case "card":
        if (item.card && item.card.number) {
          copyToClipboard(item.card.number, true, "card number")
        }
        break
      case "ssh_key":
        if (item.ssh_key && item.ssh_key.private_key) {
          copyToClipboard(item.ssh_key.private_key, true, "SSH private key")
        } else if (item.ssh_key && item.ssh_key.public_key) {
          copyToClipboard(item.ssh_key.public_key, false, "SSH public key")
        }
        break
      case "note":
        copyToClipboard(item.notes || "", false, "secure note")
        break
      case "identity":
        if (item.identity && item.identity.email) {
          copyToClipboard(item.identity.email, false, "identity email")
        } else if (item.identity && (item.identity.firstName || item.identity.lastName)) {
          copyToClipboard((item.identity.firstName + " " + item.identity.lastName).trim(), false, "name")
        }
        break
      default:
        copyToClipboard(item.notes || "", false, "content")
    }
  }

  function getAvailableActions(item) {
    if (!item) return []
    var actions = []
    
    if (item.type_name === "login" && item.login) {
      if (item.login.password) actions.push({ label: "Copy Password", icon: "🔒", action: function() { root.copyToClipboard(item.login.password, true, "password") } })
      if (item.login.username) actions.push({ label: "Copy Username", icon: "👤", action: function() { root.copyToClipboard(item.login.username, false, "username") } })
      if (root.currentTotp.code) actions.push({ label: "Copy TOTP Code", icon: "⏱️", action: function() { root.copyToClipboard(root.currentTotp.code, true, "TOTP code") } })
      if (item.login.uris && item.login.uris.length > 0 && item.login.uris[0].uri) {
        actions.push({ label: "Open URL", icon: "🌐", action: function() { Qt.openUrlExternally(item.login.uris[0].uri) } })
      }
    } else if (item.type_name === "card" && item.card) {
      if (item.card.number) actions.push({ label: "Copy Card Number", icon: "💳", action: function() { root.copyToClipboard(item.card.number, true, "card number") } })
      if (item.card.code) actions.push({ label: "Copy Security Code (CVV)", icon: "🔢", action: function() { root.copyToClipboard(item.card.code, true, "CVV") } })
      if (item.card.cardholderName) actions.push({ label: "Copy Cardholder Name", icon: "👤", action: function() { root.copyToClipboard(item.card.cardholderName, false, "cardholder") } })
    } else if (item.type_name === "ssh_key" && item.ssh_key) {
      if (item.ssh_key.public_key) actions.push({ label: "Copy Public Key", icon: "🔑", action: function() { root.copyToClipboard(item.ssh_key.public_key, false, "public key") } })
      if (item.ssh_key.private_key) actions.push({ label: "Copy Private Key", icon: "🗝️", action: function() { root.copyToClipboard(item.ssh_key.private_key, true, "private key") } })
      if (item.ssh_key.passphrase) actions.push({ label: "Copy Passphrase", icon: "🔒", action: function() { root.copyToClipboard(item.ssh_key.passphrase, true, "passphrase") } })
    } else if (item.type_name === "identity" && item.identity) {
      if (item.identity.email) actions.push({ label: "Copy Email", icon: "✉️", action: function() { root.copyToClipboard(item.identity.email, false, "email") } })
      if (item.identity.phone) actions.push({ label: "Copy Phone", icon: "📞", action: function() { root.copyToClipboard(item.identity.phone, false, "phone") } })
    }

    if (item.notes) {
      actions.push({ label: "Copy Notes", icon: "📝", action: function() { root.copyToClipboard(item.notes, false, "notes") } })
    }

    // Check custom fields for PIN or other attributes
    if (item.fields) {
      for (var f = 0; f < item.fields.length; f++) {
        var field = item.fields[f]
        if (field.name && field.value) {
          var fLower = field.name.toLowerCase()
          if (fLower === "pin" || fLower.indexOf("pin") !== -1) {
            (function(pinVal) {
              actions.push({
                label: "Copy PIN",
                icon: "🔢",
                action: function() { root.copyToClipboard(String(pinVal), true, "PIN") }
              })
            })(field.value)
          } else {
            (function(fld) {
              actions.push({
                label: "Copy " + fld.name,
                icon: "🏷️",
                action: function() { root.copyToClipboard(String(fld.value), true, fld.name) }
              })
            })(field)
          }
        }
      }
    }

    return actions
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
      case "ssh_key": return "🗝️"
      default: return "🔒"
    }
  }

  // TOTP live refresh timer
  Timer {
    interval: 1000
    running: root.opened && root.effectiveView === "search" && root.selectedItem && root.selectedItem.login && root.selectedItem.login.totp
    repeat: true
    onTriggered: {
      if (root.currentTotp.ttl > 1) {
        root.currentTotp = ({ code: root.currentTotp.code, ttl: root.currentTotp.ttl - 1, period: root.currentTotp.period })
      } else {
        root.updateTotpForSelected()
      }
    }
  }

  FloatingWindow {
    id: panel
    title: "Bitwarden"
    visible: root.opened
    color: root.background
    implicitWidth: 920
    implicitHeight: 600
    minimumSize: Qt.size(720, 480)

    FocusScope {
      id: focusRoot
      anchors.fill: parent
      focus: true

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (root.showActionPalette) {
          var actions = root.getAvailableActions(root.selectedItem)
          if (event.key === Qt.Key_Escape) {
            root.showActionPalette = false
            event.accepted = true
          } else if (event.key === Qt.Key_Down) {
            if (actions.length > 0) root.actionPaletteIndex = (root.actionPaletteIndex + 1) % actions.length
            event.accepted = true
          } else if (event.key === Qt.Key_Up) {
            if (actions.length > 0) root.actionPaletteIndex = (root.actionPaletteIndex - 1 + actions.length) % actions.length
            event.accepted = true
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            if (actions.length > 0 && root.actionPaletteIndex < actions.length) {
              actions[root.actionPaletteIndex].action()
              root.showActionPalette = false
            }
            event.accepted = true
          }
          return
        }

        if (event.key === Qt.Key_Escape) {
          root.dismiss()
          event.accepted = true
        } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_K) {
          if (root.selectedItem) {
            root.actionPaletteIndex = 0
            root.showActionPalette = true
          }
          event.accepted = true
        } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_L) {
          root.doLock()
          event.accepted = true
        } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_R) {
          root.syncVault()
          event.accepted = true
        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
          if (root.effectiveView === "search" && root.selectedItem) {
            root.executePrimaryAction(root.selectedItem)
            event.accepted = true
          }
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

          // Quick Action Palette button
          Button {
            visible: root.authState.status === "unlocked" && root.selectedItem !== null
            text: "Actions (Ctrl+K)"
            onClicked: {
              root.actionPaletteIndex = 0
              root.showActionPalette = true
            }
          }

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

        // Status / Error message banner
        Rectangle {
          visible: root.errorMessage !== "" || root.statusMessage !== ""
          Layout.fillWidth: true
          implicitHeight: bannerText.implicitHeight + 10
          radius: 6
          color: (root.errorMessage !== "") ? Qt.rgba(0.9, 0.2, 0.2, 0.15) : Qt.rgba(0.2, 0.7, 0.9, 0.15)
          border.color: (root.errorMessage !== "") ? Qt.rgba(0.9, 0.2, 0.2, 0.4) : Qt.rgba(0.2, 0.7, 0.9, 0.4)

          Text {
            id: bannerText
            anchors.centerIn: parent
            width: parent.width - 24
            text: (root.errorMessage !== "") ? root.errorMessage : root.statusMessage
            color: (root.errorMessage !== "") ? "#f87171" : root.accent
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
          }

          Item { Layout.fillHeight: true }
        }

        // ==========================================
        // 4. VAULT SEARCH & INSPECTOR VIEW (Raycast Split Layout)
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
            placeholderText: "Search credentials (names, usernames, notes, cards, ssh)... (Enter: Copy, Ctrl+K: Actions)"
            font.pixelSize: Style.font.body + 2
            text: root.searchQuery
            onTextChanged: root.searchQuery = text
            onAccepted: {
              if (root.selectedItem) {
                root.executePrimaryAction(root.selectedItem)
              }
            }
            focus: root.effectiveView === "search" && !root.showActionPalette
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
            Button {
              text: "SSH Keys (" + root.getCategoryCount("ssh_key") + ")"
              highlighted: root.activeCategory === "ssh_key"
              onClicked: root.activeCategory = "ssh_key"
            }

            Item { Layout.fillWidth: true }

            Text {
              text: root.isBusy ? "Syncing..." : (root.filteredItems.length + " items")
              color: Qt.darker(root.foreground, 1.4)
              font.pixelSize: Style.font.caption
            }
          }

          // Split Content: Left (List) & Right (Details Inspector)
          RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 12

            // Left: Items Result List
            Rectangle {
              Layout.fillWidth: true
              Layout.fillHeight: true
              Layout.preferredWidth: 380
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
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    spacing: 10

                    Text {
                      text: root.getItemIcon(modelData.type_name)
                      font.pixelSize: 18
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
                      implicitHeight: 18
                      radius: 4
                      color: Qt.rgba(1, 1, 1, 0.08)
                      Text {
                        id: catBadgeText
                        anchors.centerIn: parent
                        text: (modelData.type_name === "ssh_key") ? "SSH" : modelData.type_name.toUpperCase()
                        color: Qt.darker(root.foreground, 1.3)
                        font.pixelSize: Style.font.caption - 2
                      }
                    }
                  }

                  MouseArea {
                    anchors.fill: parent
                    onClicked: root.selectedIndex = index
                    onDoubleClicked: root.executePrimaryAction(modelData)
                  }
                }

                Text {
                  visible: root.filteredItems.length === 0 && !root.isBusy
                  anchors.centerIn: parent
                  text: root.rawVaultItems.length === 0 ? "Vault is empty. Click 'Sync' to load." : "No matching items."
                  color: Qt.darker(root.foreground, 1.4)
                  font.pixelSize: Style.font.body
                }
              }
            }

            // Right: Details Inspector Pane
            Rectangle {
              Layout.fillWidth: true
              Layout.fillHeight: true
              Layout.preferredWidth: 360
              radius: 8
              color: root.selectedBackground
              border.color: root.border
              clip: true

              ScrollView {
                anchors.fill: parent
                anchors.margins: 14
                contentWidth: width

                ColumnLayout {
                  width: parent.width
                  spacing: 12

                  // Header Info
                  RowLayout {
                    Layout.fillWidth: true
                    spacing: 10

                    Text {
                      text: root.selectedItem ? root.getItemIcon(root.selectedItem.type_name) : "🔒"
                      font.pixelSize: 28
                    }

                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: 2
                      Text {
                        text: root.selectedItem ? root.selectedItem.name : "Select an item"
                        color: root.foreground
                        font.pixelSize: Style.font.title
                        font.bold: true
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                      }
                      Text {
                        text: root.selectedItem ? (root.selectedItem.type_name.toUpperCase() + (root.selectedItem.favorite ? " • Favorite" : "")) : ""
                        color: Qt.darker(root.foreground, 1.4)
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }

                  Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: root.border
                  }

                  // Login Details
                  ColumnLayout {
                    visible: root.selectedItem && root.selectedItem.type_name === "login" && root.selectedItem.login !== null
                    Layout.fillWidth: true
                    spacing: 8

                    // Username
                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Username:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 70 }
                      Text { text: (root.selectedItem && root.selectedItem.login && root.selectedItem.login.username) || "—"; color: root.foreground; font.pixelSize: Style.font.body; Layout.fillWidth: true; elide: Text.ElideRight }
                      Button {
                        text: "Copy"
                        visible: Boolean(root.selectedItem && root.selectedItem.login && root.selectedItem.login.username)
                        onClicked: root.copyToClipboard(root.selectedItem.login.username, false, "username")
                      }
                    }

                    // Password
                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Password:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 70 }
                      Text {
                        text: (root.selectedItem && root.selectedItem.login && root.selectedItem.login.password) 
                          ? (root.showPasswordRevealed ? root.selectedItem.login.password : "••••••••••••") 
                          : "—"
                        color: root.foreground
                        font.pixelSize: Style.font.body
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                      }
                      Button {
                        text: root.showPasswordRevealed ? "Hide" : "Reveal"
                        visible: Boolean(root.selectedItem && root.selectedItem.login && root.selectedItem.login.password)
                        onClicked: root.showPasswordRevealed = !root.showPasswordRevealed
                      }
                      Button {
                        text: "Copy"
                        visible: Boolean(root.selectedItem && root.selectedItem.login && root.selectedItem.login.password)
                        onClicked: root.copyToClipboard(root.selectedItem.login.password, true, "password")
                      }
                    }

                    // TOTP Code
                    ColumnLayout {
                      visible: Boolean(root.selectedItem && root.selectedItem.login && root.selectedItem.login.totp)
                      Layout.fillWidth: true
                      spacing: 4

                      RowLayout {
                        Layout.fillWidth: true
                        Text { text: "TOTP Code:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 70 }
                        Text {
                          text: root.currentTotp.code || "Generating..."
                          color: root.accent
                          font.pixelSize: Style.font.heading
                          font.bold: true
                          Layout.fillWidth: true
                        }
                        Text {
                          text: root.currentTotp.ttl + "s"
                          color: Qt.darker(root.foreground, 1.4)
                          font.pixelSize: Style.font.caption
                        }
                        Button {
                          text: "Copy"
                          enabled: Boolean(root.currentTotp.code)
                          onClicked: root.copyToClipboard(root.currentTotp.code, true, "TOTP code")
                        }
                      }

                      // TTL Progress Bar
                      Rectangle {
                        Layout.fillWidth: true
                        height: 3
                        radius: 1.5
                        color: Qt.rgba(1, 1, 1, 0.1)
                        Rectangle {
                          height: parent.height
                          radius: parent.radius
                          width: parent.width * (root.currentTotp.ttl / (root.currentTotp.period || 30))
                          color: (root.currentTotp.ttl > 5) ? root.accent : "#f87171"
                        }
                      }
                    }

                    // URIs
                    RowLayout {
                      visible: Boolean(root.selectedItem && root.selectedItem.login && root.selectedItem.login.uris && root.selectedItem.login.uris.length > 0)
                      Layout.fillWidth: true
                      Text { text: "URL:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 70 }
                      Text {
                        text: (root.selectedItem && root.selectedItem.login && root.selectedItem.login.uris && root.selectedItem.login.uris[0]) ? root.selectedItem.login.uris[0].uri : ""
                        color: root.accent
                        font.pixelSize: Style.font.bodySmall
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                      }
                      Button {
                        text: "Open"
                        onClicked: {
                          if (root.selectedItem.login.uris[0].uri) Qt.openUrlExternally(root.selectedItem.login.uris[0].uri)
                        }
                      }
                    }
                  }

                  // Card Details
                  ColumnLayout {
                    visible: root.selectedItem && root.selectedItem.type_name === "card" && root.selectedItem.card !== null
                    Layout.fillWidth: true
                    spacing: 8

                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Cardholder:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text { text: (root.selectedItem && root.selectedItem.card && root.selectedItem.card.cardholderName) || "—"; color: root.foreground; font.pixelSize: Style.font.body; Layout.fillWidth: true }
                      Button { text: "Copy"; onClicked: root.copyToClipboard(root.selectedItem.card.cardholderName, false, "cardholder") }
                    }

                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Number:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text {
                        text: (root.selectedItem && root.selectedItem.card && root.selectedItem.card.number)
                          ? (root.showPasswordRevealed ? root.selectedItem.card.number : ("•••• •••• •••• " + (root.selectedItem.card.number.slice(-4) || "")))
                          : "—"
                        color: root.foreground
                        font.pixelSize: Style.font.body
                        Layout.fillWidth: true
                      }
                      Button {
                        text: root.showPasswordRevealed ? "Hide" : "Reveal"
                        onClicked: root.showPasswordRevealed = !root.showPasswordRevealed
                      }
                      Button {
                        text: "Copy"
                        onClicked: root.copyToClipboard(root.selectedItem.card.number, true, "card number")
                      }
                    }

                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Expires:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text { text: (root.selectedItem && root.selectedItem.card) ? (root.selectedItem.card.expMonth + "/" + root.selectedItem.card.expYear) : "—"; color: root.foreground; font.pixelSize: Style.font.body; Layout.fillWidth: true }
                      Text { text: "CVV:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall }
                      Text { text: (root.selectedItem && root.selectedItem.card && root.selectedItem.card.code) ? "•••" : "—"; color: root.foreground; font.pixelSize: Style.font.body }
                      Button {
                        text: "Copy CVV"
                        visible: Boolean(root.selectedItem && root.selectedItem.card && root.selectedItem.card.code)
                        onClicked: root.copyToClipboard(root.selectedItem.card.code, true, "CVV")
                      }
                    }
                  }

                  // SSH Key Details
                  ColumnLayout {
                    visible: root.selectedItem && root.selectedItem.type_name === "ssh_key" && root.selectedItem.ssh_key !== null
                    Layout.fillWidth: true
                    spacing: 8

                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Key Type:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text { text: (root.selectedItem && root.selectedItem.ssh_key && root.selectedItem.ssh_key.key_type) || "SSH"; color: root.foreground; font.pixelSize: Style.font.body; Layout.fillWidth: true }
                    }

                    // Public Key
                    RowLayout {
                      visible: Boolean(root.selectedItem && root.selectedItem.ssh_key && root.selectedItem.ssh_key.public_key)
                      Layout.fillWidth: true
                      Text { text: "Public Key:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text {
                        text: (root.selectedItem && root.selectedItem.ssh_key && root.selectedItem.ssh_key.public_key) ? (root.selectedItem.ssh_key.public_key.slice(0, 20) + "...") : "—"
                        color: root.foreground
                        font.pixelSize: Style.font.bodySmall
                        Layout.fillWidth: true
                      }
                      Button {
                        text: "Copy Public"
                        onClicked: root.copyToClipboard(root.selectedItem.ssh_key.public_key, false, "SSH public key")
                      }
                    }

                    // Private Key
                    RowLayout {
                      visible: Boolean(root.selectedItem && root.selectedItem.ssh_key && root.selectedItem.ssh_key.private_key)
                      Layout.fillWidth: true
                      Text { text: "Private Key:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text {
                        text: root.showPrivateKeyRevealed ? "Private Key Loaded" : "••••••••••••"
                        color: root.foreground
                        font.pixelSize: Style.font.bodySmall
                        Layout.fillWidth: true
                      }
                      Button {
                        text: root.showPrivateKeyRevealed ? "Hide" : "Reveal"
                        onClicked: root.showPrivateKeyRevealed = !root.showPrivateKeyRevealed
                      }
                      Button {
                        text: "Copy Private"
                        onClicked: root.copyToClipboard(root.selectedItem.ssh_key.private_key, true, "SSH private key")
                      }
                    }

                    // Passphrase
                    RowLayout {
                      visible: Boolean(root.selectedItem && root.selectedItem.ssh_key && root.selectedItem.ssh_key.passphrase)
                      Layout.fillWidth: true
                      Text { text: "Passphrase:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80 }
                      Text { text: "••••••••"; color: root.foreground; font.pixelSize: Style.font.body; Layout.fillWidth: true }
                      Button {
                        text: "Copy"
                        onClicked: root.copyToClipboard(root.selectedItem.ssh_key.passphrase, true, "SSH passphrase")
                      }
                    }
                  }

                  // Notes section
                  ColumnLayout {
                    visible: Boolean(root.selectedItem && root.selectedItem.notes)
                    Layout.fillWidth: true
                    spacing: 4

                    RowLayout {
                      Layout.fillWidth: true
                      Text { text: "Notes:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall }
                      Item { Layout.fillWidth: true }
                      Button {
                        text: "Copy Notes"
                        onClicked: root.copyToClipboard(root.selectedItem.notes, false, "notes")
                      }
                    }

                    Rectangle {
                      Layout.fillWidth: true
                      implicitHeight: Math.min(100, notesContentText.implicitHeight + 12)
                      radius: 4
                      color: Qt.rgba(0, 0, 0, 0.2)
                      clip: true

                      Text {
                        id: notesContentText
                        anchors.fill: parent
                        anchors.margins: 6
                        text: root.selectedItem ? (root.selectedItem.notes || "") : ""
                        color: root.foreground
                        font.pixelSize: Style.font.bodySmall
                        wrapMode: Text.Wrap
                      }
                    }
                  }

                  // Custom Fields section
                  ColumnLayout {
                    visible: Boolean(root.selectedItem && root.selectedItem.fields && root.selectedItem.fields.length > 0)
                    Layout.fillWidth: true
                    spacing: 6

                    Text { text: "Custom Fields:"; color: Qt.darker(root.foreground, 1.4); font.pixelSize: Style.font.bodySmall }

                    Repeater {
                      model: root.selectedItem ? (root.selectedItem.fields || []) : []
                      delegate: RowLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        Text { text: modelData.name + ":"; color: Qt.darker(root.foreground, 1.3); font.pixelSize: Style.font.bodySmall; Layout.preferredWidth: 80; elide: Text.ElideRight }
                        Text { text: String(modelData.value || ""); color: root.foreground; font.pixelSize: Style.font.bodySmall; Layout.fillWidth: true; elide: Text.ElideRight }
                        Button {
                          text: "Copy"
                          onClicked: root.copyToClipboard(String(modelData.value), true, modelData.name)
                        }
                      }
                    }
                  }

                  Item { Layout.fillHeight: true }
                }
              }
            }
          }
        }
      }

      // ==========================================
      // ACTION PALETTE MODAL (Ctrl+K)
      // ==========================================
      Rectangle {
        visible: root.showActionPalette
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.6)

        Rectangle {
          anchors.centerIn: parent
          width: 440
          height: 340
          radius: 10
          color: root.background
          border.color: root.border

          ColumnLayout {
            anchors.fill: parent
            anchors.margins: 14
            spacing: 8

            RowLayout {
              Layout.fillWidth: true
              Text {
                text: "Actions for: " + (root.selectedItem ? root.selectedItem.name : "Item")
                color: root.foreground
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
                Layout.fillWidth: true
              }
              Button {
                text: "Esc"
                onClicked: root.showActionPalette = false
              }
            }

            Rectangle { Layout.fillWidth: true; height: 1; color: root.border }

            ListView {
              id: actionsList
              Layout.fillWidth: true
              Layout.fillHeight: true
              clip: true
              model: root.getAvailableActions(root.selectedItem)
              currentIndex: root.actionPaletteIndex

              delegate: Rectangle {
                width: actionsList.width
                height: 40
                radius: 6
                color: (index === root.actionPaletteIndex) ? root.accent : "transparent"

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 10
                  anchors.rightMargin: 10
                  spacing: 10

                  Text { text: modelData.icon; font.pixelSize: 16 }
                  Text {
                    text: modelData.label
                    color: (index === root.actionPaletteIndex) ? "#ffffff" : root.foreground
                    font.pixelSize: Style.font.body
                    Layout.fillWidth: true
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  onClicked: {
                    modelData.action()
                    root.showActionPalette = false
                  }
                }
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

  Process {
    id: clipCopyProc
    command: []
  }

  Process {
    id: totpGenProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var res = JSON.parse(text)
          if (res && res.code) {
            root.currentTotp = res
          }
        } catch (e) {}
      }
    }
  }
}
