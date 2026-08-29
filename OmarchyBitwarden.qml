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

  Component.onCompleted: {
    root.refreshConfig()
    root.refreshHealth()
    root.refreshAuthStatus()
    root.loadVaultItems()
  }

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
    clipboard_clear_seconds: 30,
    max_output_mb: 10,
    email: "",
    remember_email: true
  })
  property bool rememberEmailChecked: true
  property bool show2FAField: false

  property var cliHealth: ({
    installed: false,
    ok: false,
    version: "",
    executable_path: "",
    error: null
  })

  property var authState: ({
    status: "unlocked",
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
  property var currentAvailableActions: []

  property string currentView: "auto"
  property string loginMethod: "password"
  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property bool isLoadingVault: false

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
    if (authState.status === "unlocked" || (rawVaultItems && rawVaultItems.length > 0)) return "search"
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
    root.searchQuery = ""
    if (typeof searchInput !== "undefined" && searchInput) searchInput.text = ""
    if (typeof inputUnlockPassword !== "undefined" && inputUnlockPassword) inputUnlockPassword.text = ""
    root.refreshHealth()
    root.refreshConfig()
    root.refreshAuthStatus()
    if (root.authState.status === "unlocked" || (root.rawVaultItems && root.rawVaultItems.length > 0)) {
      if (!root.rawVaultItems || root.rawVaultItems.length === 0) root.loadVaultItems()
      root.syncVault(true)
    }
    Qt.callLater(function() {
      if (root.effectiveView === "search") searchInput.forceActiveFocus()
      else if (root.effectiveView === "unlock") inputUnlockPassword.forceActiveFocus()
      else if (root.effectiveView === "login") {
        if (typeof inputLoginEmail !== "undefined" && inputLoginEmail && inputLoginEmail.text.trim().length > 0) {
          if (typeof inputLoginPassword !== "undefined" && inputLoginPassword) inputLoginPassword.forceActiveFocus()
        } else {
          if (typeof inputLoginEmail !== "undefined" && inputLoginEmail) inputLoginEmail.forceActiveFocus()
        }
      }
    })
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

  function updateConfig(options) {
    var cmd = [root.helperPath, "config", "set"]
    if (options.server_url !== undefined) cmd.push("--server-url", options.server_url)
    if (options.bw_path !== undefined) cmd.push("--bw-path", options.bw_path)
    if (options.auto_lock_minutes !== undefined) cmd.push("--auto-lock", String(options.auto_lock_minutes))
    if (options.clipboard_clear_seconds !== undefined) cmd.push("--clipboard-clear", String(options.clipboard_clear_seconds))
    if (options.max_output_mb !== undefined) cmd.push("--max-output-mb", String(options.max_output_mb))
    if (options.email !== undefined) cmd.push("--email", options.email)
    if (options.remember_email !== undefined) cmd.push("--remember-email", options.remember_email ? "true" : "false")
    configSetProc.command = cmd
    configSetProc.running = true
  }

  function submitLoginForm() {
    if (root.isBusy) return
    if (root.loginMethod === "password") {
      var email = (typeof inputLoginEmail !== "undefined" && inputLoginEmail) ? inputLoginEmail.text.trim() : ""
      var password = (typeof inputLoginPassword !== "undefined" && inputLoginPassword) ? inputLoginPassword.text : ""
      var code = (root.show2FAField && typeof inputLogin2FA !== "undefined" && inputLogin2FA) ? inputLogin2FA.text.trim() : ""
      if (!email) {
        if (typeof inputLoginEmail !== "undefined" && inputLoginEmail) inputLoginEmail.forceActiveFocus()
        return
      }
      if (!password) {
        if (typeof inputLoginPassword !== "undefined" && inputLoginPassword) inputLoginPassword.forceActiveFocus()
        return
      }
      root.doLoginPassword(email, password, code)
    } else if (root.loginMethod === "apikey") {
      var clientId = (typeof inputClientId !== "undefined" && inputClientId) ? inputClientId.text.trim() : ""
      var clientSecret = (typeof inputClientSecret !== "undefined" && inputClientSecret) ? inputClientSecret.text.trim() : ""
      if (!clientId) {
        if (typeof inputClientId !== "undefined" && inputClientId) inputClientId.forceActiveFocus()
        return
      }
      if (!clientSecret) {
        if (typeof inputClientSecret !== "undefined" && inputClientSecret) inputClientSecret.forceActiveFocus()
        return
      }
      root.doLoginApiKey(clientId, clientSecret)
    }
  }

  function refreshHealth() {
    healthProc.command = [root.helperPath, "health"]
    healthProc.running = true
  }

  function refreshAuthStatus() {
    authStatusProc.command = [root.helperPath, "auth", "status"]
    authStatusProc.running = true
  }

  function syncVault(isBackground) {
    if (!isBackground) {
      root.isBusy = true
      root.statusMessage = "Syncing vault with Bitwarden..."
    }
    vaultSyncProc.command = [root.helperPath, "vault", "sync"]
    vaultSyncProc.running = true
  }

  function loadVaultItems() {
    root.isLoadingVault = true
    vaultListProc.command = [root.helperPath, "vault", "list"]
    vaultListProc.running = true
  }

  function isSubsequence(pattern, text) {
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
        res.push({ item: item, score: item.favorite ? 100 : 0 })
      } else {
        var words = q.split(/\s+/)
        var totalScore = item.favorite ? 100 : 0
        var nameLower = (item.name || "").toLowerCase()
        var subLower = (item.sub_title || "").toLowerCase()
        var searchLower = (item.search_text || "").toLowerCase()
        var notesLower = (item.notes || "").toLowerCase()

        var allWordsMatched = true
        for (var w = 0; w < words.length; w++) {
          var word = words[w]
          if (!word) continue
          var wordMatched = false

          if (nameLower === word) {
            totalScore += 2000
            wordMatched = true
          } else if (nameLower.indexOf(word) === 0) {
            totalScore += 1000
            wordMatched = true
          } else if (nameLower.indexOf(word) !== -1) {
            totalScore += 500
            wordMatched = true
          } else if (subLower.indexOf(word) === 0) {
            totalScore += 400
            wordMatched = true
          } else if (subLower.indexOf(word) !== -1) {
            totalScore += 300
            wordMatched = true
          } else if (searchLower.indexOf(word) !== -1 || notesLower.indexOf(word) !== -1) {
            totalScore += 100
            wordMatched = true
          } else if (root.isSubsequence(word, nameLower)) {
            totalScore += 80
            wordMatched = true
          }

          if (!wordMatched) {
            allWordsMatched = false
            break
          }
        }

        if (allWordsMatched) {
          res.push({ item: item, score: totalScore })
        }
      }
    }

    res.sort(function(a, b) {
      return b.score - a.score
    })

    var out = []
    for (var j = 0; j < res.length; j++) {
      out.push(res[j].item)
    }

    root.filteredItems = out
    root.selectedIndex = 0
    if (typeof itemsList !== "undefined" && itemsList) {
      itemsList.positionViewAtIndex(0, ListView.Beginning)
    }
    root.onSelectedItemChanged()
  }

  onSearchQueryChanged: filterVaultItems()
  onActiveCategoryChanged: filterVaultItems()
  onSelectedIndexChanged: {
    if (typeof itemsList !== "undefined" && itemsList && itemsList.count > 0 && root.selectedIndex >= 0 && root.selectedIndex < itemsList.count) {
      itemsList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
    }
    root.onSelectedItemChanged()
  }

  function updateAvailableActions() {
    root.currentAvailableActions = root.getAvailableActions(root.selectedItem)
  }

  onShowActionPaletteChanged: {
    if (root.showActionPalette) {
      root.actionPaletteIndex = 0
      root.updateAvailableActions()
      Qt.callLater(function() {
        if (typeof actionPaletteFocusScope !== "undefined" && actionPaletteFocusScope) {
          actionPaletteFocusScope.forceActiveFocus()
        }
      })
    }
  }

  onSelectedItemChanged: {
    root.showPasswordRevealed = false
    root.showPrivateKeyRevealed = false
    root.updateTotpForSelected()
    root.updateAvailableActions()
  }

  function updateTotpForSelected() {
    var item = root.selectedItem
    if (item && item.login && item.login.totp) {
      totpGenProc.secret = item.login.totp
      totpGenProc.command = [root.helperPath, "totp", "generate"]
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
    var cmd = [root.helperPath, "clipboard", "copy"]
    if (isSensitive) {
      cmd.push("--sensitive")
    }
    clipCopyProc.secret = text
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
      if (item.login.password) {
        actions.push({ label: "Copy Password", icon: "🔒", action: function() { root.copyToClipboard(item.login.password, true, "password") } })
      }
      if (item.login.username) {
        actions.push({ label: "Copy Username (" + item.login.username + ")", icon: "👤", action: function() { root.copyToClipboard(item.login.username, false, "username") } })
      }
      if ((item.login.totp) || (root.currentTotp && root.currentTotp.code)) {
        var totpLabel = "Copy TOTP Code" + ((root.currentTotp && root.currentTotp.code) ? (" (" + root.currentTotp.code + ")") : "")
        actions.push({
          label: totpLabel,
          icon: "⏱️",
          action: function() {
            if (root.currentTotp && root.currentTotp.code) {
              root.copyToClipboard(root.currentTotp.code, true, "TOTP code")
            }
          }
        })
      }
      if (item.login.uris && item.login.uris.length > 0 && item.login.uris[0].uri) {
        actions.push({ label: "Open URL (" + item.login.uris[0].uri + ")", icon: "🌐", action: function() { Qt.openUrlExternally(item.login.uris[0].uri) } })
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
    if (settings.max_output_mb !== undefined) cmd.push("--max-output-mb", String(settings.max_output_mb))
    
    configSetProc.command = cmd
    configSetProc.running = true
  }

  function doUnlock(password) {
    if (!password) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Unlocking vault..."
    authUnlockProc.secret = password
    authUnlockProc.command = [root.helperPath, "auth", "unlock"]
    authUnlockProc.running = true
  }

  function doLock() {
    root.isBusy = true
    root.searchQuery = ""
    if (typeof searchInput !== "undefined" && searchInput) searchInput.text = ""
    if (typeof inputUnlockPassword !== "undefined" && inputUnlockPassword) inputUnlockPassword.text = ""
    if (typeof inputLoginPassword !== "undefined" && inputLoginPassword) inputLoginPassword.text = ""
    root.activeCategory = "all"
    root.selectedIndex = 0
    root.statusMessage = "Locking vault..."
    authLockProc.command = [root.helperPath, "auth", "lock"]
    authLockProc.running = true
  }

  function doLoginPassword(email, password, code) {
    if (!email || !password) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Logging in to Bitwarden..."
    var cmd = [root.helperPath, "auth", "login-password", "--email", email]
    if (code) cmd.push("--code", code)
    authLoginProc.secret = password
    authLoginProc.command = cmd
    authLoginProc.running = true
  }

  function doLoginApiKey(clientId, clientSecret) {
    if (!clientId || !clientSecret) return
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Authenticating with API Key..."
    authLoginProc.secret = clientSecret
    authLoginProc.command = [root.helperPath, "auth", "login-apikey", "--client-id", clientId]
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

  function extractDomain(uri) {
    if (!uri) return ""
    var str = String(uri).trim()
    if (str.indexOf("://") !== -1) {
      str = str.split("://")[1]
    }
    str = str.split("/")[0]
    str = str.split("?")[0]
    str = str.split("#")[0]
    str = str.split(":")[0]
    if (str.indexOf("@") !== -1) {
      str = str.split("@")[1]
    }
    if (str.indexOf("www.") === 0) {
      str = str.slice(4)
    }
    return str
  }

  function getFaviconUrl(item) {
    if (item && item.type_name === "login" && item.login && item.login.uris && item.login.uris.length > 0 && item.login.uris[0].uri) {
      var dom = root.extractDomain(item.login.uris[0].uri)
      if (dom && dom.indexOf(".") !== -1 && dom !== "localhost") {
        return "https://www.google.com/s2/favicons?domain=" + dom + "&sz=64"
      }
    }
    return ""
  }

  function getCardBrand(item) {
    if (!item) return ""
    var typeName = (typeof item === "string") ? item : (item.type_name || "")
    if (typeName !== "card") return ""
    var brand = ""
    if (typeof item === "object" && item.card) {
      brand = (item.card.brand ? String(item.card.brand) : "")
      if (!brand && item.card.number) {
        var num = String(item.card.number).replace(/\s+/g, "")
        if (num.indexOf("4") === 0) brand = "Visa"
        else if (num.match(/^5[1-5]/) || num.match(/^2[2-7]/)) brand = "Mastercard"
        else if (num.match(/^3[47]/)) brand = "Amex"
        else if (num.match(/^35/)) brand = "JCB"
        else if (num.match(/^6(?:011|5)/)) brand = "Discover"
        else if (num.indexOf("62") === 0) brand = "UnionPay"
      }
    }
    return brand
  }

  function getItemIcon(item) {
    if (!item) return "🌐"
    var typeName = (typeof item === "string") ? item : (item.type_name || "login")
    if (typeName === "card") {
      return "💳"
    } else if (typeName === "ssh_key") {
      return "⚡"
    } else if (typeName === "note") {
      return "📄"
    } else if (typeName === "identity") {
      return "🪪"
    }
    return "🌐"
  }

  property bool isAuthTransitionBusy: root.isBusy && (root.effectiveView === "login" || root.effectiveView === "unlock" || root.statusMessage.indexOf("Locking") !== -1 || root.statusMessage.indexOf("Logging out") !== -1 || root.statusMessage.indexOf("Logging in") !== -1 || root.statusMessage.indexOf("Unlocking") !== -1 || root.statusMessage.indexOf("Authenticating") !== -1)

  Timer {
    id: statusMessageTimer
    interval: 3000
    repeat: false
    onTriggered: root.statusMessage = ""
  }

  onStatusMessageChanged: {
    if (root.statusMessage !== "" && !root.isAuthTransitionBusy) {
      statusMessageTimer.restart()
    }
  }

  onIsBusyChanged: {
    if (!root.isBusy && root.statusMessage !== "") {
      statusMessageTimer.restart()
    }
  }

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
    color: Color.menu.background
    implicitWidth: 920
    implicitHeight: 600
    minimumSize: Qt.size(720, 480)

onVisibleChanged: {
      if (visible) {
        Qt.callLater(function() {
          if (root.effectiveView === "search") searchInput.forceActiveFocus()
          else if (root.effectiveView === "unlock") inputUnlockPassword.forceActiveFocus()
          else if (root.effectiveView === "login") {
            if (typeof inputLoginEmail !== "undefined" && inputLoginEmail && inputLoginEmail.text.trim().length > 0) {
              if (typeof inputLoginPassword !== "undefined" && inputLoginPassword) inputLoginPassword.forceActiveFocus()
            } else {
              if (typeof inputLoginEmail !== "undefined" && inputLoginEmail) inputLoginEmail.forceActiveFocus()
            }
          }
        })
      }
    }

    Shortcut {
      sequence: "Ctrl+Return"
      enabled: root.opened && root.effectiveView === "login" && !root.isBusy
      onActivated: root.submitLoginForm()
    }

    Shortcut {
      sequence: "Ctrl+Enter"
      enabled: root.opened && root.effectiveView === "login" && !root.isBusy
      onActivated: root.submitLoginForm()
    }

    Shortcut {
      sequence: "Ctrl+K"
      enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null
      onActivated: {
        root.actionPaletteIndex = 0
        root.showActionPalette = true
        Qt.callLater(function() { actionPaletteFocusScope.forceActiveFocus() })
      }
    }

    Shortcut {
      sequence: "Ctrl+L"
      enabled: root.opened && root.authState.status === "unlocked"
      onActivated: root.doLock()
    }

    Shortcut {
      sequence: "Ctrl+R"
      enabled: root.opened && root.authState.status === "unlocked" && !root.isBusy
      onActivated: root.syncVault()
    }

        Shortcut {
      sequence: "Ctrl+,"
      enabled: root.opened
      onActivated: {
        root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
      }
    }

    Shortcut {
      sequence: "Escape"
      enabled: root.opened
      onActivated: {
        if (root.showActionPalette) {
          root.showActionPalette = false
          Qt.callLater(function() { searchInput.forceActiveFocus() })
        } else {
          root.dismiss()
        }
      }
    }

    FocusScope {
      id: focusRoot
      anchors.fill: parent
      focus: true

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (root.showActionPalette) {
          var actions = root.currentAvailableActions || []
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

          Button {
            visible: root.authState.status === "unlocked" && root.selectedItem !== null
            text: "Actions (Ctrl+K)"
            onClicked: {
              root.actionPaletteIndex = 0
              root.showActionPalette = true
            }
          }

          Button {
            visible: root.authState.status === "unlocked"
            text: "Sync (Ctrl+R)"
            enabled: !root.isBusy
            onClicked: root.syncVault()
          }

          Button {
            visible: root.authState.status === "unlocked"
            text: "Lock (Ctrl+L)"
            onClicked: root.doLock()
          }

          Button {
            text: root.effectiveView === "settings" ? "Back" : "Settings (Ctrl+,)"
            onClicked: {
              root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
            }
          }
        }

        Rectangle {
          visible: (root.errorMessage !== "") || (!root.isAuthTransitionBusy && root.statusMessage !== "")
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

        // 0. AUTH / BUSY LOADING VIEW
        Item {
          visible: root.isAuthTransitionBusy
          Layout.fillWidth: true
          Layout.fillHeight: true

          ColumnLayout {
            anchors.centerIn: parent
            width: Math.min(parent.width, 420)
            spacing: 14

            Text {
              text: {
                if (root.statusMessage.indexOf("Logging in") !== -1) return "Logging in..."
                if (root.statusMessage.indexOf("Unlocking") !== -1) return "Unlocking vault..."
                if (root.statusMessage.indexOf("Locking") !== -1) return "Locking vault..."
                if (root.statusMessage.indexOf("Logging out") !== -1) return "Logging out..."
                if (root.statusMessage.indexOf("Authenticating") !== -1) return "Authenticating..."
                if (root.statusMessage) return root.statusMessage
                return "Loading..."
              }
              color: root.foreground
              font.pixelSize: Style.font.heading + 4
              font.bold: true
              horizontalAlignment: Text.AlignHCenter
              Layout.alignment: Qt.AlignHCenter
              Layout.fillWidth: true
            }

            Text {
              text: "Please wait a moment..."
              color: Qt.darker(root.foreground, 1.4)
              font.pixelSize: Style.font.bodySmall
              horizontalAlignment: Text.AlignHCenter
              Layout.alignment: Qt.AlignHCenter
              Layout.fillWidth: true
            }

            Rectangle {
              Layout.alignment: Qt.AlignHCenter
              implicitWidth: loadingServerBadgeRow.implicitWidth + 16
              implicitHeight: 26
              radius: 13
              color: Qt.rgba(1, 1, 1, 0.07)
              border.color: Qt.rgba(1, 1, 1, 0.15)

              RowLayout {
                id: loadingServerBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Text {
                  text: "🌐"
                  font.pixelSize: Style.font.caption
                }

                Text {
                  text: (root.config && root.config.server_url) ? root.config.server_url : "https://vault.bitwarden.com"
                  color: root.accent
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }
            }
          }
        }

        // 1. UNLOCK VIEW
        ColumnLayout {
          visible: !root.isAuthTransitionBusy && root.effectiveView === "unlock"
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

            Rectangle {
              Layout.alignment: Qt.AlignHCenter
              implicitWidth: unlockServerBadgeRow.implicitWidth + 16
              implicitHeight: 26
              radius: 13
              color: Qt.rgba(1, 1, 1, 0.07)
              border.color: Qt.rgba(1, 1, 1, 0.15)

              RowLayout {
                id: unlockServerBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Text {
                  text: "🌐 Server:"
                  color: Qt.darker(root.foreground, 1.4)
                  font.pixelSize: Style.font.caption
                }

                Text {
                  text: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "https://vault.bitwarden.com"
                  color: root.accent
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }
            }

            TextField {
              id: inputUnlockPassword
              Layout.fillWidth: true
              echoMode: TextInput.Password
              placeholderText: "Master Password / PIN"
              font.pixelSize: Style.font.body
              focus: root.effectiveView === "unlock"
              onAccepted: root.doUnlock(text)
            }

            Button {
              Layout.fillWidth: true
              text: root.isBusy ? "Unlocking..." : "Unlock Vault"
              selected: true
              enabled: !root.isBusy && inputUnlockPassword.text.length > 0
              onClicked: root.doUnlock(inputUnlockPassword.text)
            }

            RowLayout {
              Layout.alignment: Qt.AlignHCenter
              Button {
                text: "Logout Account"
                onClicked: root.doLogout()
              }
            }
          }

          Item { Layout.fillHeight: true }
        }

        // 2. LOGIN VIEW
        ColumnLayout {
          visible: !root.isAuthTransitionBusy && root.effectiveView === "login"
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

            Rectangle {
              Layout.alignment: Qt.AlignHCenter
              implicitWidth: loginServerBadgeRow.implicitWidth + 16
              implicitHeight: 26
              radius: 13
              color: Qt.rgba(1, 1, 1, 0.07)
              border.color: Qt.rgba(1, 1, 1, 0.15)

              RowLayout {
                id: loginServerBadgeRow
                anchors.centerIn: parent
                spacing: 6

                Text {
                  text: "🌐 Server:"
                  color: Qt.darker(root.foreground, 1.4)
                  font.pixelSize: Style.font.caption
                }

                Text {
                  text: (root.config && root.config.server_url) ? root.config.server_url : "https://vault.bitwarden.com"
                  color: root.accent
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Text {
                  text: "(Change in Settings)"
                  color: Qt.darker(root.foreground, 1.3)
                  font.pixelSize: Style.font.caption
                }
              }

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.currentView = "settings"
                }
              }
            }

            RowLayout {
              Layout.alignment: Qt.AlignHCenter
              spacing: 8
              Button {
                text: "Master Password"
                selected: root.loginMethod === "password"
                onClicked: { root.loginMethod = "password" }
              }
              Button {
                text: "API Key"
                selected: root.loginMethod === "apikey"
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
                text: (root.config && root.config.remember_email && root.config.email) ? root.config.email : ""
                font.pixelSize: Style.font.body
                focus: root.effectiveView === "login" && (!root.config || !root.config.remember_email || !root.config.email)
                Keys.onReturnPressed: (event) => {
                  if (event.modifiers & Qt.ControlModifier) {
                    root.submitLoginForm()
                  } else {
                    inputLoginPassword.forceActiveFocus()
                  }
                }
                Keys.onEnterPressed: (event) => {
                  if (event.modifiers & Qt.ControlModifier) {
                    root.submitLoginForm()
                  } else {
                    inputLoginPassword.forceActiveFocus()
                  }
                }
              }

              TextField {
                id: inputLoginPassword
                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: "Master Password"
                font.pixelSize: Style.font.body
                focus: root.effectiveView === "login" && (root.config && root.config.remember_email && root.config.email && root.config.email.length > 0)
                Keys.onReturnPressed: (event) => { root.submitLoginForm() }
                Keys.onEnterPressed: (event) => { root.submitLoginForm() }
              }

              TextField {
                id: inputLogin2FA
                visible: root.show2FAField
                Layout.fillWidth: true
                placeholderText: "2FA Verification Code (from Authenticator)"
                font.pixelSize: Style.font.body
                Keys.onReturnPressed: (event) => { root.submitLoginForm() }
                Keys.onEnterPressed: (event) => { root.submitLoginForm() }
              }

              RowLayout {
                Layout.fillWidth: true
                spacing: 8

                MouseArea {
                  id: rememberEmailArea
                  Layout.preferredHeight: 22
                  Layout.fillWidth: true
                  cursorShape: Qt.PointingHandCursor
                  hoverEnabled: true
                  onClicked: {
                    root.rememberEmailChecked = !root.rememberEmailChecked
                  }

                  RowLayout {
                    anchors.fill: parent
                    spacing: 8

                    Rectangle {
                      width: 16
                      height: 16
                      radius: 3
                      color: root.rememberEmailChecked ? root.accent : "transparent"
                      border.color: root.rememberEmailChecked ? root.accent : (rememberEmailArea.containsMouse ? root.foreground : Qt.rgba(1, 1, 1, 0.2))
                      border.width: 1

                      Text {
                        anchors.centerIn: parent
                        text: "✓"
                        color: root.background
                        font.pixelSize: 11
                        font.bold: true
                        visible: root.rememberEmailChecked
                      }
                    }

                    Text {
                      text: "Remember email"
                      color: rememberEmailArea.containsMouse ? root.foreground : Qt.darker(root.foreground, 1.3)
                      font.pixelSize: Style.font.bodySmall
                      Layout.fillWidth: true
                    }
                  }
                }
              }

              Button {
                Layout.fillWidth: true
                text: root.isBusy ? "Logging in..." : (root.show2FAField ? "Verify 2FA & Log In" : "Log In")
                selected: true
                enabled: !root.isBusy && inputLoginEmail.text.length > 0 && inputLoginPassword.text.length > 0
                onClicked: root.submitLoginForm()
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
                Keys.onReturnPressed: (event) => {
                  if (event.modifiers & Qt.ControlModifier) {
                    root.submitLoginForm()
                  } else {
                    inputClientSecret.forceActiveFocus()
                  }
                }
                Keys.onEnterPressed: (event) => {
                  if (event.modifiers & Qt.ControlModifier) {
                    root.submitLoginForm()
                  } else {
                    inputClientSecret.forceActiveFocus()
                  }
                }
              }

              TextField {
                id: inputClientSecret
                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: "client_secret"
                font.pixelSize: Style.font.body
                Keys.onReturnPressed: (event) => { root.submitLoginForm() }
                Keys.onEnterPressed: (event) => { root.submitLoginForm() }
              }

              Button {
                Layout.fillWidth: true
                text: root.isBusy ? "Authenticating..." : "Log In with API Key"
                selected: true
                enabled: !root.isBusy && inputClientId.text.length > 0 && inputClientSecret.text.length > 0
                onClicked: root.submitLoginForm()
              }
            }
          }

          Item { Layout.fillHeight: true }
        }

        // 3. SETTINGS VIEW
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

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4
              Text {
                text: "Max Vault Payload Bound (MB):"
                color: root.foreground
                font.pixelSize: Style.font.bodySmall
              }
              TextField {
                id: inputMaxOutputMb
                Layout.fillWidth: true
                text: String(root.config.max_output_mb ?? 10)
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
              selected: true
              onClicked: {
                var autoLockVal = parseInt(inputAutoLock.text.trim())
                var clipClearVal = parseInt(inputClipClear.text.trim())
                var maxOutputVal = parseInt(inputMaxOutputMb.text.trim())
                root.saveSettings({
                  server_url: inputServerUrl.text.trim(),
                  bw_path: inputBwPath.text.trim(),
                  auto_lock_minutes: isNaN(autoLockVal) ? 15 : autoLockVal,
                  clipboard_clear_seconds: isNaN(clipClearVal) ? 30 : clipClearVal,
                  max_output_mb: isNaN(maxOutputVal) ? 10 : maxOutputVal
                })
              }
            }
            Item { Layout.fillWidth: true }
          }

          Item { Layout.fillHeight: true }
        }

        // 4. VAULT SEARCH & INSPECTOR VIEW
        ColumnLayout {
          visible: !root.isAuthTransitionBusy && root.effectiveView === "search"
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: 10

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
            Keys.onDownPressed: function(event) {
              if (root.filteredItems.length > 0 && root.selectedIndex < root.filteredItems.length - 1) {
                root.selectedIndex += 1
                event.accepted = true
              }
            }
            Keys.onUpPressed: function(event) {
              if (root.filteredItems.length > 0 && root.selectedIndex > 0) {
                root.selectedIndex -= 1
                event.accepted = true
              }
            }
            focus: root.effectiveView === "search" && !root.showActionPalette
          }

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Button {
              text: "All (" + root.getCategoryCount("all") + ")"
              selected: root.activeCategory === "all"
              onClicked: root.activeCategory = "all"
            }
            Button {
              text: "Logins (" + root.getCategoryCount("login") + ")"
              selected: root.activeCategory === "login"
              onClicked: root.activeCategory = "login"
            }
            Button {
              text: "Cards (" + root.getCategoryCount("card") + ")"
              selected: root.activeCategory === "card"
              onClicked: root.activeCategory = "card"
            }
            Button {
              text: "Identities (" + root.getCategoryCount("identity") + ")"
              selected: root.activeCategory === "identity"
              onClicked: root.activeCategory = "identity"
            }
            Button {
              text: "Notes (" + root.getCategoryCount("note") + ")"
              selected: root.activeCategory === "note"
              onClicked: root.activeCategory = "note"
            }
            Button {
              text: "SSH Keys (" + root.getCategoryCount("ssh_key") + ")"
              selected: root.activeCategory === "ssh_key"
              onClicked: root.activeCategory = "ssh_key"
            }

            Item { Layout.fillWidth: true }

            Text {
              text: root.isBusy ? "Syncing..." : (root.filteredItems.length + " items")
              color: Qt.darker(root.foreground, 1.4)
              font.pixelSize: Style.font.caption
            }
          }

          RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 12

            BorderSurface {
              Layout.fillWidth: true
              Layout.fillHeight: true
              Layout.preferredWidth: 380
              radius: Style.cornerRadius
              color: Style.controlFill(false, false, root.foreground, root.accent)
              borderSpec: Border.controlSpec("normal", root.foreground, root.accent)
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
                  color: (index === root.selectedIndex) ? root.accent : "transparent"
                  border.color: (index === root.selectedIndex) ? root.accent : "transparent"

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 10
                    anchors.rightMargin: 10
                    spacing: 10

                    Item {
                      width: 22
                      height: 22
                      Layout.alignment: Qt.AlignVCenter

                      Image {
                        id: faviconImg
                        anchors.fill: parent
                        fillMode: Image.PreserveAspectFit
                        source: root.getFaviconUrl(modelData)
                        visible: source !== "" && status === Image.Ready
                        asynchronous: true
                        smooth: true
                      }

                      Text {
                        anchors.centerIn: parent
                        visible: !faviconImg.visible
                        text: root.getItemIcon(modelData)
                        font.pixelSize: 16
                        color: (index === root.selectedIndex) ? "#ffffff" : root.foreground
                      }
                    }

                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: 2

                      RowLayout {
                        spacing: 6
                        Text {
                          text: modelData.name || "Untitled"
                          color: (index === root.selectedIndex) ? "#ffffff" : root.foreground
                          font.pixelSize: Style.font.body
                          font.bold: true
                        }
                        Text {
                          visible: modelData.favorite
                          text: "★"
                          color: (index === root.selectedIndex) ? Qt.rgba(1, 1, 1, 0.9) : root.accent
                          font.pixelSize: Style.font.caption
                        }
                      }

                      Text {
                        text: modelData.sub_title || modelData.type_name
                        color: (index === root.selectedIndex) ? Qt.rgba(1, 1, 1, 0.85) : Qt.darker(root.foreground, 1.4)
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
                        text: {
                          if (modelData.type_name === "ssh_key") return "SSH"
                          if (modelData.type_name === "card") {
                            var b = root.getCardBrand(modelData)
                            return b ? b.toUpperCase() : "CARD"
                          }
                          return modelData.type_name.toUpperCase()
                        }
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
                  visible: root.filteredItems.length === 0
                  anchors.centerIn: parent
                  text: root.isLoadingVault ? "Loading vault items..." : (root.rawVaultItems.length === 0 ? "Vault is empty. Click 'Sync' to load." : "No matching items.")
                  color: Qt.darker(root.foreground, 1.4)
                  font.pixelSize: Style.font.body
                }
              }
            }

            BorderSurface {
              Layout.fillWidth: true
              Layout.fillHeight: true
              Layout.preferredWidth: 360
              radius: Style.cornerRadius
              color: Style.controlFill(false, false, root.foreground, root.accent)
              borderSpec: Border.controlSpec("normal", root.foreground, root.accent)
              clip: true

              ScrollView {
                anchors.fill: parent
                anchors.margins: 14
                contentWidth: width

                ColumnLayout {
                  width: parent.width
                  spacing: 12

                  RowLayout {
                    spacing: 10
                    Layout.fillWidth: true

                    Item {
                      width: 32
                      height: 32
                      Layout.alignment: Qt.AlignVCenter

                      Image {
                        id: inspFaviconImg
                        anchors.fill: parent
                        fillMode: Image.PreserveAspectFit
                        source: root.selectedItem ? root.getFaviconUrl(root.selectedItem) : ""
                        visible: source !== "" && status === Image.Ready
                        asynchronous: true
                        smooth: true
                      }

                      Text {
                        anchors.centerIn: parent
                        visible: !inspFaviconImg.visible
                        text: root.selectedItem ? root.getItemIcon(root.selectedItem) : "🌐"
                        font.pixelSize: 24
                        color: root.foreground
                      }
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
                        text: {
                          if (!root.selectedItem) return ""
                          var cat = root.selectedItem.type_name
                          if (cat === "card") {
                            var b = root.getCardBrand(root.selectedItem)
                            cat = b ? (b.toUpperCase() + " CARD") : "CARD"
                          } else if (cat === "ssh_key") {
                            cat = "SSH KEY"
                          } else {
                            cat = cat.toUpperCase()
                          }
                          return cat + (root.selectedItem.favorite ? " • Favorite" : "")
                        }
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

      // Action Palette Modal (Ctrl+K)
      Rectangle {
        id: actionPaletteOverlay
        z: 100
        visible: root.showActionPalette
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.65)

        MouseArea {
          anchors.fill: parent
          onClicked: {
            root.showActionPalette = false
            Qt.callLater(function() { searchInput.forceActiveFocus() })
          }
        }

        Rectangle {
          anchors.centerIn: parent
          width: Math.min(480, parent.width - 40)
          height: Math.min(360, parent.height - 40)
          radius: 10
          color: root.background
          border.color: root.border
          clip: true

          MouseArea {
            anchors.fill: parent
          }

          FocusScope {
            id: actionPaletteFocusScope
            anchors.fill: parent
            focus: root.showActionPalette

            Keys.priority: Keys.BeforeItem
            Keys.onPressed: function(event) {
              var actions = root.currentAvailableActions || []
              if (event.key === Qt.Key_Escape) {
                root.showActionPalette = false
                Qt.callLater(function() { searchInput.forceActiveFocus() })
                event.accepted = true
              } else if (event.key === Qt.Key_Down) {
                if (actions.length > 0 && root.actionPaletteIndex < actions.length - 1) {
                  root.actionPaletteIndex += 1
                }
                event.accepted = true
              } else if (event.key === Qt.Key_Up) {
                if (actions.length > 0 && root.actionPaletteIndex > 0) {
                  root.actionPaletteIndex -= 1
                }
                event.accepted = true
              } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                if (actions.length > 0 && root.actionPaletteIndex < actions.length) {
                  actions[root.actionPaletteIndex].action()
                  root.showActionPalette = false
                  Qt.callLater(function() { searchInput.forceActiveFocus() })
                }
                event.accepted = true
              }
            }

            ColumnLayout {
              anchors.fill: parent
              anchors.margins: 14
              spacing: 8

              RowLayout {
                Layout.fillWidth: true
                Text {
                  text: "Actions: " + (root.selectedItem ? root.selectedItem.name : "Item")
                  color: root.foreground
                  font.pixelSize: Style.font.title
                  font.bold: true
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                }
                Button {
                  text: "Esc"
                  onClicked: {
                    root.showActionPalette = false
                    Qt.callLater(function() { searchInput.forceActiveFocus() })
                  }
                }
              }

              Rectangle { Layout.fillWidth: true; height: 1; color: root.border }

              ListView {
                id: actionsList
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: root.currentAvailableActions
                currentIndex: root.actionPaletteIndex

                delegate: Rectangle {
                  width: actionsList.width
                  height: 42
                  radius: 6
                  color: (index === root.actionPaletteIndex) ? root.accent : "transparent"

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12
                    spacing: 10

                    Text { text: modelData.icon; font.pixelSize: 18 }
                    Text {
                      text: modelData.label
                      color: (index === root.actionPaletteIndex) ? "#ffffff" : root.foreground
                      font.pixelSize: Style.font.body
                      font.bold: index === root.actionPaletteIndex
                      Layout.fillWidth: true
                    }
                    Text {
                      text: index === 0 ? "(Primary / Enter)" : ""
                      color: (index === root.actionPaletteIndex) ? Qt.rgba(1, 1, 1, 0.7) : Qt.darker(root.foreground, 1.4)
                      font.pixelSize: Style.font.caption
                    }
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onEntered: root.actionPaletteIndex = index
                    onClicked: {
                      modelData.action()
                      root.showActionPalette = false
                      Qt.callLater(function() { searchInput.forceActiveFocus() })
                    }
                  }
                }

                Text {
                  visible: !root.currentAvailableActions || root.currentAvailableActions.length === 0
                  anchors.centerIn: parent
                  text: "No actions available for this item."
                  color: Qt.darker(root.foreground, 1.4)
                  font.pixelSize: Style.font.body
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
          if (data.remember_email !== undefined) {
            root.rememberEmailChecked = (data.remember_email !== false)
          }
          if (data.email && root.rememberEmailChecked) {
            if (typeof inputLoginEmail !== "undefined" && inputLoginEmail && !inputLoginEmail.text) {
              inputLoginEmail.text = data.email
            }
          }
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
            root.loadVaultItems()
            root.syncVault(true)
          }
        } catch (e) {}
      }
    }
  }

  Process {
    id: authUnlockProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = "Vault unlocked successfully."
            root.searchQuery = ""
            if (typeof searchInput !== "undefined" && searchInput) searchInput.text = ""
            if (typeof inputUnlockPassword !== "undefined" && inputUnlockPassword) inputUnlockPassword.text = ""
            root.authState = ({
              status: "unlocked",
              server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
              user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
              has_session: true
            })
            root.refreshAuthStatus()
            if (data.session) {
              root.loadVaultItems()
              root.syncVault(true)
            }
          } else {
            root.errorMessage = data.error || "Unlock failed."
          }
        } catch (e) {
          root.errorMessage = "Failed to parse unlock response."
        }
        root.isBusy = false
      }
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) root.errorMessage = "Unlock command failed."
    }
  }

  Process {
    id: authLoginProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            root.statusMessage = "Logged in successfully."
            root.searchQuery = ""
            if (typeof searchInput !== "undefined" && searchInput) searchInput.text = ""

            // Save or clear remembered email in config
            if (root.loginMethod === "password" && typeof inputLoginEmail !== "undefined" && inputLoginEmail) {
              var emailToSave = root.rememberEmailChecked ? inputLoginEmail.text.trim() : ""
              root.updateConfig({
                email: emailToSave,
                remember_email: root.rememberEmailChecked
              })
            }

            root.show2FAField = false
            if (typeof inputLogin2FA !== "undefined" && inputLogin2FA) inputLogin2FA.text = ""
            if (typeof inputLoginPassword !== "undefined" && inputLoginPassword) inputLoginPassword.text = ""

            root.authState = ({
              status: data.status || "unlocked",
              server_url: (root.config && root.config.server_url) || "",
              user_email: (typeof inputLoginEmail !== "undefined" && inputLoginEmail) ? inputLoginEmail.text.trim() : "",
              has_session: Boolean(data.session)
            })
            root.refreshAuthStatus()
            if (data.session) {
              root.loadVaultItems()
              root.syncVault(true)
            }
          } else {
            root.errorMessage = data.error || "Login failed."
            var errLower = (data.error || "").toLowerCase()
            if (errLower.indexOf("two-step") !== -1 || errLower.indexOf("two-factor") !== -1 || errLower.indexOf("code") !== -1) {
              root.show2FAField = true
              Qt.callLater(function() {
                if (typeof inputLogin2FA !== "undefined" && inputLogin2FA) {
                  inputLogin2FA.forceActiveFocus()
                }
              })
            }
          }
        } catch (e) {
          root.errorMessage = "Failed to parse login response."
        }
        root.isBusy = false
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
        root.authState = ({
          status: "locked",
          server_url: (root.authState && root.authState.server_url) || "",
          user_email: (root.authState && root.authState.user_email) || "",
          has_session: false
        })
        root.rawVaultItems = []
        root.filteredItems = []
        root.refreshAuthStatus()
        root.isBusy = false
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
        root.authState = ({
          status: "unauthenticated",
          server_url: "",
          user_email: "",
          has_session: false
        })
        root.rawVaultItems = []
        root.filteredItems = []
        root.refreshAuthStatus()
        root.isBusy = false
      }
    }
    onExited: function(code) {
      root.isBusy = false
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
          root.isLoadingVault = false
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
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
    command: []
  }

  Process {
    id: totpGenProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      if (secret) {
        write(secret + "\n")
        secret = ""
      }
    }
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
