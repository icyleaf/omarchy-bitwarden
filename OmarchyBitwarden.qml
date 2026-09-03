import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "./components"

Item {
  id: root

  Component.onCompleted: {
    root.refreshConfig()
    root.refreshHealth()
    root.refreshAuthStatus()
    root.checkUpdates(false)
  }

  property var shell: null
  property var manifest: null
  property bool opened: false
  function toLocalPath(url) {
    if (!url) return ""
    var str = url.toString ? url.toString() : String(url)
    return str.replace(/^file:\/+/i, "/")
  }

  property string helperPath: {
    var custom = Quickshell.env("OMARCHY_BITWARDEN_HELPER")
    if (custom) return custom
    var localPath = root.toLocalPath(Qt.resolvedUrl("bin/omawarden"))
    if (localPath) return localPath
    var pluginDir = Quickshell.env("XDG_CONFIG_HOME") || (Quickshell.env("HOME") + "/.config")
    var baseDir = pluginDir + "/omarchy/plugins/icyleaf.bitwarden/bin"
    return baseDir + "/omawarden"
  }

  // Configuration & Engine Health State
  property var config: ({
    server_url: "https://vault.bitwarden.com",
    download_dir: "~/Downloads",
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
    server_reachable: false,
    keyring_available: false,
    clipboard_available: false,
    error: "Checking CLI status..."
  })
  property bool isDownloadingCli: false
  property string latestVersion: ""
  property bool isCheckingUpdate: false
  property string updateCheckStatus: ""
  readonly property bool updateAvailable: {
    if (!latestVersion) return false
    var currentVer = (cliHealth && cliHealth.version) ? cliHealth.version : ""
    if (!currentVer) return false
    return compareSemVer(latestVersion, currentVer) > 0
  }

  property var authState: ({
    status: "unauthenticated",
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
  property var activeAttachmentPreview: null
  property string loadingAttachmentId: ""

  property string currentView: "auto"
  property string loginMethod: "password"
  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property bool isLoadingVault: false
  property bool lastSyncWasManual: false
  property real lastSyncTime: 0
  property int syncCooldownSeconds: 300
  property string lastVaultItemsRawText: ""
  property var logBuffer: []

  readonly property color background: Color.menu.background
  readonly property color foreground: Color.menu.text
  readonly property color borderColor: Color.menu.border
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

  onCurrentViewChanged: {
    if (root.currentView === "settings" || root.effectiveView === "settings") {
      root.refreshHealth()
      root.refreshConfig()
    }
  }

  onEffectiveViewChanged: {
    Qt.callLater(function() {
      if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField) {
        searchHeader.searchField.forceActiveFocus()
      } else if (root.opened && authViewComponent && authViewComponent.unlockInput) {
        authViewComponent.unlockInput.forceActiveFocus()
      }
    })
  }

  function open(payloadJson) {
    root.opened = true
    root.errorMessage = ""
    root.statusMessage = ""
    root.currentView = "auto"
    root.showActionPalette = false
    root.showPasswordRevealed = false
    root.showPrivateKeyRevealed = false
    root.activeAttachmentPreview = null
    root.loadingAttachmentId = ""
    root.searchQuery = ""
    root.refreshHealth()
    root.refreshConfig()
    root.refreshAuthStatus()
    root.checkUpdates(false)
    if (root.authState.status === "unlocked") {
      if (!root.rawVaultItems || root.rawVaultItems.length === 0) root.loadVaultItems()
      root.syncVault(true, false)
    }
    Qt.callLater(function() {
      if (root.effectiveView === "search" && searchHeader && searchHeader.searchField) {
        searchHeader.searchField.forceActiveFocus()
      } else if (authViewComponent && authViewComponent.unlockInput) {
        authViewComponent.unlockInput.forceActiveFocus()
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
    if (options.download_dir !== undefined) cmd.push("--download-dir", options.download_dir)
    if (options.auto_lock_minutes !== undefined) cmd.push("--auto-lock", String(options.auto_lock_minutes))
    if (options.clipboard_clear_seconds !== undefined) cmd.push("--clipboard-clear", String(options.clipboard_clear_seconds))
    if (options.max_output_mb !== undefined) cmd.push("--max-output-mb", String(options.max_output_mb))
    if (options.email !== undefined) cmd.push("--email", options.email)
    if (options.remember_email !== undefined) cmd.push("--remember-email", options.remember_email ? "true" : "false")
    configSetProc.command = cmd
    configSetProc.running = true
  }

  function downloadCli() {
    if (root.isDownloadingCli) return
    root.isDownloadingCli = true
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Downloading omawarden backend engine..."

    var localDir = root.toLocalPath(Qt.resolvedUrl("bin"))
    var pluginDir = Quickshell.env("XDG_CONFIG_HOME") || (Quickshell.env("HOME") + "/.config")
    var baseDir = localDir || (pluginDir + "/omarchy/plugins/icyleaf.bitwarden/bin")
    var scriptPath = root.toLocalPath(Qt.resolvedUrl("scripts/download-engine.sh"))

    downloadCliProc.running = false
    downloadCliProc.command = ["bash", scriptPath, baseDir]
    downloadCliProc.running = true
  }

  function parseSemVer(v) {
    if (!v) return [0, 0, 0]
    var clean = String(v).replace(/^omawarden-|^v/i, "").trim()
    var parts = clean.split("-")[0].split(".")
    var major = parseInt(parts[0]) || 0
    var minor = parseInt(parts[1]) || 0
    var patch = parseInt(parts[2]) || 0
    return [major, minor, patch]
  }

  function compareSemVer(v1, v2) {
    var a = parseSemVer(v1)
    var b = parseSemVer(v2)
    for (var i = 0; i < 3; i++) {
      if (a[i] > b[i]) return 1
      if (a[i] < b[i]) return -1
    }
    return 0
  }

  function checkUpdates(isManual) {
    if (root.isCheckingUpdate) return
    root.isCheckingUpdate = true
    if (isManual) {
      root.updateCheckStatus = "Checking for updates..."
    }

    var scriptPath = root.toLocalPath(Qt.resolvedUrl("scripts/check-update.sh"))
    updateCheckProc.running = false
    updateCheckProc.command = ["bash", scriptPath]
    updateCheckProc.running = true
  }

  function refreshHealth() {
    healthProc.running = false
    healthProc.command = [root.helperPath, "health"]
    healthProc.running = true
  }

  function refreshAuthStatus() {
    authStatusProc.command = [root.helperPath, "auth", "status"]
    authStatusProc.running = true
  }

  function syncVault(isBackground, force) {
    if (vaultSyncProc.running) return
    var now = Date.now()
    if (isBackground && !force) {
      if (root.lastSyncTime > 0 && (now - root.lastSyncTime) < (root.syncCooldownSeconds * 1000)) {
        return
      }
    }
    root.logInfo("omarchy:vault", "Starting vault sync (manual: " + (!isBackground) + ", force: " + Boolean(force) + ")...")
    root.lastSyncWasManual = !isBackground
    root.isBusy = true
    root.statusMessage = "Syncing vault with Bitwarden..."
    vaultSyncProc.command = [root.helperPath, "vault", "sync"]
    vaultSyncProc.running = true
  }

  function loadVaultItems() {
    root.logInfo("omarchy:vault", "Loading vault items from local daemon/engine...")
    root.isLoadingVault = true
    vaultListProc.command = [root.helperPath, "vault", "list"]
    vaultListProc.running = true
  }

  function isAttachmentPreviewable(filename) {
    if (!filename) return false
    var dotIdx = filename.lastIndexOf(".")
    if (dotIdx === -1) return false
    var ext = filename.slice(dotIdx + 1).toLowerCase()
    var previewableExts = [
      "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
      "txt", "md", "markdown", "json", "yaml", "yml", "toml", "csv", "tsv", "log",
      "sh", "bash", "zsh", "py", "js", "ts", "jsx", "tsx", "html", "htm", "css", "scss", "sass", "less",
      "xml", "conf", "config", "ini", "env", "pem", "key", "pub", "crt", "cer",
      "diff", "patch", "sql", "lua", "c", "cpp", "cc", "cxx", "h", "hpp", "rs", "go", "java", "kt", "kts", "rb", "php"
    ]
    return previewableExts.indexOf(ext) !== -1
  }

  function sanitizeServerUrl(url) {
    if (!url || !url.trim()) return "Default (https://vault.bitwarden.com)"
    var trimmed = url.trim()
    var lower = trimmed.toLowerCase()
    if (lower === "https://vault.bitwarden.com" || lower === "http://vault.bitwarden.com") {
      return "Official Cloud (https://vault.bitwarden.com)"
    }
    if (lower === "https://vault.bitwarden.eu" || lower === "http://vault.bitwarden.eu") {
      return "Official Cloud (https://vault.bitwarden.eu)"
    }
    var scheme = (lower.indexOf("http://") === 0) ? "http" : "https"
    if (lower.indexOf("127.0.0.1") !== -1 || lower.indexOf("localhost") !== -1 || lower.indexOf("192.168.") !== -1 || lower.indexOf("10.") !== -1 || lower.indexOf("172.") !== -1) {
      return "Self-Hosted / Local IP (" + scheme + "://<REDACTED_LOCAL_IP>)"
    }
    return "Self-Hosted / Custom (" + scheme + "://<REDACTED_CUSTOM_HOST>)"
  }

  function sanitizeLog(text) {
    if (!text) return ""
    var str = String(text)
    str = str.replace(/bearer\s+[a-z0-9_\-\.]+/gi, "Bearer <REDACTED>")
    str = str.replace(/("password"|"masterPasswordHash"|"master_password_hash")\s*:\s*"[^"]*"/gi, '$1:"<REDACTED>"')
    str = str.replace(/("client_secret"|"clientSecret"|"userKey"|"privateKey")\s*:\s*"[^"]*"/gi, '$1:"<REDACTED>"')
    return str
  }

  function appendLog(level, source, message) {
    var sanitized = root.sanitizeLog(message)
    if (!sanitized || sanitized.trim().length === 0) return
    var ts = new Date().toISOString()
    var entry = {
      timestamp: ts,
      level: level.toUpperCase(),
      source: source || "omarchy:ui",
      message: sanitized.trim()
    }

    var buf = root.logBuffer.slice()
    buf.push(entry)
    if (buf.length > 500) {
      buf.shift()
    }
    root.logBuffer = buf

    var formatted = "[" + ts + "] [" + entry.level + "] [" + entry.source + "] " + entry.message
    if (entry.level === "ERROR") {
      console.error(formatted)
    } else if (entry.level === "WARN") {
      console.warn(formatted)
    } else {
      console.log(formatted)
    }
  }

  function logError(source, msg) { root.appendLog("ERROR", source, msg) }
  function logWarn(source, msg) { root.appendLog("WARN", source, msg) }
  function logInfo(source, msg) { root.appendLog("INFO", source, msg) }
  function logDebug(source, msg) { root.appendLog("DEBUG", source, msg) }

  function handleProcessStderr(text, defaultSource) {
    if (!text) return
    var lines = String(text).split("\n")
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim()
      if (!line) continue
      var match = line.match(/^(?:\[([0-9T:\-\.Z]+)\]\s+)?\[(ERROR|WARN|INFO|DEBUG|TRACE)\]\s+\[([^\]]+)\]\s+(.*)$/i)
      if (match) {
        var ts = match[1] || new Date().toISOString()
        var lvl = match[2].toUpperCase()
        var src = match[3]
        var msg = match[4]
        var entry = {
          timestamp: ts,
          level: lvl,
          source: src,
          message: root.sanitizeLog(msg)
        }
        var buf = root.logBuffer.slice()
        buf.push(entry)
        if (buf.length > 500) buf.shift()
        root.logBuffer = buf
        if (lvl === "ERROR") console.error(line)
        else if (lvl === "WARN") console.warn(line)
        else console.log(line)
      } else {
        root.logError(defaultSource || "omawarden:cli", line)
      }
    }
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

  function filterVaultItems(resetSelection) {
    var currentId = (root.selectedItem && !resetSelection) ? root.selectedItem.id : null
    var q = (root.searchQuery || "").trim().toLowerCase()
    var cat = root.activeCategory
    var items = root.rawVaultItems || []

    var res = []
    for (var i = 0; i < items.length; i++) {
      var item = items[i]
      if (cat !== "all" && item.type_name !== cat && !(cat === "ssh_key" && item.category === "ssh_key")) continue

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

    var targetIndex = 0
    if (currentId && out.length > 0) {
      for (var k = 0; k < out.length; k++) {
        if (out[k].id === currentId) {
          targetIndex = k
          break
        }
      }
    }
    root.selectedIndex = targetIndex
    root.handleSelectedItemChanged()
  }

  onSearchQueryChanged: filterVaultItems(true)
  onActiveCategoryChanged: filterVaultItems(true)
  onSelectedIndexChanged: root.handleSelectedItemChanged()

  function handleSelectedItemChanged() {
    root.showPasswordRevealed = false
    root.showPrivateKeyRevealed = false
    root.activeAttachmentPreview = null
    root.loadingAttachmentId = ""
    root.updateTotpForSelected()
    root.updateAvailableActions()
  }

  function updateAvailableActions() {
    root.currentAvailableActions = root.getAvailableActions(root.selectedItem)
  }

  onShowActionPaletteChanged: {
    if (root.showActionPalette) {
      root.updateAvailableActions()
    } else {
      Qt.callLater(function() {
        if (root.effectiveView === "search" && searchHeader && searchHeader.searchField) {
          searchHeader.searchField.forceActiveFocus()
        }
      })
    }
  }

  onSelectedItemChanged: root.handleSelectedItemChanged()

  function updateTotpForSelected() {
    var item = root.selectedItem
    if (item && item.login && item.login.totp) {
      totpGenProc.running = false
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
    root.logInfo("omarchy:clipboard", "Copying " + (label || "item") + " to clipboard (sensitive: " + isSensitive + ")")
    var cmd = [root.helperPath, "clipboard", "copy"]
    if (isSensitive) {
      cmd.push("--sensitive")
    }
    clipCopyProc.secret = JSON.stringify({ text: String(text) })
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
        if (item.notes) {
          copyToClipboard(item.notes, false, "secure note")
        } else if (item.fields && item.fields.length > 0 && item.fields[0].value) {
          copyToClipboard(String(item.fields[0].value), item.fields[0].type === 1, item.fields[0].name || "custom field")
        }
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

  function copyItemUsername(item) {
    if (!item) return
    var uName = ""
    if (item.type_name === "login" && item.login && item.login.username) {
      uName = item.login.username
    } else if (item.type_name === "identity" && item.identity && item.identity.username) {
      uName = item.identity.username
    }
    if (uName) {
      root.copyToClipboard(uName, false, "username")
    }
  }

  function copyItemTotp(item) {
    if (!item) return
    if (root.currentTotp && root.currentTotp.code) {
      root.copyToClipboard(root.currentTotp.code, true, "TOTP code")
    }
  }

  function openFirstWebsite(item) {
    if (!item) return
    var targetUri = ""
    if (item.type_name === "login" && item.login && item.login.uris && item.login.uris.length > 0) {
      for (var u = 0; u < item.login.uris.length; u++) {
        var uriObj = item.login.uris[u]
        var uriStr = (typeof uriObj === "string") ? uriObj : (uriObj && uriObj.uri ? uriObj.uri : "")
        if (uriStr) {
          targetUri = uriStr
          break
        }
      }
    }
    if (targetUri) {
      if (!targetUri.match(/^https?:\/\//i)) {
        targetUri = "https://" + targetUri
      }
      Qt.openUrlExternally(targetUri)
    }
  }

  function getAvailableActions(item) {
    if (!item) return []
    var actions = []

    if (item.type_name === "login" && item.login) {
      if (item.login.password) {
        actions.push({ label: "Copy Password", icon: "\uf023", shortcut: "↵", action: function() { root.copyToClipboard(item.login.password, true, "password") } })
      }
      if (item.login.username) {
        actions.push({ label: "Copy Username (" + item.login.username + ")", icon: "\uf007", shortcut: "Ctrl+U", action: function() { root.copyToClipboard(item.login.username, false, "username") } })
      }
      if ((item.login.totp) || (root.currentTotp && root.currentTotp.code)) {
        var totpLabel = "Copy TOTP Code" + ((root.currentTotp && root.currentTotp.code) ? (" (" + root.currentTotp.code + ")") : "")
        actions.push({
          label: totpLabel,
          icon: "\uf017",
          shortcut: "Ctrl+T",
          action: function() {
            if (root.currentTotp && root.currentTotp.code) {
              root.copyToClipboard(root.currentTotp.code, true, "TOTP code")
            }
          }
        })
      }
      if (item.login.uris && item.login.uris.length > 0) {
        var hasAssignedUrlShortcut = false
        for (var u = 0; u < item.login.uris.length; u++) {
          var uriObj = item.login.uris[u]
          var uriStr = (typeof uriObj === "string") ? uriObj : (uriObj && uriObj.uri ? uriObj.uri : "")
          if (uriStr) {
            (function(targetUri, isFirstUri) {
              actions.push({
                label: "Open URL (" + targetUri + ")",
                icon: "\uf08e",
                shortcut: isFirstUri ? "Ctrl+O" : "",
                action: function() {
                  var openUrl = targetUri
                  if (!openUrl.match(/^https?:\/\//i)) openUrl = "https://" + openUrl
                  Qt.openUrlExternally(openUrl)
                }
              })
            })(uriStr, !hasAssignedUrlShortcut)
            hasAssignedUrlShortcut = true
          }
        }
      }
    } else if (item.type_name === "card" && item.card) {
      if (item.card.number) actions.push({ label: "Copy Card Number", icon: "\uf09d", shortcut: "↵", action: function() { root.copyToClipboard(item.card.number, true, "card number") } })
      if (item.card.code) actions.push({ label: "Copy Security Code (CVV)", icon: "\uf292", shortcut: "", action: function() { root.copyToClipboard(item.card.code, true, "CVV") } })
      if (item.card.cardholderName) actions.push({ label: "Copy Cardholder Name", icon: "\uf007", shortcut: "", action: function() { root.copyToClipboard(item.card.cardholderName, false, "cardholder") } })
      if (item.card.expMonth && item.card.expYear) {
        var expStr = item.card.expMonth + "/" + item.card.expYear
        actions.push({ label: "Copy Expiration (" + expStr + ")", icon: "\uf073", shortcut: "", action: function() { root.copyToClipboard(expStr, false, "expiration") } })
      }
    } else if (item.type_name === "ssh_key" && item.ssh_key) {
      if (item.ssh_key.private_key) actions.push({ label: "Copy Private Key", icon: "\uf084", shortcut: "↵", action: function() { root.copyToClipboard(item.ssh_key.private_key, true, "private key") } })
      if (item.ssh_key.public_key) actions.push({ label: "Copy Public Key", icon: "\uf084", shortcut: "", action: function() { root.copyToClipboard(item.ssh_key.public_key, false, "public key") } })
      if (item.ssh_key.fingerprint) actions.push({ label: "Copy Fingerprint", icon: "\uf084", shortcut: "", action: function() { root.copyToClipboard(item.ssh_key.fingerprint, false, "fingerprint") } })
      if (item.ssh_key.passphrase) actions.push({ label: "Copy Passphrase", icon: "\uf023", shortcut: "", action: function() { root.copyToClipboard(item.ssh_key.passphrase, true, "passphrase") } })
    } else if (item.type_name === "identity" && item.identity) {
      var idFullName = ((item.identity.firstName || "") + " " + (item.identity.lastName || "")).trim()
      if (idFullName) actions.push({ label: "Copy Full Name (" + idFullName + ")", icon: "\uf007", shortcut: "", action: function() { root.copyToClipboard(idFullName, false, "full name") } })
      if (item.identity.username) actions.push({ label: "Copy Username (" + item.identity.username + ")", icon: "\uf02b", shortcut: "Ctrl+U", action: function() { root.copyToClipboard(item.identity.username, false, "username") } })
      if (item.identity.email) actions.push({ label: "Copy Email (" + item.identity.email + ")", icon: "\uf0e0", shortcut: "↵", action: function() { root.copyToClipboard(item.identity.email, false, "email") } })
      if (item.identity.phone) actions.push({ label: "Copy Phone (" + item.identity.phone + ")", icon: "\uf095", shortcut: "", action: function() { root.copyToClipboard(item.identity.phone, false, "phone") } })
      if (item.identity.company) actions.push({ label: "Copy Company (" + item.identity.company + ")", icon: "\uf1ad", shortcut: "", action: function() { root.copyToClipboard(item.identity.company, false, "company") } })
      var addrStr = [item.identity.address1, item.identity.city, item.identity.state, item.identity.postalCode, item.identity.country].filter(Boolean).join(", ")
      if (addrStr) actions.push({ label: "Copy Address (" + addrStr + ")", icon: "\uf041", shortcut: "", action: function() { root.copyToClipboard(addrStr, false, "address") } })
      if (item.identity.ssn) actions.push({ label: "Copy SSN", icon: "\uf292", shortcut: "", action: function() { root.copyToClipboard(item.identity.ssn, true, "SSN") } })
      if (item.identity.passportNumber) actions.push({ label: "Copy Passport Number", icon: "\uf2c2", shortcut: "", action: function() { root.copyToClipboard(item.identity.passportNumber, true, "passport") } })
      if (item.identity.licenseNumber) actions.push({ label: "Copy Driver License", icon: "\uf2c2", shortcut: "", action: function() { root.copyToClipboard(item.identity.licenseNumber, true, "driver license") } })
    }

    if (item.notes) {
      actions.push({ label: "Copy Notes", icon: "\uf0f6", shortcut: "", action: function() { root.copyToClipboard(item.notes, false, "notes") } })
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
                icon: "\uf292",
                shortcut: "",
                action: function() { root.copyToClipboard(String(pinVal), true, "PIN") }
              })
            })(field.value)
          } else {
            (function(fld) {
              actions.push({
                label: "Copy " + fld.name,
                icon: "\uf02b",
                shortcut: "",
                action: function() { root.copyToClipboard(String(fld.value), true, fld.name) }
              })
            })(field)
          }
        }
      }
    }

    if (item.attachments && item.attachments.length > 0) {
      for (var a = 0; a < item.attachments.length; a++) {
        var att = item.attachments[a]
        if (att && att.fileName) {
          (function(currAtt) {
            if (root.isAttachmentPreviewable(currAtt.fileName)) {
              actions.push({
                label: "View Attachment: " + currAtt.fileName,
                icon: "\uf06e",
                shortcut: "",
                action: function() { root.viewAttachment(item, currAtt) }
              })
            }
            actions.push({
              label: "Download Attachment: " + currAtt.fileName,
              icon: "\uf019",
              shortcut: "",
              action: function() { root.downloadAttachment(item, currAtt) }
            })
          })(att)
        }
      }
    }

    if (item.folder_name) {
      actions.push({
        label: "Copy Folder (" + item.folder_name + ")",
        icon: "\uf07b",
        shortcut: "",
        action: function() { root.copyToClipboard(item.folder_name, false, "folder name") }
      })
    }

    if (item.organization_name) {
      actions.push({
        label: "Copy Organization (" + item.organization_name + ")",
        icon: "\uf1ad",
        shortcut: "",
        action: function() { root.copyToClipboard(item.organization_name, false, "organization name") }
      })
    }

    actions.push({ label: "Copy Item Name (" + item.name + ")", icon: "\uf0c5", shortcut: "", action: function() { root.copyToClipboard(item.name, false, "item name") } })
    actions.push({ label: "Sync Vault Now", icon: "\uf021", shortcut: "Ctrl+R", action: function() { root.syncVault(false, true) } })
    actions.push({ label: "Lock Vault", icon: "\uf023", shortcut: "Ctrl+L", action: function() { root.doLock() } })

    return actions
  }

  function viewAttachment(item, att) {
    if (!item || !att) return
    root.logInfo("omarchy:attachment", "Requesting preview for " + (att.fileName || "attachment"))
    root.loadingAttachmentId = (att.id || att.fileName || "loading")
    attachmentProc.activeAttachmentId = att.id || ""
    attachmentProc.command = [
      root.helperPath,
      "attachment",
      "download",
      "--item-id", item.id,
      "--attachment-id", att.id,
      "--filename", att.fileName || "attachment",
      "--preview"
    ]
    attachmentProc.running = true
  }

  function downloadAttachment(item, att) {
    if (!item || !att) return
    root.logInfo("omarchy:attachment", "Requesting download for " + (att.fileName || "attachment"))
    root.statusMessage = "Downloading attachment " + (att.fileName || "") + "..."
    var cmd = [
      root.helperPath,
      "attachment",
      "download",
      "--item-id", item.id,
      "--attachment-id", att.id,
      "--filename", att.fileName || "attachment"
    ]
    if (root.config && root.config.download_dir) {
      cmd.push("--output-dir", root.config.download_dir)
    }
    attachmentProc.command = cmd
    attachmentProc.running = true
  }

  function saveSettings(settings) {
    root.isBusy = true
    root.logInfo("omarchy:settings", "Saving configuration (log_level: " + (settings.log_level || "error") + ")...")
    root.statusMessage = "Saving configuration..."
    var cmd = [root.helperPath, "config", "set"]
    if (settings.server_url !== undefined) cmd.push("--server-url", settings.server_url)
    if (settings.download_dir !== undefined) cmd.push("--download-dir", settings.download_dir)
    if (settings.auto_lock_minutes !== undefined) cmd.push("--auto-lock", String(settings.auto_lock_minutes))
    if (settings.clipboard_clear_seconds !== undefined) cmd.push("--clipboard-clear", String(settings.clipboard_clear_seconds))
    if (settings.max_output_mb !== undefined) cmd.push("--max-output-mb", String(settings.max_output_mb))
    if (settings.log_level !== undefined) cmd.push("--log-level", settings.log_level)

    configSetProc.command = cmd
    configSetProc.running = true
  }

  function copyDiagnostics() {
    var ts = new Date().toISOString()
    var cliVer = (root.cliHealth && root.cliHealth.version) ? root.cliHealth.version : "Unknown"
    var rawUrl = (root.config && root.config.server_url) ? root.config.server_url : ""
    var sUrl = root.sanitizeServerUrl(rawUrl)
    var lLevel = (root.config && root.config.log_level) ? root.config.log_level : "error"
    var vStatus = (root.authState ? root.authState.status : "unknown")

    var report = "### Omarchy Bitwarden Diagnostics Report\n\n"
    report += "- **Generated At**: " + ts + "\n"
    report += "- **omawarden Version**: " + cliVer + "\n"
    report += "- **Server URL**: " + sUrl + "\n"
    report += "- **Configured Log Level**: " + lLevel + "\n"
    report += "- **Vault Status**: " + vStatus + "\n"
    report += "- **Engine Ready**: " + (root.cliHealth && root.cliHealth.installed ? "Yes" : "No") + "\n"
    report += "- **Keyring Available**: " + (root.cliHealth && root.cliHealth.keyring_available ? "Yes" : "No") + "\n"
    report += "- **Clipboard Available**: " + (root.cliHealth && root.cliHealth.clipboard_available ? "Yes" : "No") + "\n\n"
    report += "#### Recent Logs (" + (root.logBuffer ? root.logBuffer.length : 0) + " entries):\n\n```text\n"

    var logs = root.logBuffer || []
    var recent = logs.slice(-50)
    for (var i = 0; i < recent.length; i++) {
      var item = recent[i]
      report += "[" + item.timestamp + "] [" + item.level + "] [" + item.source + "] " + item.message + "\n"
    }
    if (recent.length === 0) {
      report += "(No logs recorded yet)\n"
    }
    report += "```\n"

    root.copyToClipboard(report, false, "Diagnostics report")
    root.statusMessage = "Diagnostics report copied to clipboard."
  }

  function doUnlock(password) {
    if (!password) return
    root.logInfo("omarchy:auth", "Submitting unlock request...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Unlocking vault..."
    authUnlockProc.secret = password
    authUnlockProc.command = [root.helperPath, "auth", "unlock"]
    authUnlockProc.running = true
  }

  function doLock() {
    root.logInfo("omarchy:auth", "Locking vault...")
    if (authViewComponent) authViewComponent.clearInputs()
    root.authState = ({
      status: "locked",
      server_url: (root.authState && root.authState.server_url) || "",
      user_email: (root.authState && root.authState.user_email) || "",
      has_session: false
    })
    root.rawVaultItems = []
    root.filteredItems = []
    root.lastVaultItemsRawText = ""
    root.lastSyncTime = 0
    root.searchQuery = ""
    root.activeCategory = "all"
    root.selectedIndex = 0
    root.isBusy = true
    root.statusMessage = "Locking vault..."
    authLockProc.command = [root.helperPath, "auth", "lock"]
    authLockProc.running = true
  }

  function doLoginPassword(email, password, code) {
    if (!email || !password) return
    root.logInfo("omarchy:auth", "Submitting password login for " + email + "...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Logging in to Bitwarden..."
    var cmd = [root.helperPath, "auth", "login-password", "--email", email]
    if (code) {
      authLoginProc.secret = JSON.stringify({ password: password, code: code })
    } else {
      authLoginProc.secret = password
    }
    authLoginProc.command = cmd
    authLoginProc.running = true
  }

  function doLoginApiKey(clientId, clientSecret) {
    if (!clientId || !clientSecret) return
    root.logInfo("omarchy:auth", "Submitting API Key login for client " + clientId + "...")
    root.isBusy = true
    root.errorMessage = ""
    root.statusMessage = "Authenticating with API Key..."
    authLoginProc.secret = clientSecret
    authLoginProc.command = [root.helperPath, "auth", "login-apikey", "--client-id", clientId]
    authLoginProc.running = true
  }

  function doLogout() {
    root.logInfo("omarchy:auth", "Logging out session...")
    if (authViewComponent) authViewComponent.clearInputs()
    root.authState = ({
      status: "unauthenticated",
      server_url: "",
      user_email: "",
      has_session: false
    })
    root.rawVaultItems = []
    root.filteredItems = []
    root.lastVaultItemsRawText = ""
    root.lastSyncTime = 0
    root.searchQuery = ""
    root.activeCategory = "all"
    root.selectedIndex = 0
    root.isBusy = true
    root.statusMessage = "Logging out..."
    authLogoutProc.command = [root.helperPath, "auth", "logout"]
    authLogoutProc.running = true
  }

  Timer {
    id: statusMessageTimer
    interval: 3000
    repeat: false
    onTriggered: root.statusMessage = ""
  }

  onStatusMessageChanged: {
    if (root.statusMessage !== "") {
      statusMessageTimer.restart()
    }
  }

  Timer {
    interval: 1000
    running: Boolean(root.opened && root.effectiveView === "search" && root.selectedItem && root.selectedItem.login && root.selectedItem.login.totp)
    repeat: true
    onTriggered: {
      if (root.currentTotp.ttl > 1) {
        root.currentTotp = ({ code: root.currentTotp.code, ttl: root.currentTotp.ttl - 1, period: root.currentTotp.period })
      } else {
        root.updateTotpForSelected()
      }
    }
  }

  // ======================================================
  // FLOATING OVERLAY WINDOW
  // ======================================================
  FloatingWindow {
    id: panel
    title: "Bitwarden"
    visible: root.opened
    color: Color.menu.background
    implicitWidth: 880
    implicitHeight: 560
    minimumSize: Qt.size(720, 480)

    onVisibleChanged: {
      if (visible) {
        Qt.callLater(function() {
          if (root.effectiveView === "search" && searchHeader && searchHeader.searchField) {
            searchHeader.searchField.forceActiveFocus()
          } else if (authViewComponent && authViewComponent.unlockInput) {
            authViewComponent.unlockInput.forceActiveFocus()
          }
        })
      }
    }

    Shortcut {
      sequence: "Ctrl+K"
      enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null
      onActivated: {
        root.actionPaletteIndex = 0
        root.showActionPalette = true
      }
    }

    Shortcut {
      sequence: "Ctrl+U"
      enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.showActionPalette
      onActivated: root.copyItemUsername(root.selectedItem)
    }

    Shortcut {
      sequence: "Ctrl+T"
      enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.showActionPalette
      onActivated: root.copyItemTotp(root.selectedItem)
    }

    Shortcut {
      sequence: "Ctrl+O"
      enabled: root.opened && root.effectiveView === "search" && root.selectedItem !== null && !root.showActionPalette
      onActivated: root.openFirstWebsite(root.selectedItem)
    }

    Shortcut {
      sequence: "Ctrl+L"
      enabled: root.opened && root.authState.status === "unlocked"
      onActivated: root.doLock()
    }

    Shortcut {
      sequence: "Ctrl+R"
      enabled: root.opened && root.authState.status === "unlocked" && !root.isBusy
      onActivated: root.syncVault(false, true)
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
        } else if (root.activeAttachmentPreview !== null) {
          root.activeAttachmentPreview = null
        } else if (root.effectiveView === "settings") {
          root.currentView = "auto"
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
          if (event.key === Qt.Key_Escape) {
            root.showActionPalette = false
            event.accepted = true
          }
          return
        }

        if (event.key === Qt.Key_Escape) {
          if (root.activeAttachmentPreview !== null) {
            root.activeAttachmentPreview = null
          } else if (root.effectiveView === "settings") {
            root.currentView = "auto"
          } else {
            root.dismiss()
          }
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
        } else if (event.key === Qt.Key_Down && root.effectiveView === "search") {
          if (root.filteredItems.length > 0) {
            root.selectedIndex = (root.selectedIndex + 1) % root.filteredItems.length
          }
          event.accepted = true
        } else if (event.key === Qt.Key_Up && root.effectiveView === "search") {
          if (root.filteredItems.length > 0) {
            root.selectedIndex = (root.selectedIndex - 1 + root.filteredItems.length) % root.filteredItems.length
          }
          event.accepted = true
        }
      }

      ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 14
        anchors.rightMargin: 14
        anchors.topMargin: 14
        anchors.bottomMargin: 4
        spacing: 8

        // 1. Search & Category Header (Search View)
        SearchHeader {
          id: searchHeader
          visible: root.effectiveView === "search"
          Layout.preferredHeight: visible ? implicitHeight : 0
          searchQuery: root.searchQuery
          categoryList: root.categoryList
          activeCategory: root.activeCategory
          rawVaultItems: root.rawVaultItems
          fontFamily: root.fontFamily
          foreground: root.foreground
          accent: root.accent
          borderColor: root.borderColor
          onSearchQueryChanged: root.searchQuery = searchQuery
          onCategorySelected: function(cat) { root.activeCategory = cat }
          onClearSearchRequested: {
            root.searchQuery = ""
            root.filterVaultItems()
          }
        }

        // 2. Main Content Center View
        Item {
          Layout.fillWidth: true
          Layout.fillHeight: true

          // Mode A: Search / Vault View (2-Column Split)
          RowLayout {
            anchors.fill: parent
            spacing: 12
            visible: root.effectiveView === "search"

            // Left Column: Items List
            VaultItemList {
              id: vaultItemList
              Layout.fillHeight: true
              Layout.preferredWidth: 320
              Layout.minimumWidth: 260
              items: root.filteredItems
              selectedIndex: root.selectedIndex
              searchQuery: root.searchQuery
              fontFamily: root.fontFamily
              foreground: root.foreground
              accent: root.accent
              selectedBackground: root.selectedBackground
              borderColor: root.borderColor
              onItemSelected: function(idx) { root.selectedIndex = idx }
              onItemTriggered: function(idx) {
                root.selectedIndex = idx
                root.executePrimaryAction(root.selectedItem)
              }
            }

            // Vertical Divider
            Rectangle {
              Layout.fillHeight: true
              width: 1
              color: root.borderColor
            }

            // Right Column: Detail Inspector OR Empty Cheat Sheet
            Item {
              Layout.fillWidth: true
              Layout.fillHeight: true

              // Item Inspector View
              ItemInspector {
                anchors.fill: parent
                visible: root.selectedItem !== null
                item: root.selectedItem
                currentTotp: root.currentTotp
                showPasswordRevealed: root.showPasswordRevealed
                showPrivateKeyRevealed: root.showPrivateKeyRevealed
                activeAttachmentPreview: root.activeAttachmentPreview
                loadingAttachmentId: root.loadingAttachmentId
                fontFamily: root.fontFamily
                foreground: root.foreground
                accent: root.accent
                borderColor: root.borderColor
                onCopyRequested: function(text, isSensitive, label) { root.copyToClipboard(text, isSensitive, label) }
                onViewAttachmentRequested: function(item, att) { root.viewAttachment(item, att) }
                onDownloadAttachmentRequested: function(item, att) { root.downloadAttachment(item, att) }
                onClosePreviewRequested: { root.activeAttachmentPreview = null }
                onTogglePasswordRevealed: { root.showPasswordRevealed = !root.showPasswordRevealed }
                onTogglePrivateKeyRevealed: { root.showPrivateKeyRevealed = !root.showPrivateKeyRevealed }
              }

              // Empty Selection State View
              EmptyInspector {
                anchors.fill: parent
                visible: root.selectedItem === null
                rawVaultItems: root.rawVaultItems
                authState: root.authState
                fontFamily: root.fontFamily
                foreground: root.foreground
                accent: root.accent
                borderColor: root.borderColor
              }
            }
          }

          // Mode B: Auth View (Unlock or Login)
          AuthView {
            id: authViewComponent
            anchors.fill: parent
            visible: root.effectiveView === "unlock" || root.effectiveView === "login"
            authState: root.authState
            config: root.config
            cliHealth: root.cliHealth
            isDownloadingCli: root.isDownloadingCli
            isBusy: root.isBusy
            loginMethod: root.loginMethod
            rememberEmailChecked: root.rememberEmailChecked
            show2FAField: root.show2FAField
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            borderColor: root.borderColor
            onUnlockRequested: function(pwd) { root.doUnlock(pwd) }
            onLoginPasswordRequested: function(email, pwd, code) { root.doLoginPassword(email, pwd, code) }
            onLoginApiKeyRequested: function(cId, cSec) { root.doLoginApiKey(cId, cSec) }
            onLogoutRequested: { root.doLogout() }
            onDownloadCliRequested: { root.downloadCli() }
            onSettingsRequested: { root.currentView = "settings" }
          }

          // Mode C: Settings View
          SettingsModal {
            anchors.fill: parent
            visible: root.effectiveView === "settings"
            config: root.config
            cliHealth: root.cliHealth
            logBuffer: root.logBuffer
            isDownloadingCli: root.isDownloadingCli
            isBusy: root.isBusy
            updateAvailable: root.updateAvailable
            latestVersion: root.latestVersion
            isCheckingUpdate: root.isCheckingUpdate
            updateCheckStatus: root.updateCheckStatus
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            borderColor: root.borderColor
            onSaveRequested: function(newSettings) { root.saveSettings(newSettings) }
            onCloseRequested: { root.currentView = "auto" }
            onRefreshHealthRequested: {
              root.refreshHealth()
              root.refreshConfig()
            }
            onCheckUpdateRequested: { root.checkUpdates(true) }
            onDownloadCliRequested: { root.downloadCli() }
            onCopyDiagnosticsRequested: { root.copyDiagnostics() }
            onClearLogsRequested: { root.logBuffer = [] }
          }
        }

        // 3. Footer Bar (Bottom Left: Actions, Sync, Lock, Settings; Bottom Right: Versions & Actions)
        FooterBar {
          isUnlocked: root.effectiveView === "search"
          isBusy: root.isBusy
          overlayVersion: (root.manifest && root.manifest.version) ? (root.manifest.version) : ""
          backendVersion: (root.cliHealth && root.cliHealth.version) || ""
          isEngineInstalled: Boolean(root.cliHealth && root.cliHealth.installed)
          isDownloadingCli: root.isDownloadingCli
          updateAvailable: root.updateAvailable
          latestVersion: root.latestVersion
          background: root.background
          fontFamily: root.fontFamily
          foreground: root.foreground
          accent: root.accent
          borderColor: root.borderColor
          onActionPaletteTriggered: {
            root.actionPaletteIndex = 0
            root.showActionPalette = true
          }
          onSyncTriggered: { root.syncVault(false, true) }
          onLockTriggered: { root.doLock() }
          onSettingsTriggered: {
            root.currentView = (root.effectiveView === "settings") ? "auto" : "settings"
          }
          onDownloadCliTriggered: { root.downloadCli() }
        }
      }

      // 4. Floating Top-Right Toast Alert (Prevents dynamic window shifting!)
      ToastAlert {
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.topMargin: 14
        anchors.rightMargin: 14
        statusMessage: root.statusMessage
        errorMessage: root.errorMessage
        isBusy: root.isBusy
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        onClearRequested: {
          root.statusMessage = ""
          root.errorMessage = ""
        }
      }

      // 5. Action Palette Modal Overlay (Ctrl+K)
      ActionPaletteModal {
        active: root.showActionPalette
        actions: root.currentAvailableActions
        fontFamily: root.fontFamily
        foreground: root.foreground
        accent: root.accent
        borderColor: root.borderColor
        onActionSelected: function(actionItem) {
          root.showActionPalette = false
          if (actionItem && typeof actionItem.action === "function") {
            actionItem.action()
          }
        }
        onCloseRequested: { root.showActionPalette = false }
      }
    }
  }

  // ======================================================
  // QUICKSHELL IO BACKGROUND PROCESSES
  // ======================================================
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
        } catch (e) {
          root.logError("omarchy:ui", "Failed to parse config: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:config")
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
          root.logError("omarchy:ui", "Failed to parse updated config: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:config")
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
          var cleanText = (text || "").trim()
          if (cleanText.length === 0) {
            root.cliHealth = ({
              installed: false,
              ok: false,
              version: "",
              server_reachable: false,
              keyring_available: false,
              clipboard_available: false,
              error: "CLI executable not found or output empty."
            })
            return
          }
          var data = JSON.parse(cleanText)
          if (data && typeof data === "object") {
            root.cliHealth = data
          }
        } catch (e) {
          root.cliHealth = ({
            installed: false,
            ok: false,
            version: "",
            server_reachable: false,
            keyring_available: false,
            clipboard_available: false,
            error: "Failed to parse CLI health output."
          })
          root.logError("omarchy:ui", "Failed to parse health status: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:health")
    }
    onExited: function(code) {
      if (code !== 0 && (!root.cliHealth || !root.cliHealth.installed)) {
        root.cliHealth = ({
          installed: false,
          ok: false,
          version: "",
          server_reachable: false,
          keyring_available: false,
          clipboard_available: false,
          error: "CLI executable not found or failed to execute."
        })
      }
    }
  }

  Process {
    id: downloadCliProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isDownloadingCli = false
        root.isBusy = false
        try {
          var cleanText = (text || "").trim()
          var data = JSON.parse(cleanText)
          if (data && data.ok) {
            root.statusMessage = "omawarden engine updated successfully."
            root.errorMessage = ""
            root.refreshHealth()
            root.refreshConfig()
            root.refreshAuthStatus()
          } else {
            root.errorMessage = (data && data.error) ? data.error : "Failed to download omawarden."
            root.logError("omarchy:cli-download", root.errorMessage)
          }
        } catch (e) {
          root.errorMessage = "Failed to process download response."
          root.logError("omarchy:cli-download", root.errorMessage + ": " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omarchy:cli-download")
    }
    onExited: function(code) {
      root.isDownloadingCli = false
      root.isBusy = false
      if (code !== 0 && !root.errorMessage) {
        root.errorMessage = "Download script failed."
      }
    }
  }

  Process {
    id: updateCheckProc
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.isCheckingUpdate = false
        try {
          var cleanText = (text || "").trim()
          var data = JSON.parse(cleanText)
          if (data && data.ok && data.tag) {
            var rawTag = data.tag
            var cleanTag = String(rawTag).replace(/^omawarden-|^v/i, "").trim()
            root.latestVersion = cleanTag
            var currentVer = (root.cliHealth && root.cliHealth.version) ? root.cliHealth.version : ""
            if (currentVer && root.compareSemVer(cleanTag, currentVer) > 0) {
              root.updateCheckStatus = "Update available: v" + cleanTag
            } else {
              root.updateCheckStatus = "Up to date (v" + (currentVer || cleanTag) + ")"
            }
          } else {
            root.updateCheckStatus = (data && data.error) ? data.error : "Update check failed"
          }
        } catch (e) {
          root.updateCheckStatus = "Update check failed"
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omarchy:update")
    }
    onExited: function(code) {
      root.isCheckingUpdate = false
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
          if (data && data.status) {
            var wasNotUnlocked = (root.authState.status !== "unlocked")
            root.authState = data
            if (data.status === "unlocked" && (wasNotUnlocked || !root.rawVaultItems || root.rawVaultItems.length === 0)) {
              root.loadVaultItems()
              root.syncVault(true, false)
            }
            Qt.callLater(function() {
              if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.showActionPalette) {
                searchHeader.searchField.forceActiveFocus()
              }
            })
          }
        } catch (e) {
          root.authState = ({
            status: "unauthenticated",
            server_url: "",
            user_email: "",
            has_session: false
          })
          root.logError("omarchy:auth", "Failed to parse auth status: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
    }
    onExited: function(code) {
      if (code !== 0) {
        root.authState = ({
          status: "unauthenticated",
          server_url: "",
          user_email: "",
          has_session: false
        })
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
            if (authViewComponent) authViewComponent.clearInputs()
            root.authState = ({
              status: "unlocked",
              server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
              user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
              has_session: true
            })
            root.refreshAuthStatus()
            root.loadVaultItems()
            root.syncVault(true, true)
          } else {
            root.errorMessage = data.error || "Unlock failed."
            root.logError("omarchy:auth", root.errorMessage)
          }
        } catch (e) {
          root.errorMessage = "Failed to parse unlock response."
          root.logError("omarchy:auth", root.errorMessage + ": " + e)
        }
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
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
            if (authViewComponent) authViewComponent.clearInputs()

            root.show2FAField = false
            root.authState = ({
              status: "unlocked",
              server_url: (root.authState && root.authState.server_url) || (root.config && root.config.server_url) || "",
              user_email: (root.authState && root.authState.user_email) || (root.config && root.config.email) || "",
              has_session: true
            })
            root.refreshAuthStatus()
            root.loadVaultItems()
            root.syncVault(true, true)
          } else {
            root.errorMessage = data.error || "Login failed."
            root.logError("omarchy:auth", root.errorMessage)
            var errLower = (data.error || "").toLowerCase()
            if (errLower.indexOf("two-step") !== -1 || errLower.indexOf("two-factor") !== -1 || errLower.indexOf("code") !== -1) {
              root.show2FAField = true
            }
          }
        } catch (e) {
          root.errorMessage = "Failed to parse login response."
          root.logError("omarchy:auth", root.errorMessage + ": " + e)
        }
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
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
        root.lastVaultItemsRawText = ""
        root.lastSyncTime = 0
        root.refreshAuthStatus()
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
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
        root.lastVaultItemsRawText = ""
        root.lastSyncTime = 0
        root.refreshAuthStatus()
        root.isBusy = false
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:auth")
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
        root.lastSyncTime = Date.now()
        root.statusMessage = "Vault synchronized."
        root.loadVaultItems()
        Qt.callLater(function() {
          if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.showActionPalette) {
            searchHeader.searchField.forceActiveFocus()
          }
        })
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:vault")
    }
    onExited: function(code) {
      root.isBusy = false
      if (code !== 0) {
        root.errorMessage = "Vault sync failed."
        root.logError("omarchy:vault", "Vault sync process exited with code " + code)
      }
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
          var cleanText = (text || "").trim()
          if (cleanText === root.lastVaultItemsRawText && root.rawVaultItems && root.rawVaultItems.length > 0) {
            Qt.callLater(function() {
              if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.showActionPalette) {
                searchHeader.searchField.forceActiveFocus()
              }
            })
            return
          }
          root.lastVaultItemsRawText = cleanText
          var items = JSON.parse(cleanText)
          root.rawVaultItems = items || []
          root.filterVaultItems(false)
          Qt.callLater(function() {
            if (root.opened && root.effectiveView === "search" && searchHeader && searchHeader.searchField && !root.showActionPalette) {
              searchHeader.searchField.forceActiveFocus()
            }
          })
        } catch (e) {
          root.logError("omarchy:vault", "Failed to parse vault items: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:vault")
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
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:clipboard")
    }
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
        var cleanText = (text || "").trim()
        if (!cleanText) return
        try {
          var res = JSON.parse(cleanText)
          if (res && res.code) {
            root.currentTotp = res
          } else {
            root.currentTotp = ({ code: "Invalid Secret", ttl: 0, period: 30 })
          }
        } catch (e) {
          root.currentTotp = ({ code: "Invalid Secret", ttl: 0, period: 30 })
          root.logError("omarchy:totp", "Failed to parse TOTP response: " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:totp")
    }
  }

  Process {
    id: attachmentProc
    property string activeAttachmentId: ""
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.loadingAttachmentId = ""
        try {
          var data = JSON.parse(text)
          if (data.ok) {
            if (data.action === "preview") {
              data.attachment_id = attachmentProc.activeAttachmentId
              root.activeAttachmentPreview = data
            } else if (data.action === "view") {
              root.statusMessage = "Opened " + (data.filename || "attachment") + "."
            } else {
              root.statusMessage = "Saved " + (data.filename || "attachment") + " to " + (data.path || "Downloads")
            }
          } else {
            root.errorMessage = data.error || "Failed to process attachment."
            root.logError("omarchy:attachment", root.errorMessage)
          }
        } catch (e) {
          root.errorMessage = "Failed to parse attachment response."
          root.logError("omarchy:attachment", root.errorMessage + ": " + e)
        }
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handleProcessStderr(text, "omawarden:attachment")
    }
    onExited: function(code) {
      root.loadingAttachmentId = ""
      if (code !== 0 && !root.errorMessage) root.errorMessage = "Attachment command failed."
    }
  }
}
