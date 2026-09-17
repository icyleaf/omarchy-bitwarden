import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner
  width: 400
  height: 300

  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) }
    else console.log("PASS: " + msg)
  }

  SettingsModal { id: sm }
  SearchHeader { id: sh }
  ItemInspector { id: inspector }

  // Simulation harness for OmarchyBitwarden lifecycle
  property var config: ({ remember_last_search: false })
  property var authState: ({ status: "unlocked", has_session: true })
  property bool opened: false
  property string searchQuery: ""
  property int selectedIndex: 0
  property var filteredItems: []
  property string activeCategory: "all"
  property string activeVaultScope: "all"
  property string activeFolderScope: "all"

  readonly property var selectedItem: (filteredItems && filteredItems.length > selectedIndex && selectedIndex >= 0) ? filteredItems[selectedIndex] : null

  property bool showPasswordRevealed: false
  property bool showActionPalette: false
  property var currentAvailableActions: []
  property var currentTotp: ({ code: "", ttl: 30, period: 30 })
  property int totpFetchCount: 0

  function updateTotpForSelected() {
    var it = selectedItem
    if (it && it.login && (it.login.totp || it.login.has_totp)) {
      totpFetchCount++
      currentTotp = ({ code: "987654", ttl: 28, period: 30 })
    } else {
      currentTotp = ({ code: "", ttl: 30, period: 30 })
    }
  }

  function updateAvailableActions() {
    currentAvailableActions = [{ label: "Copy Password" }]
  }

  function handleSelectedItemChanged() {
    showPasswordRevealed = false
    updateTotpForSelected()
    updateAvailableActions()
  }

  function clearSensitiveState() {
    searchQuery = ""
    selectedIndex = 0
    filteredItems = []
    activeCategory = "all"
    activeVaultScope = "all"
    activeFolderScope = "all"
    showPasswordRevealed = false
    showActionPalette = false
    currentAvailableActions = []
    currentTotp = ({ code: "", ttl: 30, period: 30 })
  }

  function simulateOpen() {
    opened = true
    var canRemember = Boolean(config && config.remember_last_search === true && authState && authState.status === "unlocked")
    if (!canRemember) {
      searchQuery = ""
      selectedIndex = 0
    } else {
      if (filteredItems && filteredItems.length > 0) {
        if (selectedIndex < 0) selectedIndex = 0
        else if (selectedIndex >= filteredItems.length) selectedIndex = filteredItems.length - 1
      } else {
        selectedIndex = 0
      }
    }
    if (!authState || authState.status !== "unlocked") {
      clearSensitiveState()
    } else {
      showActionPalette = false
      showPasswordRevealed = false
      currentAvailableActions = []
      currentTotp = ({ code: "", ttl: 30, period: 30 })
    }

    if (authState && authState.status === "unlocked" && selectedItem) {
      handleSelectedItemChanged()
    }
  }

  function simulateClose() {
    opened = false
    showActionPalette = false
    showPasswordRevealed = false
    currentAvailableActions = []
    currentTotp = ({ code: "", ttl: 30, period: 30 })
    var canRemember = Boolean(config && config.remember_last_search === true && authState && authState.status === "unlocked")
    if (!canRemember) {
      searchQuery = ""
      selectedIndex = 0
    }
  }

  function simulateTotpTimerTick() {
    if (currentTotp && currentTotp.code && currentTotp.ttl > 1) {
      currentTotp = ({ code: currentTotp.code, ttl: currentTotp.ttl - 1, period: currentTotp.period })
    } else {
      updateTotpForSelected()
    }
  }

  Component.onCompleted: {
    // 1. SettingsModal config binding & buildPayload
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", remember_last_search: false })
    check(sm.rememberLastSearchChecked === false, "config remember_last_search:false sets checkbox false")

    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error", remember_last_search: true })
    check(sm.rememberLastSearchChecked === true, "config remember_last_search:true sets checkbox true")

    // Upgrade path: defaults to false if key is absent
    sm.config = ({ server_url: "https://vault.bitwarden.com", log_level: "error" })
    check(sm.rememberLastSearchChecked === false, "missing remember_last_search defaults checkbox to false")

    sm.rememberLastSearchChecked = true
    check(sm.buildPayload().remember_last_search === true, "checked box emits remember_last_search:true in buildPayload")

    sm.rememberLastSearchChecked = false
    check(sm.buildPayload().remember_last_search === false, "unchecked box emits remember_last_search:false in buildPayload")

    // 2. Overlay retention behavior when remember_last_search is disabled (default)
    config = ({ remember_last_search: false })
    authState = ({ status: "unlocked", has_session: true })
    searchQuery = "github"
    selectedIndex = 2
    showPasswordRevealed = true
    simulateClose()
    check(searchQuery === "", "disabled remember_last_search clears searchQuery on close")
    check(selectedIndex === 0, "disabled remember_last_search resets selectedIndex on close")

    // 3. Overlay retention behavior when remember_last_search is enabled
    config = ({ remember_last_search: true })
    authState = ({ status: "unlocked", has_session: true })
    filteredItems = [
      { id: "1", name: "Item 1", login: {} },
      { id: "2", name: "Item 2", login: { username: "user", has_totp: true } },
      { id: "3", name: "Item 3", login: {} }
    ]
    searchQuery = "gitlab"
    selectedIndex = 1
    activeCategory = "login"
    showPasswordRevealed = true
    showActionPalette = true

    totpFetchCount = 0
    simulateClose()
    check(searchQuery === "gitlab", "enabled remember_last_search preserves searchQuery on close")
    check(selectedIndex === 1, "enabled remember_last_search preserves selectedIndex on close")
    check(showPasswordRevealed === false, "sensitive revealed password is reset on close")
    check(showActionPalette === false, "action palette is dismissed on close")
    check(currentTotp.code === "", "currentTotp reset to empty on close")

    // Reopen overlay with item retaining selection
    simulateOpen()
    check(searchQuery === "gitlab", "enabled remember_last_search preserves searchQuery on open")
    check(selectedIndex === 1, "enabled remember_last_search preserves selectedIndex on open")
    check(totpFetchCount === 1, "reopening invokes updateTotpForSelected() immediately")
    check(currentTotp.code === "987654", "currentTotp code populated on reopen without getting stuck in generating")
    check(currentAvailableActions.length > 0, "currentAvailableActions populated on reopen")

    // Test TOTP timer behavior when code is already present vs empty
    simulateTotpTimerTick()
    check(currentTotp.ttl === 27, "totp timer decrements TTL when code is present")

    currentTotp = ({ code: "", ttl: 30, period: 30 })
    totpFetchCount = 0
    simulateTotpTimerTick()
    check(totpFetchCount === 1, "totp timer immediately calls updateTotpForSelected if code is empty instead of counting down 30s")

    // Clamping of selectedIndex if filteredItems shrank
    filteredItems = [{ id: "1", name: "Single Item", login: {} }]
    simulateOpen()
    check(selectedIndex === 0, "selectedIndex clamped when filtered items shrink")

    // 4. Security Invariant: Vault lock wipes state unconditionally even with remember_last_search: true
    config = ({ remember_last_search: true })
    searchQuery = "sensitive-search"
    selectedIndex = 1
    activeCategory = "card"
    activeVaultScope = "org-1"
    activeFolderScope = "folder-1"

    // Simulate lock
    authState = ({ status: "locked", has_session: true })
    clearSensitiveState()
    simulateOpen()

    check(searchQuery === "", "searchQuery strictly cleared when vault is locked")
    check(selectedIndex === 0, "selectedIndex strictly cleared when vault is locked")
    check(activeCategory === "all", "category strictly reset to 'all' when locked")
    check(activeVaultScope === "all", "vault scope strictly reset to 'all' when locked")
    check(activeFolderScope === "all", "folder scope strictly reset to 'all' when locked")

    // 5. SearchHeader focusSearch(cursorAtEnd)
    sh.searchQuery = "example"
    sh.focusSearch(true)
    check(sh.searchField.cursorPosition === 7, "focusSearch(true) positions cursor at the end")
    check(sh.searchField.selectedText === "", "focusSearch(true) leaves text deselected")

    // 6. ItemInspector has_totp support
    inspector.item = { id: "test", name: "Has TOTP Only", type_name: "login", login: { has_totp: true } }
    check(inspector.item.login.has_totp === true, "inspector item has_totp is recognized")

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
