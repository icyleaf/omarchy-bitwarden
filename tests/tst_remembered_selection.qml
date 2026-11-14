import QtQuick
import ".."

Item {
  id: test
  OmarchyBitwarden { id: overlay }

  readonly property var session: ({ status: "unlocked", has_session: true, server_url: "https://vault.example", user_id: "test", lock_generation: "8000000000000000001" })
  readonly property var a: ({ id: "alpha", name: "Same login", type_name: "login", login: { password: "a" } })
  readonly property var b: ({ id: "beta", name: "Same login", type_name: "login", login: { username: "user-b", password: "pass-b", has_totp: true } })
  readonly property var c: ({ id: "gamma", name: "Other login", type_name: "login", login: {} })
  property var statusProc
  property var listProc

  function check(condition, message) {
    if (!condition) throw new Error(message)
  }

  function processEnding(first, last) {
    for (var i = 0; i < overlay.data.length; ++i) {
      var p = overlay.data[i]
      if (p.command && p.command.some(arg => arg.indexOf(first) !== -1) && p.command[p.command.length - 1] === last) return p
    }
    throw new Error("Missing command " + first + " … " + last)
  }

  function copiedText() {
    var copy = processEnding("copy", "30")
    check(copy.running, "expected a copy process")
    copy.finish()
    return JSON.parse(copy.lastInput).text
  }

  function refreshList(items) {
    overlay.loadVaultItems()
    check(listProc.running, "missing list request")
    listProc.reply(items)
  }

  function select(id) {
    overlay.selectedIndex = overlay.filteredItems.findIndex(it => it.id === id)
    check(overlay.highlightedItem && overlay.highlightedItem.id === id, "fixture cannot select " + id)
  }

  function closeOnBeta() {
    select("beta")
    overlay.toggle()
    overlay.close() // shell.hide() can deliver close() again
  }

  function warmOpen(expectedId) {
    var cached = overlay.rawVaultItems
    overlay.toggle()
    check(overlay.rawVaultItems === cached && overlay.highlightedItem.id === expectedId,
          "reopen lost its cached rows or highlighted the wrong ID")
    check(statusProc.running && !listProc.running, "warm reopen should only need the existing status probe")
  }

  function testImmediateKeys() {
    overlay.searchQuery = "Same"
    closeOnBeta()
    check(overlay.rememberedItemId === "beta" && overlay.searchQuery === "", "short follow-up retained the wrong state")
    refreshList([c, a, b])
    warmOpen("beta")
    overlay.requestFieldCopy("primary")
    check(overlay.pendingFieldCopy.id === "beta" && !overlay.selectedItem, "early Enter lost its target")
    refreshList([b, c, a]) // an unrelated sync reorders the rows during verification
    check(overlay.highlightedItem.id === "beta" && overlay.searchQuery === "", "refresh changed the target or restored the query")
    statusProc.reply(session)
    check(!listProc.running && copiedText() === "pass-b", "Enter needed a list reload or copied the wrong password")

    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("totp")
    statusProc.reply(session)
    processEnding("totp", "beta").reply({ code: "123456", ttl: 28, period: 30 })
    check(copiedText() === "123456", "early Ctrl+Enter did not copy the fresh TOTP")
    overlay.requestFieldCopy("username")
    check(copiedText() === "user-b", "username shortcut used the wrong item")

    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("primary")
    select("alpha")
    statusProc.reply(session)
    check(!overlay.pendingFieldCopy && !processEnding("copy", "30").running, "navigation redirected a queued copy")

    closeOnBeta()
    refreshList([a, c])
    warmOpen("alpha")
    statusProc.reply(session)
    check(!overlay.rememberedItemId, "deleted item kept a pending selection")
  }

  function testSearchPreference() {
    refreshList([a, b, c])
    overlay.applyConfig({ server_url: session.server_url, remember_last_search: true })
    overlay.searchQuery = "Same"
    closeOnBeta()
    check(!overlay.rememberedItemId, "two retention policies ran at once")
    refreshList([b, c, a])
    warmOpen("beta")
    statusProc.reply(session)
    check(overlay.searchQuery === "Same", "opt-in lost its query")
    select("alpha")
    refreshList([a, b, c])
    check(overlay.selectedItem.id === "alpha", "refresh overrode manual navigation")

    overlay.applyConfig({ server_url: session.server_url, remember_last_search: false })
    closeOnBeta()
    overlay.open(JSON.stringify({ view: "ssh-approval" }))
    overlay.close()
    check(overlay.rememberedItemId === "beta", "SSH-only open/close changed the selection")
    statusProc.reply(session)
    overlay.selectionExpiresAt = Date.now() - 1
    warmOpen("alpha")
    statusProc.reply(session)
    check(!overlay.rememberedItemId, "suspend or delayed timer restored an expired item")
  }

  function testSessionBoundaries() {
    // A probe started before hiding cannot validate the next view.
    overlay.refreshAuthStatus()
    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("primary")
    statusProc.reply(session)
    check(!overlay.selectedItem && overlay.pendingFieldCopy, "old status validated a new view")
    overlay.refreshAuthStatus()
    statusProc.reply(Object.assign({}, session, { lock_generation: "8000000000000000002" }))
    check(!overlay.pendingFieldCopy && !overlay.highlightedItem && !processEnding("copy", "30").running,
          "external lock/unlock copied from the old session")
    listProc.reply([a, b])
    check(overlay.selectedItem.id === "alpha", "new session restored the old selection")

    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("username")
    statusProc.reply({ status: "locked", has_session: true, server_url: session.server_url })
    check(!overlay.highlightedItem && !overlay.pendingFieldCopy && !processEnding("copy", "30").running, "hidden lock released a credential")
    overlay.refreshAuthStatus()
    statusProc.reply(session)
    listProc.reply([a, b])

    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("primary")
    overlay.applyConfig({ server_url: "https://second.example" })
    statusProc.reply(session)
    check(!overlay.highlightedItem && !overlay.pendingFieldCopy && !processEnding("copy", "30").running, "server switch kept the old copy")
    overlay.refreshAuthStatus()
    statusProc.reply(session)
    listProc.reply([a, b])
    closeOnBeta()
    warmOpen("beta")
    overlay.requestFieldCopy("primary")
    overlay.doLock()
    check(overlay.authState.status === "unlocked" && !overlay.pendingFieldCopy && !overlay.highlightedItem,
          "pending lock claimed success or retained the selected credential")
    processEnding("auth", "lock").reply({ ok: true, status: "locked", epoch_advanced: true })
    statusProc.reply(session)
    check(overlay.authState.status === "locked" && !overlay.pendingFieldCopy && !overlay.highlightedItem, "a stale status undid manual lock")

    var legacy = Object.assign({}, session, { lock_generation: undefined })
    overlay.refreshAuthStatus()
    statusProc.reply(legacy)
    listProc.reply([a, b])
    closeOnBeta()
    check(!overlay.rememberedItemId, "older engine allowed an unverified remembered ID")
    overlay.toggle()
    check(overlay.selectedItem.id === "alpha", "older engine lost the default reopen behavior")
    statusProc.reply(session)
    closeOnBeta()
    overlay.doLogout()
    check(!overlay.rememberedItemId && !overlay.highlightedItem, "logout retained the selection")
  }

  Timer {
    id: checkExpiry
    interval: 100
    onTriggered: {
      try {
        check(!overlay.rememberedItemId, "the TTL did not expire while hidden")
        check(!statusProc.running, "a status poll started while hidden")
        console.log("Remembered selection lifecycle passed")
        Qt.exit(0)
      } catch (e) { console.error(e); Qt.exit(1) }
    }
  }

  Component.onCompleted: {
    try {
      overlay.applyConfig({ server_url: session.server_url, remember_last_search: false, check_updates: false })
      overlay.cliHealth = ({ clipboard_available: true })
      overlay.open("{}")
      statusProc = processEnding("auth status", "omawarden")
      statusProc.reply(session)
      listProc = processEnding("vault", "list")
      listProc.reply([a, b, c])
      testImmediateKeys()
      testSearchPreference()
      testSessionBoundaries()

      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      for (var i = 0; i < overlay.data.length; i++) {
        var timer = overlay.data[i]
        if (timer.interval === 3000 && timer.repeat) check(!timer.running, "lockSyncTimer is polling while hidden")
        if (timer.interval === 30000 && timer.running) { timer.interval = 10; timer.restart() }
      }
      checkExpiry.start()
    } catch (e) { console.error(e, e.stack); Qt.exit(1) }
  }
}
