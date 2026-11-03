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

  function closeOnBeta() {
    overlay.selectedIndex = overlay.filteredItems.findIndex(it => it.id === "beta")
    check(overlay.selectedItem && overlay.selectedItem.id === "beta", "test setup selected beta")
    overlay.toggle()
    overlay.close() // shell.hide() delivers close() again
    check(overlay.rememberedItemId === "beta", "second close overwrote the remembered ID")
  }

  function reopen(items) {
    overlay.toggle()
    check(!overlay.selectedItem, "field actions were available before auth was checked")
    statusProc.reply(session)
    check(!overlay.selectedItem, "field actions were available before the local list arrived")
    listProc.reply(items)
  }

  Timer {
    id: checkExpiry
    interval: 100
    onTriggered: {
      try {
        check(overlay.rememberedItemId === "", "the timer did not clear the hidden selection")
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
      overlay.searchQuery = "Same"
      closeOnBeta()
      check(overlay.searchQuery === "", "default search preference retained query text")
      reopen([c, a, b])
      check(overlay.selectedIndex === 2 && overlay.selectedItem.id === "beta", "reordered duplicate names restored the wrong item")

      overlay.copyItemUsername(overlay.selectedItem)
      check(copiedText() === "user-b", "username shortcut used the wrong item")
      overlay.executePrimaryAction(overlay.selectedItem)
      check(copiedText() === "pass-b", "password shortcut used the wrong item")
      processEnding("totp", "beta").reply({ code: "123456", ttl: 28, period: 30 })
      overlay.copyItemTotp(overlay.selectedItem)
      check(copiedText() === "123456", "TOTP shortcut did not use the restored item")

      // A status poll and a list refresh from the old view may both finish after reopening.
      overlay.refreshAuthStatus()
      overlay.loadVaultItems()
      closeOnBeta()
      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([b])
      check(!overlay.selectedItem && overlay.rememberedItemId === "beta", "stale replies exposed an item")
      overlay.refreshAuthStatus()
      statusProc.reply(session)
      listProc.reply([a, b, c])

      overlay.applyConfig({ server_url: session.server_url, remember_last_search: true })
      overlay.searchQuery = "Same"
      closeOnBeta()
      reopen([b, c, a])
      check(overlay.searchQuery === "Same" && overlay.selectedItem.id === "beta", "remembered search lost its query or item")
      overlay.selectedIndex = 1 // alpha
      overlay.loadVaultItems()
      listProc.reply([a, b, c])
      check(overlay.selectedItem.id === "alpha", "later refresh overrode manual navigation")
      closeOnBeta()
      reopen([a, { id: "beta", name: "Renamed", type_name: "login", login: {} }])
      check(overlay.selectedItem.id === "alpha" && overlay.filteredItems.length === 1, "restore bypassed the search filter")

      overlay.applyConfig({ server_url: session.server_url, remember_last_search: false })
      overlay.searchQuery = ""
      overlay.loadVaultItems()
      listProc.reply([a, b, c])
      closeOnBeta()
      reopen([a, c])
      check(overlay.selectedItem.id === "alpha" && !overlay.rememberedItemId, "deleted ID did not fall back to the first result")
      overlay.loadVaultItems()
      listProc.reply([a, b, c])
      closeOnBeta()
      overlay.open(JSON.stringify({ view: "ssh-approval" }))
      overlay.close()
      check(overlay.rememberedItemId === "beta", "SSH-only open/close replaced the selection")

      overlay.selectionExpiresAt = Date.now() - 1
      overlay.toggle()
      check(!overlay.rememberedItemId && overlay.selectedItem.id === "alpha", "overdue timer restored an expired ID")
      statusProc.reply(session)
      closeOnBeta()
      overlay.toggle()
      statusProc.reply({ status: "locked", has_session: true, server_url: session.server_url })
      check(!overlay.rememberedItemId && !overlay.selectedItem, "lock while hidden restored a cached item")

      overlay.refreshAuthStatus()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      overlay.refreshAuthStatus() // the hidden lock timer polls while the ID is live
      statusProc.reply({ status: "locked", has_session: true, server_url: session.server_url })
      check(!overlay.opened && !overlay.rememberedItemId && !listProc.running, "hidden lock retained the ID or reloaded the vault")
      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      overlay.toggle()
      statusProc.reply(Object.assign({}, session, { lock_generation: "8000000000000000002" }))
      listProc.reply([a, b])
      check(!overlay.rememberedItemId && overlay.selectedItem.id === "alpha", "missed lock/unlock cycle restored beta")
      closeOnBeta()
      overlay.toggle()
      statusProc.reply(Object.assign({}, session, { lock_generation: undefined }))
      listProc.reply([a, b])
      overlay.selectedIndex = 1
      overlay.toggle()
      check(!overlay.rememberedItemId, "older engine allowed a restore without a lock generation")
      overlay.toggle()
      statusProc.reply(session)
      closeOnBeta()
      overlay.applyConfig({ server_url: "https://second.example" })
      check(!overlay.rememberedItemId && !overlay.selectedItem, "switching servers retained the old selection")
      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      overlay.refreshAuthStatus()
      overlay.doLock()
      statusProc.reply(session)
      check(overlay.authState.status === "locked" && !overlay.rememberedItemId, "stale auth reply undid an explicit lock")
      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      overlay.doLogout()
      check(!overlay.rememberedItemId && !overlay.selectedItem, "logout retained the old selection")

      overlay.toggle()
      statusProc.reply(session)
      listProc.reply([a, b])
      closeOnBeta()
      for (var j = 0; j < overlay.data.length; ++j) {
        var timer = overlay.data[j]
        if (timer.interval === 30000 && timer.running) { timer.interval = 10; timer.restart(); break }
      }
      checkExpiry.start()
    } catch (e) { console.error(e, e.stack); Qt.exit(1) }
  }
}
