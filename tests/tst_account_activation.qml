import QtQuick
import ".."

Item {
  OmarchyBitwarden { id: overlay }

  function check(condition, message) {
    if (!condition) throw new Error(message)
  }

  function processFor(argument) {
    for (var i = 0; i < overlay.data.length; ++i) {
      var child = overlay.data[i]
      if (child.command && child.command.indexOf(argument) !== -1) return child
    }
    throw new Error("Missing process for " + argument)
  }

  Component.onCompleted: {
    try {
      var previous = {
        id: "old-only", type_name: "login", name: "Previous account",
        login: { password: "fixture-old-password" }
      }
      overlay.authState = ({
        status: "unlocked", has_session: true, server_url: "https://vault.example",
        user_id: "old-user", lock_generation: "1"
      })
      overlay.rawVaultItems = [previous]
      overlay.loadVaultItems()
      var list = processFor("list")
      overlay.syncVault(true, true)
      var sync = processFor("sync")
      overlay.viewAttachment(previous, { id: "old-attachment", file_name: "old.txt" })
      var attachment = processFor("attachment")
      var previousRevision = overlay.vaultRevision

      overlay.doLoginPassword("new@example.invalid", "fixture-password")
      var login = processFor("login-password")
      login.reply({ ok: true, status: "unlocked" })
      check(overlay.rawVaultItems.length === 0 && overlay.vaultRevision > previousRevision,
            "account activation retained the previous account's rows")

      list.reply([previous])
      sync.reply({ ok: false, error: "Please log in again." })
      attachment.reply({ ok: true, action: "preview", filename: "old.txt" })
      check(overlay.authState.status === "unlocked" && overlay.rawVaultItems.length === 0,
            "an old vault response changed the new session")
      check(overlay.activeAttachmentPreview === null, "an old attachment was displayed")

      overlay.doLoginPassword("new@example.invalid", "fixture-password")
      login.reply({ ok: true, status: "locked" })
      check(overlay.authState.status === "locked" && overlay.statusMessage.indexOf("API Key") === -1,
            "a locked password login was presented as API Key authentication")
      console.log("Account activation overlay handoff passed")
      Qt.exit(0)
    } catch (e) { console.error(e, e.stack); Qt.exit(1) }
  }
}
