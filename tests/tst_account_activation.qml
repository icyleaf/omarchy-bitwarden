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
      overlay.cliHealth = ({ clipboard_available: true })
      overlay.rawVaultItems = [previous]
      overlay.loadVaultItems()
      var list = processFor("list")
      overlay.syncVault(true, true)
      var sync = processFor("sync")
      overlay.viewAttachment(previous, { id: "old-attachment", file_name: "old.txt" })
      var attachment = processFor("attachment")
      overlay.copyToClipboard(previous.login.password, true, "password")
      var clipboard = processFor("copy")
      check(clipboard.command.indexOf("--expected-lock-generation") !== -1
            && clipboard.command.indexOf("1") !== -1, "copy was not bound to the old session")
      check(attachment.command.indexOf("--expected-lock-generation") !== -1
            && attachment.command.indexOf("1") !== -1, "attachment was not bound to the old session")
      overlay.sshApprovalPrompt = ({ id: 2, key_name: "old key" })
      overlay.sshApprovalOnly = true
      overlay.refreshSshApprovals()
      var approvals = processFor("pending")
      var previousRevision = overlay.vaultRevision

      overlay.doLoginPassword("new@example.invalid", "fixture-password")
      var login = processFor("login-password")
      login.reply({ ok: true, status: "unlocked" })
      check(overlay.rawVaultItems.length === 0 && overlay.vaultRevision > previousRevision,
            "account activation retained the previous account's rows")
      check(!clipboard.running && clipboard.secret === "", "account activation retained a copy helper")
      check(!attachment.running && attachment.activeItemId === "", "account activation retained an attachment helper")
      check(overlay.sshApprovalPrompt === null && !overlay.sshApprovalOnly,
            "account activation retained the previous SSH approval view")

      overlay.isLoadingVault = true
      overlay.isBusy = true
      var message = overlay.statusMessage
      sync.stderr.text = "late-old-sync-error"
      sync.stderr.streamFinished()
      attachment.stderr.text = "late-old-attachment-error"
      attachment.stderr.streamFinished()
      list.reply([previous])
      sync.reply({ ok: false, error: "Please log in again." })
      attachment.reply({ ok: true, action: "preview", filename: "old.txt" })
      clipboard.exited(0, 0)
      approvals.reply({ ok: true, prompts: [{ id: 2, key_name: "old key" }] })
      check(overlay.authState.status === "unlocked" && overlay.rawVaultItems.length === 0,
            "an old vault response changed the new session")
      check(overlay.activeAttachmentPreview === null, "an old attachment was displayed")
      check(overlay.statusMessage === message, "an old clipboard helper changed the new session's status")
      check(overlay.sshApprovalPrompt === null, "a late SSH reply restored an old approval")
      check(overlay.isLoadingVault && overlay.isBusy, "old replies cleared the new session's loading state")
      check(!overlay.logBuffer.some(entry => entry.message.indexOf("late-old-") !== -1),
            "an old helper wrote an error into the new session's log")

      overlay.doLoginPassword("new@example.invalid", "fixture-password")
      login.reply({ ok: true, status: "locked" })
      check(overlay.authState.status === "locked" && overlay.statusMessage.indexOf("API Key") === -1,
            "a locked password login was presented as API Key authentication")
      overlay.open(JSON.stringify({ view: "ssh-approval" }))
      approvals.reply({ ok: true, prompts: [{ id: 3, key_name: "current key" }] })
      check(overlay.sshApprovalPrompt && overlay.sshApprovalPrompt.id === 3,
            "opening the overlay for a new SSH approval discarded the prompt")
      overlay.authState = ({ status: "unlocked", lock_generation: "2", has_session: true })
      overlay.clearSensitiveState()
      check(!overlay.sshApprovalOnly && overlay.sshApprovalPrompt === null,
            "discarding an unlocked session retained approval-only mode")
      console.log("Account activation overlay handoff passed")
      Qt.exit(0)
    } catch (e) { console.error(e, e.stack); Qt.exit(1) }
  }
}
