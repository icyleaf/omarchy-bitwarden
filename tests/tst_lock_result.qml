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

  function statusProcess() {
    for (var i = 0; i < overlay.data.length; ++i) {
      var child = overlay.data[i]
      if (child.command && child.command.join(" ").indexOf(" auth status") !== -1) return child
    }
    throw new Error("Missing auth status process")
  }

  function beginLock(withStatusInFlight) {
    statusProcess().running = false
    overlay.authState = ({
      status: "unlocked", server_url: "https://vault.example",
      user_email: "fixture@example.invalid", has_session: true, lock_generation: "1"
    })
    overlay.rawVaultItems = [{ id: "fixture", login: { password: "fixture-password" } }]
    overlay.errorMessage = ""
    if (withStatusInFlight) {
      overlay.refreshAuthStatus()
      check(statusProcess().running, "fixture did not start the pre-lock status request")
    }
    overlay.doLock()
    check(overlay.authState.status === "unlocked", "lock status changed before confirmation")
    check(overlay.rawVaultItems.length === 0, "pending lock retained locally displayed secrets")
    check(overlay.isBusy, "pending lock did not report busy state")
    var revision = overlay.vaultRevision
    overlay.doLock()
    check(overlay.vaultRevision === revision, "a repeated lock replaced the pending request")
    overlay.refreshAuthStatus()
    check(statusProcess().running === Boolean(withStatusInFlight),
          "locking changed the pending status request or started a new poll")
    return processFor("lock")
  }

  function output(process, value) {
    process.stdout.text = typeof value === "string" ? value : JSON.stringify(value)
    process.stdout.streamFinished()
  }

  function exit(process, code, status) {
    process.running = false
    process.exited(code, status)
  }

  Component.onCompleted: {
    try {
      overlay.refreshAuthStatus()
      var process = beginLock()
      output(process, { ok: true, status: "locked", epoch_advanced: true })
      check(overlay.authState.status === "unlocked", "stdout committed lock before process exit")
      exit(process, 0, 0)
      check(overlay.authState.status === "locked" && !overlay.isBusy, "confirmed lock was not applied")
      check(overlay.errorMessage === "" && statusProcess().running, "confirmed lock did not refresh status")

      process = beginLock()
      exit(process, 0, 0)
      check(overlay.isBusy && overlay.authState.status === "unlocked", "exit committed lock before stdout")
      output(process, { ok: true, status: "locked" })
      check(overlay.authState.status === "locked" && !overlay.isBusy, "reversed completion order lost lock result")

      for (var statusAfterLock of [false, true]) {
        process = beginLock(true)
        var staleStatus = {
          status: "unlocked", server_url: "https://vault.example",
          user_email: "fixture@example.invalid", has_session: true, lock_generation: "1"
        }
        var stateBeforeReply = overlay.authState
        if (statusAfterLock) {
          output(process, { ok: true, status: "locked", epoch_advanced: true })
          exit(process, 0, 0)
          stateBeforeReply = overlay.authState
        }
        statusProcess().reply(staleStatus)
        check(overlay.authState === stateBeforeReply,
              "a pre-lock status reply replaced the current auth state")
        check(overlay.rawVaultItems.length === 0,
              "a pre-lock status reply restored sensitive items")
        if (!statusAfterLock) {
          check(overlay.isBusy, "a pre-lock status reply completed the pending lock")
          output(process, { ok: true, status: "locked", epoch_advanced: true })
          exit(process, 0, 0)
        }
        check(overlay.authState.status === "locked" && !overlay.isBusy,
              "a pre-lock status reply prevented or undid the confirmed lock")
      }

      var failures = [
        { reply: { ok: false, error: "Owner confirmation failed" }, code: 1, status: 0 },
        { reply: { ok: true, status: "locked" }, code: 1, status: 0 },
        { reply: { ok: true, status: "locked" }, code: 0, status: 1 },
        { reply: "not-json", code: 0, status: 0 },
        { reply: "", code: 0, status: 0 }
      ]
      for (var i = 0; i < failures.length; ++i) {
        process = beginLock()
        output(process, failures[i].reply)
        exit(process, failures[i].code, failures[i].status)
        check(overlay.authState.status === "unlocked", "failed lock reported locked in case " + i)
        check(Boolean(overlay.errorMessage) && !overlay.isBusy, "failed lock was silent in case " + i)
        check(statusProcess().running, "failed lock did not refresh status in case " + i)
      }

      for (var legacy of [false, true]) {
        process = beginLock()
        var warning = "Vault locked. Shared output revocation is pending."
        var reply = { ok: true, status: "locked", epoch_advanced: false }
        reply[legacy ? "error" : "warning"] = warning
        output(process, reply)
        exit(process, 0, 0)
        check(overlay.authState.status === "locked", "epoch warning hid confirmed lock")
        check(overlay.errorMessage === "", "epoch warning was presented as lock failure")
        check(overlay.statusMessage === warning, "epoch warning was discarded")
        statusProcess().reply({ status: "locked", server_url: "https://vault.example",
                                user_email: "fixture@example.invalid", has_session: true })
        check(overlay.statusMessage === warning, "status refresh discarded the epoch warning")
      }

      process = beginLock()
      overlay.clearSensitiveState()
      overlay.authState = ({ status: "unlocked", user_email: "new@example.invalid", lock_generation: "2" })
      overlay.isBusy = true
      overlay.statusMessage = "New session operation"
      output(process, { ok: true, status: "locked" })
      exit(process, 0, 0)
      process.stderr.text = "stale lock diagnostic"
      process.stderr.streamFinished()
      check(overlay.authState.status === "unlocked" && overlay.authState.user_email === "new@example.invalid",
            "stale lock reply changed the new session")
      check(overlay.isBusy && overlay.statusMessage === "New session operation",
            "stale lock reply changed the new operation")
      check(!overlay.logBuffer.some(entry => entry.message.indexOf("stale lock diagnostic") !== -1),
            "stale lock stderr reached the new session")
      console.log("Lock result confirmation and warning tests passed")
      Qt.exit(0)
    } catch (e) { console.error(e, e.stack); Qt.exit(1) }
  }
}
