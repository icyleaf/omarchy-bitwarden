import QtQuick
import QtQuick.Controls
import "../components"

Item {
  width: 800; height: 600
  property int failures: 0
  property var replies: []
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

  SshApprovalModal {
    id: modal
    onReplyRequested: function(approve) { replies.push(approve) }
  }

  // The Text item under `item` showing exactly `text`, if any.
  function findText(item, text) {
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].text === text) return kids[i]
      var found = findText(kids[i], text)
      if (found) return found
    }
    return null
  }

  Component.onCompleted: {
    // Hidden until the overlay is open and a prompt exists
    check(modal.visible === false, "hidden with no prompt")
    modal.active = true
    check(modal.visible === false, "hidden when active but no prompt")

    modal.prompt = ({ id: 1, title: "Sign with Git?", action: "Git commit or tag signature", key_name: "Work", fingerprint: "SHA256:abc",
                      client: "git (ssh)", command: "ssh-keygen -Y sign", forwarded: false, remembered: true })
    check(modal.visible === true, "visible with a prompt")

    modal.active = false
    check(modal.visible === false, "hidden when the overlay closes")
    modal.active = true

    // Forwarded requests switch the card border to the danger color
    modal.prompt = ({ id: 2, title: "Log in to vps?", action: "SSH login as root@vps", key_name: "Work", fingerprint: "SHA256:abc",
                      client: "ssh", command: "ssh vps", forwarded: true, remembered: false })
    check(modal.visible === true, "forwarded prompt visible")

    // Text from the request (user names, namespaces, commands) can come from a
    // forwarding host, so it must never be read as rich text.
    var fields = [modal.prompt.title, modal.prompt.action, modal.prompt.key_name,
                  modal.prompt.fingerprint, modal.prompt.client, modal.prompt.command]
    for (var i = 0; i < fields.length; i++) {
      var t = findText(modal, fields[i])
      check(t !== null, "a Text shows " + fields[i])
      if (t) check(t.textFormat === Text.PlainText, "plain text for " + fields[i])
    }
    modal.prompt = ({ id: 2, title: "<b>Log in</b>", action: "root<font size=7>@x</font>", key_name: "<i>k</i>", fingerprint: "SHA256:abc",
                      client: "ssh", command: "ssh <u>vps</u>", forwarded: true, remembered: false })
    var markup = findText(modal, "root<font size=7>@x</font>")
    check(markup !== null && markup.textFormat === Text.PlainText && markup.text === "root<font size=7>@x</font>",
          "markup in the action is shown literally")

    // When first-use cannot remember due to an unidentified requester, the footer explains why as plain text
    modal.prompt = ({ id: 4, title: "Use SSH key?", action: "SSH login as root", key_name: "Work", fingerprint: "SHA256:abc",
                      client: "A program", command: "Command unavailable", forwarded: false, remembered: false,
                      remember_unavailable_reason: "<b>Cannot</b> identify requester; approval will not be remembered" })
    var reasonFooter = findText(modal, "Enter allow · Esc deny · <b>Cannot</b> identify requester; approval will not be remembered")
    check(reasonFooter !== null && reasonFooter.textFormat === Text.PlainText,
          "footer displays remember_unavailable_reason literally as plain text")

    // Without remember_unavailable_reason and with remembered=false, the standard footer is shown
    modal.prompt = ({ id: 2, title: "<b>Log in</b>", action: "root<font size=7>@x</font>", key_name: "<i>k</i>", fingerprint: "SHA256:abc",
                      client: "ssh", command: "ssh <u>vps</u>", forwarded: true, remembered: false })
    var defaultFooter = findText(modal, "Enter allow · Esc deny")
    check(defaultFooter !== null, "standard footer shown when remember_unavailable_reason is omitted")

    // The card opens by itself: Allow is ignored until it has been up briefly
    replies = []
    check(modal.armed === false, "a new prompt starts unarmed")
    modal.allow()
    check(replies.length === 0, "allow is ignored before arming")
    armWait.start()
  }

  Timer {
    id: armWait
    interval: 800
    onTriggered: {
      check(modal.armed === true, "armed after the delay")
      // A polling refresh of the same prompt doesn't re-arm
      modal.prompt = Object.assign({}, modal.prompt)
      check(modal.armed === true, "refreshing the same prompt keeps it armed")
      modal.allow()
      check(replies.length === 1 && replies[0] === true, "allow approves once armed")

      // A different prompt starts unarmed again
      modal.prompt = Object.assign({}, modal.prompt, { id: 3 })
      check(modal.armed === false, "a new prompt re-arms")
      Qt.exit(failures === 0 ? 0 : 1)
    }
  }
}
