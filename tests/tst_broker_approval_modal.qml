import QtQuick
import QtQuick.Controls
import "../components"

Item {
  width: 800; height: 600
  property int failures: 0
  property var replies: []
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

  BrokerApprovalModal {
    id: modal
    onReplyRequested: function(decision) { replies.push(decision) }
  }

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
    // 1. Hidden until overlay is active and prompt exists
    check(modal.visible === false, "hidden with no prompt")
    modal.active = true
    check(modal.visible === false, "hidden when active but no prompt")

    modal.prompt = ({
      id: 1,
      title: "Authorize Secret Access for OpenAI",
      cipher_ref: "OpenAI",
      binary_path: "/usr/bin/python3",
      command: "python3 -m my_agent --run",
      caller_app: "alacritty"
    })
    check(modal.visible === true, "visible with prompt")

    modal.active = false
    check(modal.visible === false, "hidden when overlay closes")
    modal.active = true

    // 2. Text fields must strictly render as plain text to prevent rich text or HTML injection
    var fields = [modal.prompt.title, modal.prompt.cipher_ref, modal.prompt.binary_path,
                  modal.prompt.command, modal.prompt.caller_app]
    for (var i = 0; i < fields.length; i++) {
      var t = findText(modal, fields[i])
      check(t !== null, "a Text item shows " + fields[i])
      if (t) check(t.textFormat === Text.PlainText, "plain text format for " + fields[i])
    }

    // Markup injection test: ensure HTML tags are displayed literally
    modal.prompt = ({
      id: 2,
      title: "<b>Inject</b>",
      cipher_ref: "<script>alert(1)</script>",
      binary_path: "/bin/sh",
      command: "sh -c <font color=red>bad</font>",
      caller_app: "<i>terminal</i>"
    })
    var markup = findText(modal, "<script>alert(1)</script>")
    check(markup !== null && markup.textFormat === Text.PlainText && markup.text === "<script>alert(1)</script>",
          "script tags in cipher_ref are displayed literally as plain text")

    // 3. Armed delay logic: premature clicks/enter must be blocked
    replies = []
    check(modal.armed === false, "new prompt starts unarmed")
    modal.allowOnce()
    modal.allowAlways()
    check(replies.length === 0, "allow is ignored before arming timer completes")

    // Deny works immediately even before arming
    modal.deny()
    check(replies.length === 1 && replies[0] === "deny", "deny works immediately")

    replies = []
    armWait.start()
  }

  Timer {
    id: armWait
    interval: 800
    onTriggered: {
      check(modal.armed === true, "modal is armed after armTimer interval")

      modal.allowOnce()
      check(replies.length === 1 && replies[0] === "allow_once", "allowOnce registers when armed")

      modal.allowAlways()
      check(replies.length === 2 && replies[1] === "allow_always", "allowAlways registers when armed")

      // Switching prompt resets armed state
      modal.prompt = Object.assign({}, modal.prompt, { id: 3 })
      check(modal.armed === false, "switching prompt resets armed state")

      Qt.exit(failures === 0 ? 0 : 1)
    }
  }
}
