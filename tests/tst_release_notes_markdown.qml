import QtQuick
import QtQuick.Controls
import "../components"

ApplicationWindow {
  id: testRunner
  visible: true
  width: 400
  height: 300

  ReleaseNotesModal {
    id: modal
  }

  function assert(condition, message) {
    if (!condition) {
      console.error("ASSERTION FAILED: " + message)
      Qt.quit()
      throw new Error("Assertion failed: " + message)
    } else {
      console.log("PASS: " + message)
    }
  }

  Timer {
    id: testTimer
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Release Notes Markdown Rendering Tests...")

      var rawInput = "- **(auth)**: Fix sync failure and unlock flow when logging in via api key (#99) ([7384f3f](https://github.com/icyleaf/omarchy-bitwarden/commit/7384f3f8754))"
      var rendered = modal.renderMarkdown(rawInput)

      console.log("Rendered output:\n" + rendered)

      // Test 1: Should NOT contain broken attribute leakage in commit link text:
      // e.g. 7384f3f' style='color: #60a5fa; text-decoration: underline;'>7384f3f
      assert(rendered.indexOf("7384f3f' style=") === -1, "No broken attribute leakage in commit link text")
      assert(rendered.indexOf("<a href='<a") === -1, "No nested <a href='<a tag corruption")

      // Test 2: Commit link should be cleanly rendered
      assert(rendered.indexOf("<a href='https://github.com/icyleaf/omarchy-bitwarden/commit/7384f3f8754'") !== -1, "Commit link has correct href")
      assert(rendered.indexOf(">7384f3f</a>") !== -1, "Commit link has correct label")

      // Test 3: PR link should be cleanly rendered
      var prInput = "- Fix some issue ([#99](https://github.com/icyleaf/omarchy-bitwarden/pull/99))"
      var prRendered = modal.renderMarkdown(prInput)
      assert(prRendered.indexOf("<a href='<a") === -1, "No nested tags for markdown PR links")
      assert(prRendered.indexOf("style='color: #60a5fa; text-decoration: underline;'>#99</a>") !== -1, "PR link rendered cleanly")

      // Test 4: Standalone URLs should still work
      var urlInput = "- See https://github.com/icyleaf/omarchy-bitwarden/commit/1234567890abcdef"
      var urlRendered = modal.renderMarkdown(urlInput)
      assert(urlRendered.indexOf("<a href='<a") === -1, "Standalone commit URL rendered cleanly without double wrapping")

      console.log("ALL RELEASE NOTES MARKDOWN TESTS PASSED!")
      Qt.quit()
    }
  }
}
