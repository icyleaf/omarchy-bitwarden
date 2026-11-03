import QtQuick
import QtQuick.Controls
import "../components"
import "lib"

ApplicationWindow {
  id: testRunner
  visible: true
  width: 400
  height: 300

  ReleaseNotesModal {
    id: modal
  }

  Timer {
    id: testTimer
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running Release Notes Markdown Rendering Tests...")

      // Link colors come from the accent token, so the expected string is
      // derived from the modal instead of a literal that goes stale whenever
      // the palette changes.
      var accent = String(modal.accent)

      var rawInput = "- **(auth)**: Fix sync failure and unlock flow when logging in via api key (#99) ([7384f3f](https://github.com/icyleaf/omarchy-bitwarden/commit/7384f3f8754))"
      var rendered = modal.renderMarkdown(rawInput)

      console.log("Rendered output:\n" + rendered)

      // Test 1: Should NOT contain broken attribute leakage in commit link text:
      // e.g. 7384f3f' style='color: <accent>; text-decoration: underline;'>7384f3f
      Assert.check(rendered.indexOf("7384f3f' style=") === -1, "No broken attribute leakage in commit link text")
      Assert.check(rendered.indexOf("<a href='<a") === -1, "No nested <a href='<a tag corruption")

      // Test 2: Commit link should be cleanly rendered
      Assert.check(rendered.indexOf("<a href='https://github.com/icyleaf/omarchy-bitwarden/commit/7384f3f8754'") !== -1, "Commit link has correct href")
      Assert.check(rendered.indexOf(">7384f3f</a>") !== -1, "Commit link has correct label")

      // Test 3: PR link should be cleanly rendered, keep its own href and be
      // labelled with the PR number in the accent color.
      var prInput = "- Fix some issue ([#99](https://github.com/icyleaf/omarchy-bitwarden/pull/99))"
      var prRendered = modal.renderMarkdown(prInput)
      Assert.check(prRendered.indexOf("<a href='<a") === -1, "No nested tags for markdown PR links")
      Assert.check(prRendered.indexOf("<a href='https://github.com/icyleaf/omarchy-bitwarden/pull/99'") !== -1, "PR link has correct href")
      Assert.check(prRendered.indexOf("style='color: " + accent + "; text-decoration: underline;'>#99</a>") !== -1, "PR link rendered cleanly with the accent color")

      // Test 4: Standalone URLs should still work
      var urlInput = "- See https://github.com/icyleaf/omarchy-bitwarden/commit/1234567890abcdef"
      var urlRendered = modal.renderMarkdown(urlInput)
      Assert.check(urlRendered.indexOf("<a href='<a") === -1, "Standalone commit URL rendered cleanly without double wrapping")

      if (Assert.failures === 0)
        console.log("ALL RELEASE NOTES MARKDOWN TESTS PASSED!")

      Qt.exit(Assert.exitCode())
    }
  }
}
