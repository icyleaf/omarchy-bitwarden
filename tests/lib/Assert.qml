pragma Singleton
import QtQuick

// Shared assertion harness for the standalone QML suites.
// Import it alongside the components under test:  import "lib"
// then report with Assert.check(...) / Assert.checkContrast(...) and finish
// with Qt.exit(Assert.exitCode()).
QtObject {
  id: harness

  property int failures: 0

  function check(condition, message) {
    if (condition) {
      console.log("PASS: " + message)
    } else {
      failures++
      console.error("FAIL: " + message)
    }
  }

  function exitCode() {
    return failures === 0 ? 0 : 1
  }

  // Depth-first search for a Text element by its rendered string.
  function findText(item, text) {
    if (!item) return null
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].text === text) return kids[i]
      var found = findText(kids[i], text)
      if (found) return found
    }
    return null
  }

  // --- WCAG contrast helpers ---
  function channelLuminance(value) {
    return value <= 0.03928 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4)
  }

  function relativeLuminance(colorValue) {
    var c = Qt.color(colorValue)
    return 0.2126 * channelLuminance(c.r) + 0.7152 * channelLuminance(c.g) + 0.0722 * channelLuminance(c.b)
  }

  function contrastRatio(first, second) {
    var a = relativeLuminance(first)
    var b = relativeLuminance(second)
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
  }

  // Paints a translucent role wash over `base` so the assertion measures the
  // color the user actually sees, not the raw role.
  function compositeOver(fill, alpha, base) {
    var f = Qt.color(fill)
    var b = Qt.color(base)
    return Qt.rgba(f.r * alpha + b.r * (1 - alpha),
                   f.g * alpha + b.g * (1 - alpha),
                   f.b * alpha + b.b * (1 - alpha), 1)
  }

  function checkContrast(tag, label, textColor, fillColor) {
    var ratio = contrastRatio(textColor, fillColor)
    check(ratio >= 3, tag + ": " + label + " contrast " + ratio.toFixed(2) + ":1 >= 3:1")
  }
}
