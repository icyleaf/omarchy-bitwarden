pragma Singleton
import QtQuick

// Stand-in for Omarchy's qs.Commons Color singleton.
// Lets component tests run under plain `qml6`:
//   qml6 -I tests/stubs tests/tst_theme_color_adaptation.qml
QtObject {
  id: root

  property color foreground: "#a9b1d6"
  property color background: "#1a1b26"
  property color accent: "#7aa2f7"
  property color urgent: "#f7768e"
  property color muted: "#565f89"

  readonly property QtObject popups: QtObject {
    property color background: root.background
    property color text: root.foreground
    property color border: root.accent
  }

  readonly property QtObject menu: QtObject {
    property color background: root.background
    property color text: root.foreground
    property color border: root.foreground
    property color scrim: root.background
    property color selectedBackground: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08)
    property color selectedText: root.accent
    property color selectedBorder: root.foreground
  }

  readonly property QtObject tooltip: QtObject {
    property color background: root.background
    property color text: root.foreground
    property color border: root.foreground
  }

  function setPreset(name) {
    var p = String(name || "").toLowerCase().trim()
    if (p === "catppuccin-latte" || p === "light") {
      foreground = "#4c4f69"
      background = "#eff1f5"
      accent = "#1e66f5"
      urgent = "#d20f39"
      muted = "#acb0be"
    } else if (p === "tokyo-night" || p === "dark" || p === "" || p === "default") {
      foreground = "#a9b1d6"
      background = "#1a1b26"
      accent = "#7aa2f7"
      urgent = "#f7768e"
      muted = "#565f89"
    } else {
      console.warn("Color.setPreset: unknown preset '" + name + "', falling back to dark")
      foreground = "#a9b1d6"
      background = "#1a1b26"
      accent = "#7aa2f7"
      urgent = "#f7768e"
      muted = "#565f89"
    }
  }
}
