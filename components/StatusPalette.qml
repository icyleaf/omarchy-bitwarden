pragma Singleton
import QtQuick
import qs.Commons as Commons

// Plugin-owned semantic status palette (Spec #291 / ADR 0026):
// Single source of truth for all non-theme status colors, diagnostic badges,
// packaging tags, and contrast-safe label calculation.
QtObject {
  id: palette

  // --- 1. Health Status Indicators ---
  readonly property color ok: "#4ade80"
  readonly property color fail: Commons.Color.urgent

  // --- 2. Diagnostic Log Levels ---
  readonly property color error: Commons.Color.urgent
  readonly property color warn: "#f59e0b"
  readonly property color info: "#3b82f6"
  readonly property color debug: "#a855f7"
  readonly property color trace: "#6b7280"

  function levelColor(level) {
    switch (String(level || "").toUpperCase()) {
      case "ERROR":
      case "FATAL":
        return palette.error
      case "WARN":
      case "WARNING":
        return palette.warn
      case "INFO":
        return palette.info
      case "DEBUG":
        return palette.debug
      case "TRACE":
      default:
        return palette.trace
    }
  }

  // --- 3. Packaging & Engine Source Tags ---
  readonly property color aur: "#89b4fa"
  readonly property color system: "#f9e2af"
  readonly property color installed: "#a6e3a1"
  readonly property color missing: Commons.Color.urgent
  readonly property color checking: "#f9e2af"
  readonly property color update: "#22c55e"

  // --- 4. Password Complexity Ratings ---
  readonly property color strength5: "#4ade80" // Very Strong
  readonly property color strength4: "#34d399" // Strong
  readonly property color strength3: "#60a5fa" // Fair
  readonly property color strength2: "#fbbf24" // Weak
  readonly property color strength1: Commons.Color.urgent // Very Weak

  function strengthColor(level) {
    switch (level) {
      case 5: return palette.strength5
      case 4: return palette.strength4
      case 3: return palette.strength3
      case 2: return palette.strength2
      case 1:
      default: return palette.strength1
    }
  }

  // --- 5. Feedback & Action Status ---
  readonly property color success: "#10b981"
  readonly property color danger: Commons.Color.urgent
  readonly property color invalidInput: "#fca5a5"

  // --- 6. Item Classification & Badges ---
  readonly property color favorite: "#fbbf24"
  readonly property color typeLogin: "#60a5fa"
  readonly property color organization: "#fbbf24"
  readonly property color folder: "#60a5fa"

  // --- 7. Overlay & Label Contrast Helpers ---
  // Base scrim behind modal cards. Kept here so no component needs a black
  // literal for its own overlay.
  readonly property color scrimBase: "#000000"

  function scrim(alpha) {
    return tint(scrimBase, alpha)
  }

  // Calculates relative luminance to return the high-contrast text pole
  // for any colored background fill (light fill -> dark text, dark fill -> white).
  // Dark text pole for light fills. This is deliberately a fixed ink instead
  // of Commons.Color.menu.background: that token is itself light in light
  // themes, which used to produce light text on light status fills.
  readonly property color ink: "#1a1b26"

  function textOn(fill) {
    if (!fill) return "#ffffff"
    var c = Qt.color(fill)
    var luma = 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b
    return luma > 0.7 ? palette.ink : "#ffffff"
  }

  // Derives a translucent wash from a semantic color role safely.
  function tint(colorVal, alpha) {
    var c = Qt.color(colorVal)
    return Qt.rgba(c.r, c.g, c.b, alpha)
  }

  // Relative luminance with sRGB linearization (WCAG 2.1 definition).
  function _luminance(colorVal) {
    var c = Qt.color(colorVal)
    var channels = [c.r, c.g, c.b]
    for (var i = 0; i < channels.length; i++) {
      channels[i] = channels[i] <= 0.03928 ? channels[i] / 12.92 : Math.pow((channels[i] + 0.055) / 1.055, 2.4)
    }
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
  }

  function _contrast(first, second) {
    var a = _luminance(first)
    var b = _luminance(second)
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
  }

  // Label color for a translucent role wash painted over `base`.
  // Composites the wash first, then returns whichever text pole (dark surface
  // text or white) achieves the higher WCAG contrast ratio. Use this for badges,
  // chips and log rows where the fill is a low-alpha tint rather than the role
  // color itself, because comparing the raw role to the text misjudges the
  // light-theme case (e.g. white text on 15% green over a near-white card).
  function _composite(colorVal, alpha, base) {
    var fill = Qt.color(colorVal)
    var backdrop = Qt.color(base || Commons.Color.popups.background)
    var a = alpha === undefined ? 1 : alpha
    return Qt.rgba(fill.r * a + backdrop.r * (1 - a),
                   fill.g * a + backdrop.g * (1 - a),
                   fill.b * a + backdrop.b * (1 - a),
                   1)
  }

  function _bestPoleBackground(background) {
    return _contrast(palette.ink, background) >= _contrast("#ffffff", background) ? palette.ink : "#ffffff"
  }

  function textOnTint(colorVal, alpha, base) {
    return _bestPoleBackground(_composite(colorVal, alpha, base))
  }

  // Colored label on a tinted chip or badge: keeps the role hue while it clears
  // 4.5:1 against the composited fill, and otherwise falls back to
  // textOnTint so light themes never draw amber or blue status text on a pale wash.
  function labelOnTint(colorVal, alpha, base) {
    var background = _composite(colorVal, alpha, base)
    return _contrast(colorVal, background) >= 4.5 ? colorVal : _bestPoleBackground(background)
  }
}
