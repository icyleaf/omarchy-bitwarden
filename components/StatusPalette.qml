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

  // --- 7. Label Contrast & Tint Helpers ---
  // Calculates relative luminance to return the high-contrast text pole
  // for any colored background fill (light fill -> dark text, dark fill -> white).
  function textOn(fill) {
    if (!fill) return "#ffffff"
    var c = Qt.color(fill)
    var luma = 0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b
    return luma > 0.7 ? Commons.Color.menu.background : "#ffffff"
  }

  // Derives a translucent wash from a semantic color role safely.
  function tint(colorVal, alpha) {
    var c = Qt.color(colorVal)
    return Qt.rgba(c.r, c.g, c.b, alpha)
  }
}
