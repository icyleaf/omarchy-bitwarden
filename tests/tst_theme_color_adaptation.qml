import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components"

// Theme-adaptation suite for slice 1 of the dynamic-theme epic (#266):
// AuthView and SettingsModal must follow the Commons.Color stub on both the
// dark (tokyo-night) and light (catppuccin-latte) presets and re-evaluate
// live when the preset flips — the headless model of `omarchy theme set`.
// Assertions target binding outputs on real elements (findText walks the
// children and matches a Text/TextInput by content), never the tree shape.
Item {
  id: testRunner
  width: 800; height: 600
  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) } else console.log("PASS: " + msg)
  }

  AuthView {
    id: auth
    width: 800; height: 600
    authState: ({ status: "unauthenticated", has_session: false })
  }

  SettingsModal {
    id: sm
    width: 800; height: 600
  }

  // Guards for the root wiring contract (muted: root.muted) and for
  // textOnAccent tracking the component's own accent, not the singleton.
  AuthView { id: authMutedOverride; muted: "#123456" }
  AuthView { id: authAccentProbe; accent: "#7aa2f7" }
  SettingsModal { id: smMutedOverride; muted: "#00ff00" }

  function findText(item, text) {
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].text === text) return kids[i]
      var found = findText(kids[i], text)
      if (found) return found
    }
    return null
  }

  function checkCaptionUsesMuted(component, captionText, tag) {
    var caption = findText(component, captionText)
    check(caption !== null && Qt.colorEqual(caption.color, component.muted),
          tag + ": secondary caption follows muted (M1) — " + captionText.slice(0, 28) + "…")
  }

  // The full mapping matrix, re-run for every preset (u1–u5, u10).
  function runMatrix(tag) {
    // u1 — muted resolves to the stub's Color.muted in both components
    // (regression for the old undefined authRoot.muted reads).
    check(Qt.colorEqual(auth.muted, Commons.Color.muted), tag + ": auth.muted === Color.muted (u1)")
    check(Qt.colorEqual(sm.muted, Commons.Color.muted), tag + ": settings.muted === Color.muted (u1)")

    // u2 — secondary/caption text is muted, not Qt.darker(foreground).
    checkCaptionUsesMuted(auth, "Official Bitwarden cloud uses standard HTTPS and does not require client certificates.", tag)
    checkCaptionUsesMuted(sm, "(Optional override, e.g. https://identity.bitwarden.com)", tag)

    // u3 — input fills are foreground-alpha blends (M2).
    var ph = findText(auth, "Enter master password...")
    check(ph !== null && ph.parent !== null && ph.parent.parent !== null
          && Qt.colorEqual(ph.parent.parent.color, Qt.rgba(auth.foreground.r, auth.foreground.g, auth.foreground.b, 0.08)),
          tag + ": auth unlock input fill is foreground@0.08 (M2)")
    var urlInput = findText(sm, "https://vault.bitwarden.com")
    check(urlInput !== null && urlInput.parent !== null
          && Qt.colorEqual(urlInput.parent.color, Qt.rgba(sm.foreground.r, sm.foreground.g, sm.foreground.b, 0.08)),
          tag + ": settings server-url input fill is foreground@0.08 (M2)")

    // u4 — card fills are foreground-alpha (M3); disabled submit wash (M4).
    var boxTitle = findText(auth, "SERVER & mTLS CLIENT CERTIFICATE")
    check(boxTitle !== null && boxTitle.parent !== null && boxTitle.parent.parent !== null
          && Qt.colorEqual(boxTitle.parent.parent.color, Qt.rgba(auth.foreground.r, auth.foreground.g, auth.foreground.b, 0.10)),
          tag + ": auth server-config card fill is foreground@0.10 (M3)")
    var chkUp = findText(sm, "Check Update")
    check(chkUp !== null && chkUp.parent !== null
          && Qt.colorEqual(chkUp.parent.color, Qt.rgba(sm.foreground.r, sm.foreground.g, sm.foreground.b, 0.06)),
          tag + ": settings check-update button fill is foreground@0.06 (M3)")
    auth.isBusy = true
    check(Qt.colorEqual(auth.submitButtonComponent.color, Qt.rgba(auth.foreground.r, auth.foreground.g, auth.foreground.b, 0.08)),
          tag + ": disabled submit fill is foreground@0.08 (M4)")
    auth.isBusy = false
    var logRow = findText(sm, "theme-info-row")
    check(logRow !== null && logRow.parent !== null && logRow.parent.parent !== null
          && Qt.colorEqual(logRow.parent.parent.color, Qt.rgba(sm.foreground.r, sm.foreground.g, sm.foreground.b, 0.03)),
          tag + ": log-row neutral wash is foreground@0.03 (M4)")

    // u5 — accent-button labels and checkmark glyphs use textOnAccent (M5/M6),
    // which stays white on every shipped preset accent (dark parity) and never
    // equals the accent fill itself (the M5 amendment).
    check(Qt.colorEqual(auth.textOnAccent, "#ffffff"), tag + ": auth.textOnAccent is #ffffff (u5 parity)")
    check(Qt.colorEqual(sm.textOnAccent, "#ffffff"), tag + ": settings.textOnAccent is #ffffff (u5 parity)")
    check(!Qt.colorEqual(auth.textOnAccent, auth.accent), tag + ": auth.textOnAccent differs from accent fill (u5)")
    var unlockLabel = findText(auth, "Unlock Vault")
    check(unlockLabel !== null && Qt.colorEqual(unlockLabel.color, auth.textOnAccent),
          tag + ": unlock button label uses textOnAccent (M5)")
    var saveLabel = findText(sm, "Save Settings")
    check(saveLabel !== null && Qt.colorEqual(saveLabel.color, sm.textOnAccent),
          tag + ": save button label uses textOnAccent (M5)")
    var glyph = findText(auth, "\uf00c")
    check(glyph !== null && Qt.colorEqual(glyph.color, auth.textOnAccent),
          tag + ": auth checkmark glyph uses textOnAccent (M6)")
    var smGlyph = findText(sm, "\uf00c")
    check(smGlyph !== null && Qt.colorEqual(smGlyph.color, sm.textOnAccent),
          tag + ": settings checkmark glyph uses textOnAccent (M6)")

    // u10 — the mutedForeground property is gone (rename regression);
    // the caption following `muted` is already asserted in u2.
    check(sm["mutedForeground"] === undefined, tag + ": settings exposes no mutedForeground (u10)")
  }

  Timer {
    id: suite
    interval: 400
    onTriggered: {
      // u9 — full matrix on dark, light, then dark again (live theme switch).
      Commons.Color.setPreset("dark")
      runMatrix("dark")
      Commons.Color.setPreset("light")
      runMatrix("light")
      Commons.Color.setPreset("dark")
      runMatrix("dark-again")

      // u6 — flipping the stub accent to a light color flips textOnAccent to
      // the menu background pole; re-deriving the preset flips it back.
      Commons.Color.accent = "#ffd580"
      check(Qt.colorEqual(auth.textOnAccent, Commons.Color.menu.background),
            "textOnAccent flips to menu.background on a light accent (u6)")
      check(Qt.colorEqual(sm.textOnAccent, Commons.Color.menu.background),
            "settings textOnAccent flips on a light accent (u6)")
      Commons.Color.setPreset("light")
      Commons.Color.setPreset("dark")
      check(Qt.colorEqual(auth.textOnAccent, "#ffffff"),
            "textOnAccent flips back after preset re-derivation (u6)")

      // u7 — explicit muted overrides win over the Color.muted default
      // (guards the root's muted: root.muted wiring contract).
      check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted: override wins (u7)")
      check(Qt.colorEqual(smMutedOverride.muted, "#00ff00"), "settings muted: override wins (u7)")
      Commons.Color.setPreset("light")
      check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted: override survives a preset flip (u7)")
      Commons.Color.setPreset("dark")

      // u8 + luma boundary cases, data-driven on a component whose accent is
      // set explicitly (textOnAccent must track the component accent, not the
      // singleton). Every shipped theme accent stays white; only a genuinely
      // light accent picks the dark pole.
      var cases = [
        { hex: "#7aa2f7", dark: false },  // tokyo-night
        { hex: "#e68e0d", dark: false },  // custom orange
        { hex: "#1e66f5", dark: false },  // catppuccin-latte
        { hex: "#205ea6", dark: false },  // flexoki-light
        { hex: "#6e6e6e", dark: false },  // white theme
        { hex: "#ffd580", dark: true }    // light pastel accent
      ]
      for (var i = 0; i < cases.length; i++) {
        authAccentProbe.accent = cases[i].hex
        var expected = cases[i].dark ? Commons.Color.menu.background : "#ffffff"
        check(Qt.colorEqual(authAccentProbe.textOnAccent, expected),
              "textOnAccent(" + cases[i].hex + ") picks the " + (cases[i].dark ? "dark" : "white") + " pole (u8)")
      }

      Qt.exit(failures === 0 ? 0 : 1)
    }
  }

  Component.onCompleted: {
    // Feed the logs tab before the first layout pass so the log-row wash
    // (M4, foreground@0.03) has a delegate to assert against.
    sm.activeTab = "logs"
    sm.logBuffer = [
      { level: "INFO", source: "theme-test", message: "theme-info-row", timestamp: "2026-10-28T10:00:00Z" }
    ]
    suite.start()
  }
}
