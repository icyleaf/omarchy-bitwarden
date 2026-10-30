import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components"

// End-to-end theme adaptation regression test suite (Issue #276 / ADR 0026):
// All surfaces, inputs, modals, inspectors, and bars must strictly follow
// the Commons.Color token contracts on both Dark (tokyo-night) and Light
// (catppuccin-latte) presets and re-evaluate live when preset flips.
Item {
  id: testRunner
  width: 800; height: 600
  property int failures: 0
  function check(cond, msg) {
    if (!cond) { failures++; console.error("FAIL: " + msg) } else console.log("PASS: " + msg)
  }

  // --- Core Application Views & Modals ---
  AuthView {
    id: auth
    width: 800; height: 600
    authState: ({ status: "unauthenticated", has_session: false })
  }

  SettingsModal {
    id: sm
    width: 800; height: 600
  }

  VaultItemList {
    id: vaultList
    width: 300; height: 400
    items: [
      { id: "item-1", name: "GitHub", username: "octocat", type: 1, favorite: true },
      { id: "item-2", name: "Google", username: "user@gmail.com", type: 1, favorite: false }
    ]
    selectedIndex: 0
  }

  CategoryTabBar {
    id: categoryBar
    width: 800; height: 40
  }

  SearchHeader {
    id: searchHeader
    width: 800; height: 50
  }

  FooterBar {
    id: footerBar
    width: 800; height: 40
  }

  ItemInspector {
    id: itemInspector
    width: 400; height: 600
    item: ({
      id: "item-1",
      name: "GitHub",
      type: 1,
      login: {
        username: "octocat",
        password: "secretpassword123",
        uris: [{ uri: "https://github.com" }]
      },
      notes: "Dev account notes"
    })
  }

  EmptyInspector {
    id: emptyInspector
    width: 400; height: 600
  }

  ActionPaletteModal {
    id: paletteModal
    width: 800; height: 600
    active: false
  }

  PasswordGeneratorModal {
    id: genModal
    width: 800; height: 600
    active: false
  }

  PasswordHistoryModal {
    id: histModal
    width: 800; height: 600
    active: false
  }

  SshApprovalModal {
    id: sshApprovalModal
    width: 800; height: 600
    active: false
  }

  SshKeyModal {
    id: sshKeyModal
    width: 800; height: 600
    active: false
  }

  ReleaseNotesModal {
    id: releaseModal
    width: 800; height: 600
    active: false
  }

  ScopeDropdown {
    id: scopeDropdown
    title: "Scope"
  }

  DependencyCheckView {
    id: depView
    width: 800; height: 600
  }

  // --- Override Probes ---
  AuthView { id: authMutedOverride; muted: "#123456" }
  AuthView { id: authAccentProbe; accent: "#7aa2f7" }
  SettingsModal { id: smMutedOverride; muted: "#00ff00" }

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

  function checkCaptionUsesMuted(component, captionText, tag) {
    var caption = findText(component, captionText)
    check(caption !== null && Qt.colorEqual(caption.color, component.muted),
          tag + ": secondary caption follows muted — " + captionText.slice(0, 28) + "…")
  }

  // Verification Matrix across theme presets
  function runMatrix(tag) {
    // 1. Muted token compliance across all components
    check(Qt.colorEqual(auth.muted, Commons.Color.muted), tag + ": auth.muted === Color.muted")
    check(Qt.colorEqual(sm.muted, Commons.Color.muted), tag + ": settings.muted === Color.muted")
    check(Qt.colorEqual(vaultList.muted, Commons.Color.muted), tag + ": vaultList.muted === Color.muted")
    check(Qt.colorEqual(categoryBar.muted, Commons.Color.muted), tag + ": categoryBar.muted === Color.muted")
    check(Qt.colorEqual(searchHeader.muted, Commons.Color.muted), tag + ": searchHeader.muted === Color.muted")
    check(Qt.colorEqual(footerBar.muted, Commons.Color.muted), tag + ": footerBar.muted === Color.muted")
    check(Qt.colorEqual(itemInspector.muted, Commons.Color.muted), tag + ": itemInspector.muted === Color.muted")
    check(Qt.colorEqual(emptyInspector.muted, Commons.Color.muted), tag + ": emptyInspector.muted === Color.muted")
    check(Qt.colorEqual(paletteModal.muted, Commons.Color.muted), tag + ": paletteModal.muted === Color.muted")
    check(Qt.colorEqual(genModal.muted, Commons.Color.muted), tag + ": genModal.muted === Color.muted")
    check(Qt.colorEqual(histModal.muted, Commons.Color.muted), tag + ": histModal.muted === Color.muted")
    check(Qt.colorEqual(sshApprovalModal.muted, Commons.Color.muted), tag + ": sshApprovalModal.muted === Color.muted")
    check(Qt.colorEqual(sshKeyModal.muted, Commons.Color.muted), tag + ": sshKeyModal.muted === Color.muted")
    check(Qt.colorEqual(releaseModal.muted, Commons.Color.muted), tag + ": releaseModal.muted === Color.muted")
    check(Qt.colorEqual(scopeDropdown.muted, Commons.Color.muted), tag + ": scopeDropdown.muted === Color.muted")
    check(Qt.colorEqual(depView.muted, Commons.Color.muted), tag + ": depView.muted === Color.muted")

    // 2. Modal Card Surfaces & Borders Compliance
    check(Qt.colorEqual(paletteModal.cardBackground, Commons.Color.popups.background), tag + ": paletteModal cardBackground === Color.popups.background")
    check(Qt.colorEqual(genModal.cardBackground, Commons.Color.popups.background), tag + ": genModal cardBackground === Color.popups.background")
    check(Qt.colorEqual(histModal.cardBackground, Commons.Color.popups.background), tag + ": histModal cardBackground === Color.popups.background")
    check(Qt.colorEqual(sshApprovalModal.cardBackground, Commons.Color.popups.background), tag + ": sshApprovalModal cardBackground === Color.popups.background")
    check(Qt.colorEqual(sshKeyModal.cardBackground, Commons.Color.popups.background), tag + ": sshKeyModal cardBackground === Color.popups.background")
    check(Qt.colorEqual(releaseModal.cardBackground, Commons.Color.popups.background), tag + ": releaseModal cardBackground === Color.popups.background")

    check(Qt.colorEqual(paletteModal.borderColor, Commons.Color.popups.border), tag + ": paletteModal borderColor === Color.popups.border")
    check(Qt.colorEqual(genModal.borderColor, Commons.Color.popups.border), tag + ": genModal borderColor === Color.popups.border")
    check(Qt.colorEqual(histModal.borderColor, Commons.Color.popups.border), tag + ": histModal borderColor === Color.popups.border")
    check(Qt.colorEqual(sshApprovalModal.borderColor, Commons.Color.popups.border), tag + ": sshApprovalModal borderColor === Color.popups.border")
    check(Qt.colorEqual(sshKeyModal.borderColor, Commons.Color.popups.border), tag + ": sshKeyModal borderColor === Color.popups.border")
    check(Qt.colorEqual(releaseModal.borderColor, Commons.Color.popups.border), tag + ": releaseModal borderColor === Color.popups.border")

    // 3. TextOnAccent Polarity
    check(Qt.colorEqual(auth.textOnAccent, "#ffffff"), tag + ": auth.textOnAccent is #ffffff")
    check(Qt.colorEqual(sm.textOnAccent, "#ffffff"), tag + ": sm.textOnAccent is #ffffff")
    check(Qt.colorEqual(genModal.textOnAccent, "#ffffff"), tag + ": genModal.textOnAccent is #ffffff")
    check(Qt.colorEqual(sshApprovalModal.textOnAccent, "#ffffff"), tag + ": sshApprovalModal.textOnAccent is #ffffff")
    check(Qt.colorEqual(sshKeyModal.textOnAccent, "#ffffff"), tag + ": sshKeyModal.textOnAccent is #ffffff")
    check(Qt.colorEqual(depView.textOnAccent, "#ffffff"), tag + ": depView.textOnAccent is #ffffff")

    // 4. Captions & Secondary Text following Muted
    checkCaptionUsesMuted(auth, "Official Bitwarden cloud uses standard HTTPS and does not require client certificates.", tag)
    checkCaptionUsesMuted(sm, "(Optional override, e.g. https://identity.bitwarden.com)", tag)
    checkCaptionUsesMuted(itemInspector, "Username", tag)
    checkCaptionUsesMuted(itemInspector, "Password", tag)
    checkCaptionUsesMuted(itemInspector, "Notes", tag)

    // 5. Light theme specific selection and contrast checks
    if (tag === "light") {
      check(!Qt.colorEqual(Commons.Color.menu.selectedText, "#ffffff"), tag + ": light selectedText must not be white")
      check(!Qt.colorEqual(vaultList.selectedText, "#ffffff"), tag + ": vaultList selectedText must not be white")
    }

    // 6. Input fills are foreground-alpha blends
    var ph = findText(auth, "Enter master password...")
    check(ph !== null && ph.parent !== null && ph.parent.parent !== null
          && Qt.colorEqual(ph.parent.parent.color, Qt.rgba(auth.foreground.r, auth.foreground.g, auth.foreground.b, 0.08)),
          tag + ": auth unlock input fill is foreground@0.08")
    var urlInput = findText(sm, "https://vault.bitwarden.com")
    check(urlInput !== null && urlInput.parent !== null
          && Qt.colorEqual(urlInput.parent.color, Qt.rgba(sm.foreground.r, sm.foreground.g, sm.foreground.b, 0.08)),
          tag + ": settings server-url input fill is foreground@0.08")

    // 7. Absence of obsolete property regressions
    check(sm["mutedForeground"] === undefined, tag + ": settings exposes no mutedForeground")
  }

  Timer {
    id: suite
    interval: 400
    onTriggered: {
      // 1. Dark -> Light -> Dark live preset flips
      Commons.Color.setPreset("dark")
      runMatrix("dark")
      Commons.Color.setPreset("light")
      runMatrix("light")
      Commons.Color.setPreset("dark")
      runMatrix("dark-again")

      // 2. Dynamic textOnAccent flipping on light pastel accent
      Commons.Color.accent = "#ffd580"
      check(Qt.colorEqual(auth.textOnAccent, Commons.Color.menu.background),
            "auth textOnAccent flips to menu.background on light accent")
      check(Qt.colorEqual(sm.textOnAccent, Commons.Color.menu.background),
            "settings textOnAccent flips to menu.background on light accent")
      check(Qt.colorEqual(genModal.textOnAccent, Commons.Color.menu.background),
            "genModal textOnAccent flips to menu.background on light accent")
      check(Qt.colorEqual(sshApprovalModal.textOnAccent, Commons.Color.menu.background),
            "sshApprovalModal textOnAccent flips to menu.background on light accent")
      Commons.Color.setPreset("light")
      Commons.Color.setPreset("dark")
      check(Qt.colorEqual(auth.textOnAccent, "#ffffff"),
            "auth textOnAccent flips back to white after preset re-derivation")

      // 3. Explicit muted overrides survive theme switches
      check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted override wins")
      check(Qt.colorEqual(smMutedOverride.muted, "#00ff00"), "settings muted override wins")
      Commons.Color.setPreset("light")
      check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted override survives preset flip")
      Commons.Color.setPreset("dark")

      // 4. Accent luminance boundary table
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
              "textOnAccent(" + cases[i].hex + ") selects " + (cases[i].dark ? "dark" : "white") + " pole")
      }

      console.log("=== COMPLETED tst_theme_color_adaptation with " + failures + " failures ===")
      Qt.exit(failures === 0 ? 0 : 1)
    }
  }

  Component.onCompleted: {
    sm.activeTab = "logs"
    sm.logBuffer = [
      { level: "INFO", source: "theme-test", message: "theme-info-row", timestamp: "2026-10-28T10:00:00Z" }
    ]
    suite.start()
  }
}
