import QtQuick
import QtQuick.Controls
import qs.Commons as Commons
import "../components"
import "lib"

// End-to-end theme adaptation regression test suite (Issue #276 / ADR 0026):
// All surfaces, inputs, modals, inspectors, and bars must strictly follow
// the Commons.Color token contracts on both Dark (tokyo-night) and Light
// (catppuccin-latte) presets and re-evaluate live when preset flips.
Item {
  id: testRunner
  width: 800; height: 600
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

  ToastAlert {
    id: toastError
    errorMessage: "theme contrast error"
    foreground: Commons.Color.foreground
    accent: Commons.Color.menu.selectedText
    cardBackground: Commons.Color.popups.background
    borderColor: Commons.Color.popups.border
  }
  function checkCaptionUsesMuted(component, captionText, tag) {
    var caption = Assert.findText(component, captionText)
    Assert.check(caption !== null && Qt.colorEqual(caption.color, component.muted),
          tag + ": secondary caption follows muted — " + captionText.slice(0, 28) + "…")
  }

  // --- WCAG contrast helpers (Spec #291, issue #295) ---
  // Contrast matrix for the elements that previously failed on light themes:
  // the update tag, log-level badges, log filter chips, error count badge,
  // error toast and the copy-confirmation button.
  function runContrastMatrix(tag) {
    var card = Commons.Color.popups.background

    // Update (AUR) tag: 15% update wash over the card.
    Assert.checkContrast(tag, "update tag",
                  StatusPalette.textOnTint(StatusPalette.update, 0.15, card),
                  Assert.compositeOver(StatusPalette.update, 0.15, card))

    // Log-level badges: solid role fill with the palette-chosen pole.
    var levels = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"]
    for (var i = 0; i < levels.length; i++) {
      var levelColor = StatusPalette.levelColor(levels[i])
      Assert.checkContrast(tag, "log badge " + levels[i],
                    StatusPalette.textOnTint(levelColor, 1, card), levelColor)
    }

    // Log filter chips: 20% role wash, label keeps the hue when it can.
    var chips = [
      { name: "filter chip error", role: StatusPalette.error },
      { name: "filter chip warn", role: StatusPalette.warn },
      { name: "filter chip info", role: StatusPalette.info },
      { name: "filter chip debug", role: StatusPalette.debug }
    ]
    for (var c = 0; c < chips.length; c++) {
      Assert.checkContrast(tag, chips[c].name,
                    StatusPalette.labelOnTint(chips[c].role, 0.2, card),
                    Assert.compositeOver(chips[c].role, 0.2, card))
    }

    // Error count badge and error toast (danger fill).
    Assert.checkContrast(tag, "error count badge",
                  StatusPalette.textOnTint(StatusPalette.danger, 1, card),
                  StatusPalette.danger)

    var toastFill = Assert.compositeOver(StatusPalette.danger, 0.95, card)
    var toastLabel = Assert.findText(toastError, "theme contrast error")
    Assert.check(toastLabel !== null, tag + ": error toast label resolves")
    if (toastLabel !== null) {
      Assert.checkContrast(tag, "error toast label", toastLabel.color, toastFill)
    }

    // Copy-confirmation button (solid success fill).
    Assert.checkContrast(tag, "copy confirmation",
                  StatusPalette.textOnTint(StatusPalette.success, 1, card),
                  StatusPalette.success)
  }

  // Verification Matrix across theme presets
  function runMatrix(tag) {
    // 1. Muted token compliance across all components
    Assert.check(Qt.colorEqual(auth.muted, Commons.Color.muted), tag + ": auth.muted === Color.muted")
    Assert.check(Qt.colorEqual(sm.muted, Commons.Color.muted), tag + ": settings.muted === Color.muted")
    Assert.check(Qt.colorEqual(vaultList.muted, Commons.Color.muted), tag + ": vaultList.muted === Color.muted")
    Assert.check(Qt.colorEqual(categoryBar.muted, Commons.Color.muted), tag + ": categoryBar.muted === Color.muted")
    Assert.check(Qt.colorEqual(searchHeader.muted, Commons.Color.muted), tag + ": searchHeader.muted === Color.muted")
    Assert.check(Qt.colorEqual(footerBar.muted, Commons.Color.muted), tag + ": footerBar.muted === Color.muted")
    Assert.check(Qt.colorEqual(itemInspector.muted, Commons.Color.muted), tag + ": itemInspector.muted === Color.muted")
    Assert.check(Qt.colorEqual(emptyInspector.muted, Commons.Color.muted), tag + ": emptyInspector.muted === Color.muted")
    Assert.check(Qt.colorEqual(paletteModal.muted, Commons.Color.muted), tag + ": paletteModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(genModal.muted, Commons.Color.muted), tag + ": genModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(histModal.muted, Commons.Color.muted), tag + ": histModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(sshApprovalModal.muted, Commons.Color.muted), tag + ": sshApprovalModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(sshKeyModal.muted, Commons.Color.muted), tag + ": sshKeyModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(releaseModal.muted, Commons.Color.muted), tag + ": releaseModal.muted === Color.muted")
    Assert.check(Qt.colorEqual(scopeDropdown.muted, Commons.Color.muted), tag + ": scopeDropdown.muted === Color.muted")
    Assert.check(Qt.colorEqual(depView.muted, Commons.Color.muted), tag + ": depView.muted === Color.muted")

    // 2. Modal Card Surfaces & Borders Compliance
    Assert.check(Qt.colorEqual(paletteModal.cardBackground, Commons.Color.popups.background), tag + ": paletteModal cardBackground === Color.popups.background")
    Assert.check(Qt.colorEqual(genModal.cardBackground, Commons.Color.popups.background), tag + ": genModal cardBackground === Color.popups.background")
    Assert.check(Qt.colorEqual(histModal.cardBackground, Commons.Color.popups.background), tag + ": histModal cardBackground === Color.popups.background")
    Assert.check(Qt.colorEqual(sshApprovalModal.cardBackground, Commons.Color.popups.background), tag + ": sshApprovalModal cardBackground === Color.popups.background")
    Assert.check(Qt.colorEqual(sshKeyModal.cardBackground, Commons.Color.popups.background), tag + ": sshKeyModal cardBackground === Color.popups.background")
    Assert.check(Qt.colorEqual(releaseModal.cardBackground, Commons.Color.popups.background), tag + ": releaseModal cardBackground === Color.popups.background")

    Assert.check(Qt.colorEqual(paletteModal.borderColor, Commons.Color.popups.border), tag + ": paletteModal borderColor === Color.popups.border")
    Assert.check(Qt.colorEqual(genModal.borderColor, Commons.Color.popups.border), tag + ": genModal borderColor === Color.popups.border")
    Assert.check(Qt.colorEqual(histModal.borderColor, Commons.Color.popups.border), tag + ": histModal borderColor === Color.popups.border")
    Assert.check(Qt.colorEqual(sshApprovalModal.borderColor, Commons.Color.popups.border), tag + ": sshApprovalModal borderColor === Color.popups.border")
    Assert.check(Qt.colorEqual(sshKeyModal.borderColor, Commons.Color.popups.border), tag + ": sshKeyModal borderColor === Color.popups.border")
    Assert.check(Qt.colorEqual(releaseModal.borderColor, Commons.Color.popups.border), tag + ": releaseModal borderColor === Color.popups.border")

    // 3. TextOnAccent Polarity
    Assert.check(Qt.colorEqual(auth.textOnAccent, "#ffffff"), tag + ": auth.textOnAccent is #ffffff")
    Assert.check(Qt.colorEqual(sm.textOnAccent, "#ffffff"), tag + ": sm.textOnAccent is #ffffff")
    Assert.check(Qt.colorEqual(genModal.textOnAccent, "#ffffff"), tag + ": genModal.textOnAccent is #ffffff")
    Assert.check(Qt.colorEqual(sshApprovalModal.textOnAccent, "#ffffff"), tag + ": sshApprovalModal.textOnAccent is #ffffff")
    Assert.check(Qt.colorEqual(sshKeyModal.textOnAccent, "#ffffff"), tag + ": sshKeyModal.textOnAccent is #ffffff")
    Assert.check(Qt.colorEqual(depView.textOnAccent, "#ffffff"), tag + ": depView.textOnAccent is #ffffff")

    // 4. Captions & Secondary Text following Muted
    checkCaptionUsesMuted(auth, "Official Bitwarden cloud uses standard HTTPS and does not require client certificates.", tag)
    checkCaptionUsesMuted(sm, "(Optional override, e.g. https://identity.bitwarden.com)", tag)
    checkCaptionUsesMuted(itemInspector, "Username", tag)
    checkCaptionUsesMuted(itemInspector, "Password", tag)
    checkCaptionUsesMuted(itemInspector, "Notes", tag)

    // 5. Light theme specific selection and contrast checks
    if (tag === "light") {
      Assert.check(!Qt.colorEqual(Commons.Color.menu.selectedText, "#ffffff"), tag + ": light selectedText must not be white")
      Assert.check(!Qt.colorEqual(vaultList.selectedText, "#ffffff"), tag + ": vaultList selectedText must not be white")
    }

    // 6. Input fills are foreground-alpha blends
    var ph = Assert.findText(auth, "Enter master password...")
    Assert.check(ph !== null && ph.parent !== null && ph.parent.parent !== null
          && Qt.colorEqual(ph.parent.parent.color, Qt.rgba(auth.foreground.r, auth.foreground.g, auth.foreground.b, 0.08)),
          tag + ": auth unlock input fill is foreground@0.08")
    var urlInput = Assert.findText(sm, "https://vault.bitwarden.com")
    Assert.check(urlInput !== null && urlInput.parent !== null
          && Qt.colorEqual(urlInput.parent.color, Qt.rgba(sm.foreground.r, sm.foreground.g, sm.foreground.b, 0.08)),
          tag + ": settings server-url input fill is foreground@0.08")

    // 7. Absence of obsolete property regressions
    Assert.check(sm["mutedForeground"] === undefined, tag + ": settings exposes no mutedForeground")

    // 8. WCAG contrast on colored fills and translucent washes
    runContrastMatrix(tag)
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
      Assert.check(Qt.colorEqual(auth.textOnAccent, Commons.Color.menu.background),
            "auth textOnAccent flips to menu.background on light accent")
      Assert.check(Qt.colorEqual(sm.textOnAccent, Commons.Color.menu.background),
            "settings textOnAccent flips to menu.background on light accent")
      Assert.check(Qt.colorEqual(genModal.textOnAccent, Commons.Color.menu.background),
            "genModal textOnAccent flips to menu.background on light accent")
      Assert.check(Qt.colorEqual(sshApprovalModal.textOnAccent, Commons.Color.menu.background),
            "sshApprovalModal textOnAccent flips to menu.background on light accent")
      Commons.Color.setPreset("light")
      Commons.Color.setPreset("dark")
      Assert.check(Qt.colorEqual(auth.textOnAccent, "#ffffff"),
            "auth textOnAccent flips back to white after preset re-derivation")

      // 3. Explicit muted overrides survive theme switches
      Assert.check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted override wins")
      Assert.check(Qt.colorEqual(smMutedOverride.muted, "#00ff00"), "settings muted override wins")
      Commons.Color.setPreset("light")
      Assert.check(Qt.colorEqual(authMutedOverride.muted, "#123456"), "auth muted override survives preset flip")
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
        Assert.check(Qt.colorEqual(authAccentProbe.textOnAccent, expected),
              "textOnAccent(" + cases[i].hex + ") selects " + (cases[i].dark ? "dark" : "white") + " pole")
      }

      console.log("=== COMPLETED tst_theme_color_adaptation with " + Assert.failures + " Assert.failures ===")
      Qt.exit(Assert.exitCode())
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
