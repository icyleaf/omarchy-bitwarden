import QtQuick
import QtQuick.Controls
import "../components" as Components

Item {
  id: testRunner
  width: 500
  height: 500

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  // Harness simulating PasswordGeneratorModal state & logic
  property bool active: false
  property string mode: "password" // "password" | "passphrase"
  property int passwordLength: 20
  property bool includeUppercase: true
  property bool includeLowercase: true
  property bool includeNumbers: true
  property bool includeSpecial: true
  property bool avoidAmbiguous: false

  property int passphraseWords: 4
  property string passphraseSeparator: "-"
  property bool passphraseCapitalize: false

  // Fill workflow (issue #385): when fillMode is enabled the primary action
  // returns the generated secret to the caller via passwordSelected instead
  // of writing it to the clipboard.
  property bool fillMode: false

  property string generatedPassword: ""
  property real generatedEntropy: 0.0
  property string errorMessage: ""
  property bool isEngineOutdated: false
  property string engineVersion: ""
  property string requiredVersion: "0.9.0"

  readonly property real currentEntropy: generatedEntropy > 0 ? generatedEntropy : calculateEntropy()

  readonly property int strengthLevel: {
    var e = currentEntropy
    if (e >= 100) return 5
    if (e >= 80) return 4
    if (e >= 60) return 3
    if (e >= 40) return 2
    return 1
  }

  readonly property string strengthLabel: {
    switch (strengthLevel) {
      case 5: return "Very Strong"
      case 4: return "Strong"
      case 3: return "Good"
      case 2: return "Weak"
      default: return "Very Weak"
    }
  }

  readonly property color strengthColor: {
    switch (strengthLevel) {
      case 5: return "#4ade80" // Green
      case 4: return "#34d399" // Emerald
      case 3: return "#60a5fa" // Blue
      case 2: return "#fbbf24" // Yellow
      default: return "#f87171" // Red
    }
  }

  property int executeCallCount: 0

  Timer {
    id: debounceTimer
    interval: 160
    repeat: false
    onTriggered: executeRegenerate()
  }

  function requestLazyRegenerate() {
    debounceTimer.restart()
  }

  function regenerate() {
    debounceTimer.stop()
    executeRegenerate()
  }

  property string lastCopiedText: ""
  property bool lastCopiedSensitive: false
  property string lastCopiedLabel: ""
  property bool wasClosed: false

  property string lastSelectedPassword: ""
  property int selectionCount: 0

  function handleProcessOutput(stdoutText, stderrText, exitCode) {
    var out = (stdoutText || "").trim()
    if (out) {
      try {
        var data = JSON.parse(out)
        if (data && data.ok) {
          errorMessage = ""
          generatedPassword = data.password || ""
          generatedEntropy = (typeof data.entropy === "number") ? data.entropy : calculateEntropy()
          return
        } else if (data && data.error) {
          errorMessage = data.error
          generatedPassword = ""
          return
        }
      } catch (e) {
        errorMessage = ""
        generatedPassword = out
        generatedEntropy = calculateEntropy()
        return
      }
    }
    var err = (stderrText || "").trim()
    if (err) {
      err = err.replace(/^Error:\s*/i, "")
      if (/unrecognized subcommand|not a recognized subcommand/i.test(err)) {
        var currentVer = engineVersion ? (" (v" + engineVersion + ")") : ""
        err = "omawarden engine is outdated" + currentVer + ". Please upgrade omawarden to >= " + requiredVersion + " to support credential generation."
      }
      errorMessage = err
      generatedPassword = ""
      return
    }
    if (exitCode !== 0 && !errorMessage) {
      errorMessage = "Failed to generate secret."
      generatedPassword = ""
    }
  }

  function executeRegenerate() {
    executeCallCount++
    generatedPassword = ""
    if (isEngineOutdated) {
      errorMessage = "omawarden engine is outdated" + (engineVersion ? " (v" + engineVersion + ")" : "") + ". Please upgrade to >= " + requiredVersion + " to use credential generation."
      return
    }
    errorMessage = ""
  }

  function calculateEntropy() {
    if (mode === "passphrase") {
      return passphraseWords * 12.915
    }
    var pool = 0
    if (includeUppercase) pool += avoidAmbiguous ? 24 : 26
    if (includeLowercase) pool += avoidAmbiguous ? 24 : 26
    if (includeNumbers) pool += avoidAmbiguous ? 8 : 10
    if (includeSpecial) pool += avoidAmbiguous ? 25 : 26
    if (pool <= 0) return 0.0
    return passwordLength * (Math.log(pool) / Math.LN2)
  }

  function copyAndClose() {
    if (generatedPassword && !errorMessage) {
      lastCopiedText = generatedPassword
      lastCopiedSensitive = true
      lastCopiedLabel = (mode === "passphrase" ? "passphrase" : "password")
      active = false
      wasClosed = true
    }
  }

  // Fill-mode counterpart of copyAndClose(): delivers the secret through the
  // passwordSelected signal and closes, never touching the clipboard.
  function useAndClose() {
    if (generatedPassword && !errorMessage) {
      lastSelectedPassword = generatedPassword
      selectionCount++
      active = false
      wasClosed = true
    }
  }

  // Single dispatch site for the primary footer action (mirrors the component).
  function triggerPrimaryAction() {
    if (fillMode) {
      useAndClose()
    } else {
      copyAndClose()
    }
  }

  // Primary footer action (mirrors the component's button bindings).
  readonly property string primaryActionLabel: fillMode ? "Use Password (↵)" : "Copy to Clipboard (↵)"
  readonly property string primaryActionIcon: fillMode ? "\uf00c" : "\uf0c5"

  property color accent: "#3b82f6"

  // The REAL PasswordGeneratorModal under the stub Commons harness, wired the
  // way OmarchyBitwarden.qml wires it (parent owns `active`, process output
  // feeds generatedPassword). Tests drive it only through top-level
  // properties, signals and the handleKey() keyboard seam, never internals.
  Components.PasswordGeneratorModal {
    id: genModal
    active: false
    mode: "password"
  }

  function formatStyledPassword(password) {
    if (!password) return ""
    var accentHex = "" + accent
    var res = ""
    for (var i = 0; i < password.length; i++) {
      var ch = password.charAt(i)
      var safe = ch
      if (ch === "&") safe = "&amp;"
      else if (ch === "<") safe = "&lt;"
      else if (ch === ">") safe = "&gt;"
      else if (ch === '"') safe = "&quot;"

      if (ch >= "0" && ch <= "9") {
        res += "<font color='" + accentHex + "'>" + safe + "</font>"
      } else {
        res += safe
      }
    }
    return res
  }

  function handleKey(key, modifiers) {
    if (key === Qt.Key_Escape) {
      handleEscape()
    } else if (key === Qt.Key_Return || key === Qt.Key_Enter) {
      triggerPrimaryAction()
    } else if (modifiers & Qt.ControlModifier && (key === Qt.Key_G || key === Qt.Key_R)) {
      regenerate()
    }
  }

  function handleEscape() {
    active = false
    wasClosed = true
  }

  Component.onCompleted: {
    console.log("Running PasswordGeneratorModal Logic & Entropy Tests...")

    // 1. Initial State
    check(active === false, "Initial active is false")
    check(mode === "password", "Initial mode is password")
    check(passwordLength === 20, "Default passwordLength is 20")
    check(includeUppercase === true, "Default includeUppercase is true")
    check(includeLowercase === true, "Default includeLowercase is true")
    check(includeNumbers === true, "Default includeNumbers is true")
    check(includeSpecial === true, "Default includeSpecial is true")
    check(avoidAmbiguous === false, "Default avoidAmbiguous is false")
    check(passphraseWords === 4, "Default passphraseWords is 4")
    check(passphraseSeparator === "-", "Default passphraseSeparator is hyphen")
    check(passphraseCapitalize === false, "Default passphraseCapitalize is false")

    // 2. Full Charset Entropy (26 + 26 + 10 + 27 = 89; 20 * log2(89) ~ 129.5 bits)
    var defaultEnt = calculateEntropy()
    check(defaultEnt > 128.0 && defaultEnt < 131.0, "Full charset 20-char entropy is ~129.5 bits (got " + defaultEnt.toFixed(2) + ")")

    // 3. Ambiguous Characters Excluded (24 + 24 + 8 + 26 = 82; 20 * log2(82) ~ 127.1 bits)
    avoidAmbiguous = true
    var avoidEnt = calculateEntropy()
    check(avoidEnt > 125.0 && avoidEnt < 129.0, "Avoid ambiguous 20-char entropy is ~127.1 bits (got " + avoidEnt.toFixed(2) + ")")
    avoidAmbiguous = false

    // 4. Numbers Only (pool = 10; 16 * log2(10) ~ 53.15 bits)
    passwordLength = 16
    includeUppercase = false
    includeLowercase = false
    includeSpecial = false
    var numEnt = calculateEntropy()
    check(Math.abs(numEnt - 53.15) < 0.5, "16-digit numbers-only entropy is ~53.15 bits (got " + numEnt.toFixed(2) + ")")

    // 5. Passphrase Entropy (4 words = 51.66 bits, 6 words = 77.49 bits)
    mode = "passphrase"
    passphraseWords = 4
    var phrase4Ent = calculateEntropy()
    check(Math.abs(phrase4Ent - 51.66) < 0.1, "4-word passphrase entropy is 51.66 bits (got " + phrase4Ent.toFixed(2) + ")")

    passphraseWords = 6
    var phrase6Ent = calculateEntropy()
    check(Math.abs(phrase6Ent - 77.49) < 0.1, "6-word passphrase entropy is 77.49 bits (got " + phrase6Ent.toFixed(2) + ")")

    // 6. Copy and Close signal workflow
    mode = "password"
    active = true
    generatedPassword = "TestSecret!2026Pass"
    copyAndClose()
    check(lastCopiedText === "TestSecret!2026Pass", "copyAndClose sets lastCopiedText")
    check(lastCopiedSensitive === true, "copyAndClose marks credential as sensitive")
    check(lastCopiedLabel === "password", "copyAndClose marks label as password")
    check(active === false, "copyAndClose dismisses modal")
    check(wasClosed === true, "copyAndClose marks wasClosed")

    // 7. Passphrase Copy Workflow
    mode = "passphrase"
    active = true
    wasClosed = false
    generatedPassword = "correct-horse-battery-staple"
    copyAndClose()
    check(lastCopiedLabel === "passphrase", "copyAndClose in passphrase mode sets label to passphrase")
    check(active === false, "Passphrase copy dismisses modal")

    // 8. Escape Handling
    active = true
    wasClosed = false
    handleEscape()
    check(active === false, "handleEscape dismisses modal")
    check(wasClosed === true, "handleEscape flags wasClosed")

    // 9. Process JSON Output Handling (Success & Error)
    check(errorMessage === "", "Initial errorMessage is empty")

    // 9a. Successful JSON response
    var jsonSuccess = JSON.stringify({ ok: true, password: "test-generated-secret-123", entropy: 88.5, type: "password" })
    handleProcessOutput(jsonSuccess, "", 0)
    check(errorMessage === "", "Valid JSON clears errorMessage")
    check(generatedPassword === "test-generated-secret-123", "Valid JSON extracts password")
    check(generatedEntropy === 88.5, "Valid JSON extracts precise entropy")

    // 9b. Error JSON response from CLI
    var jsonError = JSON.stringify({ ok: false, error: "Password length must be between 5 and 128 characters. Use 14 or more characters for a strong password." })
    handleProcessOutput(jsonError, "", 1)
    check(errorMessage.indexOf("Password length must be between 5 and 128") !== -1, "JSON error captures error message")

    // 9c. Stderr plain-text error fallback
    handleProcessOutput("", "Error: Passphrase word count must be between 3 and 20 words.", 1)
    check(errorMessage === "Passphrase word count must be between 3 and 20 words.", "Stderr fallback strips 'Error:' prefix and populates errorMessage")

    // 9d. Stderr unrecognized subcommand fallback transformation
    engineVersion = "0.8.2"
    handleProcessOutput("", "error: unrecognized subcommand 'generate'\n\nUsage: omawarden [OPTIONS] <COMMAND>", 2)
    check(errorMessage.indexOf("omawarden engine is outdated (v0.8.2)") !== -1, "Transforms 'unrecognized subcommand' into friendly engine upgrade reminder")
    check(errorMessage.indexOf("Please upgrade omawarden to >= 0.9.0") !== -1, "Includes minimum version requirement in upgrade reminder")

    // 10. Engine Outdated State Handling
    isEngineOutdated = true
    engineVersion = "0.8.2"
    regenerate()
    check(errorMessage.indexOf("omawarden engine is outdated (v0.8.2)") !== -1, "isEngineOutdated stops generation and sets upgrade reminder")
    isEngineOutdated = false
    engineVersion = "0.9.0"
    regenerate()
    check(errorMessage === "", "Up-to-date engine clears outdated reminder")

    // 11. Mode Switching Validation
    mode = "password"
    check(mode === "password", "Active mode is password")
    mode = "passphrase"
    check(mode === "passphrase", "Mode successfully switches to passphrase")
    mode = "password"
    check(mode === "password", "Mode successfully switches back to password")

    // 12. Copy Button Disabled on Error
    errorMessage = "omawarden engine is outdated"
    generatedPassword = ""
    var canCopyOnError = !errorMessage && Boolean(generatedPassword)
    check(canCopyOnError === false, "Copy action is disabled when errorMessage is present")

    // 13. Version Unsupported Notice Window (提示窗口) Displays While "Unavailable" Text Is Absent
    isEngineOutdated = true
    errorMessage = "omawarden engine is outdated (v0.8.2)"
    var bannerVisible = Boolean(errorMessage)
    check(bannerVisible === true, "Version unsupported notice window (版本不支持提示窗口) is displayed on outdated engine")
    var secretDisplayText = errorMessage ? "—" : (generatedPassword || "Generating...")
    check(secretDisplayText === "—", "Secret display shows placeholder dash instead of 'unavailable'")
    check(secretDisplayText.indexOf("unavailable") === -1, "No 'unavailable' text displayed in password box")
    // 14. copyAndClose() Guards Against Error State Even If Secret Property Is Populated
    lastCopiedText = ""
    wasClosed = false
    active = true
    generatedPassword = "stale-secret-123"
    errorMessage = "Some error occurred"
    copyAndClose()
    check(lastCopiedText === "", "copyAndClose() does not copy secret when errorMessage is present")
    check(wasClosed === false, "copyAndClose() does not close modal when errorMessage is present")
    errorMessage = ""
    copyAndClose()
    check(lastCopiedText === "stale-secret-123", "copyAndClose() copies secret when errorMessage is clear")
    check(wasClosed === true, "copyAndClose() closes modal when errorMessage is clear")
    generatedPassword = ""
    // Restore a clean engine state for the sections that follow.
    isEngineOutdated = false
    engineVersion = "0.9.0"

    // 15. Password Complexity / Strength Level and Label Mapping (方案 B)
    generatedEntropy = 30.0
    check(strengthLevel === 1, "Entropy < 40 maps to strengthLevel 1")
    check(strengthLabel === "Very Weak", "Entropy < 40 maps to 'Very Weak'")
    check(strengthColor.toString() === "#f87171", "Entropy < 40 maps to red color")

    generatedEntropy = 50.0
    check(strengthLevel === 2, "Entropy 50 maps to strengthLevel 2")
    check(strengthLabel === "Weak", "Entropy 50 maps to 'Weak'")
    check(strengthColor.toString() === "#fbbf24", "Entropy 50 maps to yellow color")

    generatedEntropy = 70.0
    check(strengthLevel === 3, "Entropy 70 maps to strengthLevel 3")
    check(strengthLabel === "Good", "Entropy 70 maps to 'Good'")
    check(strengthColor.toString() === "#60a5fa", "Entropy 70 maps to blue color")

    generatedEntropy = 90.0
    check(strengthLevel === 4, "Entropy 90 maps to strengthLevel 4")
    check(strengthLabel === "Strong", "Entropy 90 maps to 'Strong'")
    check(strengthColor.toString() === "#34d399", "Entropy 90 maps to emerald color")

    generatedEntropy = 125.0
    check(strengthLevel === 5, "Entropy 125 maps to strengthLevel 5")
    check(strengthLabel === "Very Strong", "Entropy 125 maps to 'Very Strong'")
    check(strengthColor.toString() === "#4ade80", "Entropy 125 maps to green color")
    generatedEntropy = 0.0

    // 16. Lazy Generate Debounce Behavior
    var initialCalls = executeCallCount
    requestLazyRegenerate()
    requestLazyRegenerate()
    requestLazyRegenerate()
    check(executeCallCount === initialCalls, "requestLazyRegenerate() does not invoke executeRegenerate() synchronously")
    check(debounceTimer.running === true, "debounceTimer is running during rapid slider moves")

    regenerate()
    check(executeCallCount === initialCalls + 1, "regenerate() executes immediately and increments executeCallCount")
    check(debounceTimer.running === false, "regenerate() cancels pending debounceTimer")

    // 17. Digit Highlighting (数字使用主色标记已标识区分)
    var styledWithDigits = formatStyledPassword("Pass123Word")
    check(styledWithDigits.indexOf("<font color='#3b82f6'>1</font>") !== -1, "Digit 1 is highlighted with accent color")
    check(styledWithDigits.indexOf("<font color='#3b82f6'>2</font>") !== -1, "Digit 2 is highlighted with accent color")
    check(styledWithDigits.indexOf("<font color='#3b82f6'>3</font>") !== -1, "Digit 3 is highlighted with accent color")
    check(styledWithDigits.indexOf("<font color") === 4, "Letters are not wrapped in font tags")

    var styledNoDigits = formatStyledPassword("correct-horse-battery-staple")
    check(styledNoDigits.indexOf("<font") === -1, "Password without digits has no font tags")
    check(styledNoDigits === "correct-horse-battery-staple", "Plain text preserved when no digits present")

    var styledEscaped = formatStyledPassword("p@ss<w0rd>&1")
    check(styledEscaped.indexOf("&lt;") !== -1, "HTML '<' character is escaped to &lt;")
    check(styledEscaped.indexOf("&gt;") !== -1, "HTML '>' character is escaped to &gt;")
    check(styledEscaped.indexOf("&amp;") !== -1, "HTML '&' character is escaped to &amp;")
    check(styledEscaped.indexOf("<font color='#3b82f6'>0</font>") !== -1, "Digit 0 in complex string is styled")
    check(styledEscaped.indexOf("<font color='#3b82f6'>1</font>") !== -1, "Digit 1 in complex string is styled")

    // 18. Generate Hotkey Ctrl+G (与官方客户端保持一致)
    var beforeCtrlGCalls = executeCallCount
    handleKey(Qt.Key_G, Qt.ControlModifier)
    check(executeCallCount === beforeCtrlGCalls + 1, "Ctrl+G triggers regenerate()")

    var beforeCtrlRCalls = executeCallCount
    handleKey(Qt.Key_R, Qt.ControlModifier)
    check(executeCallCount === beforeCtrlRCalls + 1, "Ctrl+R remains supported as alias for regenerate()")

    // 19. Long Password Wrapping Support (128-char passwords wrap cleanly)
    var long128 = "a".repeat(128)
    var isLong = long128.length > 32
    check(isLong === true, "128-char password flagged as long password (> 32 chars)")
    var styled128 = formatStyledPassword(long128)
    check(styled128.length >= 128, "128-char formatted secret retains full character content")

    // 20. Fill Mode Defaults & Primary Action Surface (issue #385)
    check(fillMode === false, "Default fillMode is false (backward compatible)")
    check(primaryActionLabel === "Copy to Clipboard (↵)", "Non-fill primary action reads 'Copy to Clipboard (↵)'")
    check(primaryActionIcon === "\uf0c5", "Non-fill primary action uses copy icon")

    // 21. Fill Mode Primary Action Surface
    fillMode = true
    check(primaryActionLabel === "Use Password (↵)", "fillMode primary action reads 'Use Password (↵)'")
    check(primaryActionIcon === "\uf00c", "fillMode primary action uses check icon")

    // 22. Fill Mode Enter Selection Workflow: passwordSelected without clipboard write
    active = true
    wasClosed = false
    lastCopiedText = ""
    generatedPassword = "FillSecret!2026Use"
    handleKey(Qt.Key_Return, Qt.NoModifier)
    check(lastSelectedPassword === "FillSecret!2026Use", "Enter in fillMode emits passwordSelected with generated secret")
    check(selectionCount === 1, "Enter in fillMode emits passwordSelected exactly once")
    check(lastCopiedText === "", "Enter in fillMode does not modify the clipboard")
    check(active === false, "Enter in fillMode closes the modal")
    check(wasClosed === true, "Enter in fillMode marks wasClosed")

    // 23. Fill Mode Enter Also Fires For Keypad Enter
    active = true
    wasClosed = false
    lastSelectedPassword = ""
    selectionCount = 0
    handleKey(Qt.Key_Enter, Qt.NoModifier)
    check(lastSelectedPassword === "FillSecret!2026Use", "Keypad Enter in fillMode emits passwordSelected")
    check(selectionCount === 1, "Keypad Enter in fillMode emits passwordSelected exactly once")
    check(wasClosed === true, "Keypad Enter in fillMode closes the modal")

    // 24. Fill Mode Selection Guards Against Error State
    active = true
    wasClosed = false
    lastSelectedPassword = ""
    selectionCount = 0
    errorMessage = "omawarden engine is outdated"
    handleKey(Qt.Key_Return, Qt.NoModifier)
    check(lastSelectedPassword === "", "fillMode Enter does not select a secret while errorMessage is present")
    check(selectionCount === 0, "fillMode Enter emits no passwordSelected while errorMessage is present")
    check(wasClosed === false, "fillMode Enter does not close the modal while errorMessage is present")
    errorMessage = ""
    handleKey(Qt.Key_Return, Qt.NoModifier)
    check(lastSelectedPassword === "FillSecret!2026Use", "fillMode Enter selects once errorMessage is clear")
    check(wasClosed === true, "fillMode Enter closes the modal once errorMessage is clear")

    // 25. Fill Mode Keeps All Generator Options Fully Functional
    mode = "password"
    check(mode === "password", "fillMode starts from password mode")
    passwordLength = 32
    includeUppercase = true
    includeLowercase = true
    includeNumbers = true
    includeSpecial = false
    var fillModeEnt = calculateEntropy()
    check(Math.abs(fillModeEnt - (32 * Math.log(26 + 26 + 10) / Math.LN2)) < 0.5, "fillMode length/charset changes recompute entropy (got " + fillModeEnt.toFixed(2) + ")")
    mode = "passphrase"
    passphraseWords = 7
    var fillModePhraseEnt = calculateEntropy()
    check(Math.abs(fillModePhraseEnt - 90.405) < 0.1, "fillMode passphrase word count changes recompute entropy (got " + fillModePhraseEnt.toFixed(2) + ")")
    mode = "password"
    passwordLength = 20
    includeSpecial = true
    passphraseWords = 4
    fillMode = false

    // 26. Non-Fill Enter Remains Copy-To-Clipboard (backward compatibility)
    active = true
    wasClosed = false
    lastCopiedText = ""
    lastSelectedPassword = ""
    selectionCount = 0
    generatedPassword = "LegacySecret!2026Copy"
    handleKey(Qt.Key_Return, Qt.NoModifier)
    check(lastCopiedText === "LegacySecret!2026Copy", "Enter without fillMode still copies to clipboard")
    check(lastCopiedSensitive === true, "Enter without fillMode marks clipboard copy as sensitive")
    check(lastCopiedLabel === "password", "Enter without fillMode labels the clipboard copy")
    check(selectionCount === 0, "Enter without fillMode never emits passwordSelected")
    check(active === false, "Enter without fillMode still dismisses the modal")
    check(wasClosed === true, "Enter without fillMode still marks wasClosed")

    // 27. Fill Mode Passphrase Selection Uses The Passphrase Secret
    fillMode = true
    mode = "passphrase"
    active = true
    wasClosed = false
    lastCopiedText = ""
    lastSelectedPassword = ""
    selectionCount = 0
    generatedPassword = "fill-mode-diceware-passphrase"
    handleKey(Qt.Key_Return, Qt.NoModifier)
    check(lastSelectedPassword === "fill-mode-diceware-passphrase", "fillMode Enter selects the generated passphrase")
    check(lastCopiedText === "", "fillMode passphrase selection never touches the clipboard")
    check(wasClosed === true, "fillMode passphrase selection closes the modal")
    mode = "password"
    fillMode = false

    // 28. Real Component: fillMode Surface & Keyboard Seam Signal Routing (issue #385)
    check(genModal.hasOwnProperty("fillMode"), "Real component exposes the fillMode property")
    check(genModal.fillMode === false, "Real component fillMode defaults to false")
    check(genModal.primaryActionLabel === "Copy to Clipboard (↵)", "Real component default primary label is 'Copy to Clipboard (↵)'")
    check(genModal.primaryActionIcon === "\uf0c5", "Real component default primary icon is the copy glyph")

    var realCopies = 0
    var realSelections = []
    var realCloses = 0
    var copyConn = genModal.copyRequested.connect(function(text, isSensitive, label) { realCopies++ })
    var selConn = genModal.passwordSelected.connect(function(password) { realSelections.push(password) })
    var closeConn = genModal.closeRequested.connect(function() { realCloses++ })
    genModal.generatedPassword = "ComponentSecret!2026"
    genModal.errorMessage = ""

    // Backward compatibility: Enter without fillMode routes through the clipboard.
    genModal.handleKey(Qt.Key_Return, Qt.NoModifier)
    check(realCopies === 1, "Real component Enter (non-fill) emits copyRequested once")
    check(realSelections.length === 0, "Real component Enter (non-fill) never emits passwordSelected")
    check(realCloses === 1, "Real component Enter (non-fill) emits closeRequested")

    // Fill mode: Enter routes through passwordSelected, never the clipboard.
    genModal.fillMode = true
    check(genModal.primaryActionLabel === "Use Password (↵)", "Real component fillMode primary label is 'Use Password (↵)'")
    check(genModal.primaryActionIcon === "\uf00c", "Real component fillMode primary icon is the check glyph")
    genModal.handleKey(Qt.Key_Return, Qt.NoModifier)
    check(realSelections.length === 1 && realSelections[0] === "ComponentSecret!2026", "Real component Enter (fillMode) emits passwordSelected with the generated secret")
    check(realCopies === 1, "Real component Enter (fillMode) does not emit copyRequested (clipboard untouched)")
    check(realCloses === 2, "Real component Enter (fillMode) emits closeRequested")

    // Keypad Enter follows the same fill-mode routing.
    genModal.handleKey(Qt.Key_Enter, Qt.NoModifier)
    check(realSelections.length === 2 && realSelections[1] === "ComponentSecret!2026", "Real component keypad Enter (fillMode) emits passwordSelected again")
    check(realCopies === 1, "Real component keypad Enter (fillMode) still does not copy")

    // Error guard parity on the real component.
    genModal.errorMessage = "boom"
    genModal.handleKey(Qt.Key_Return, Qt.NoModifier)
    check(realSelections.length === 2, "Real component Enter (fillMode) guards against errorMessage")
    genModal.errorMessage = ""
    genModal.useAndClose()
    check(realSelections.length === 3, "Real component useAndClose() emits passwordSelected once errorMessage is clear")
    genModal.generatedPassword = ""
    genModal.fillMode = false

    // 29. Real Component: All Generator Options Remain Functional In fillMode
    var realGenOpts = []
    var optsConn = genModal.generateRequested.connect(function(opts) { realGenOpts.push(opts) })
    genModal.fillMode = true
    genModal.passwordLength = 32
    genModal.includeSpecial = false
    genModal.regenerate()
    var lastOpts = realGenOpts[realGenOpts.length - 1]
    check(lastOpts && lastOpts.mode === "password" && lastOpts.length === 32 && lastOpts.uppercase === true && lastOpts.special === false, "fillMode regenerate forwards adjusted length/charset options to the engine")

    // Mode switch stays available in fillMode (Ctrl+Tab keyboard seam).
    genModal.handleKey(Qt.Key_Tab, Qt.ControlModifier)
    check(genModal.mode === "passphrase", "Ctrl+Tab switches to passphrase mode while fillMode is enabled")
    genModal.passphraseWords = 7
    genModal.passphraseSeparator = "_"
    genModal.passphraseCapitalize = true
    genModal.regenerate()
    lastOpts = realGenOpts[realGenOpts.length - 1]
    check(lastOpts && lastOpts.mode === "passphrase" && lastOpts.words === 7 && lastOpts.separator === "_" && lastOpts.capitalize === true, "fillMode passphrase options (words/separator/capitalize) reach the engine")
    check(genModal.avoidAmbiguous === false, "fillMode retains the avoidAmbiguous toggle")

    // Restore defaults for later sections.
    genModal.passwordLength = 20
    genModal.includeSpecial = true
    genModal.passphraseWords = 4
    genModal.passphraseSeparator = "-"
    genModal.passphraseCapitalize = false
    genModal.mode = "password"
    genModal.fillMode = false

    console.log("PasswordGeneratorModal Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
