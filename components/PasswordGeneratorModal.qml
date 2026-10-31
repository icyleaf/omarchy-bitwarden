import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: genModalRoot

  property bool active: false
  property string mode: "password" // "password" | "passphrase"
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  readonly property color textOnAccent: StatusPalette.textOn(accent)
  // Password options
  property int passwordLength: 20
  property bool includeUppercase: true
  property bool includeLowercase: true
  property bool includeNumbers: true
  property bool includeSpecial: true
  property bool avoidAmbiguous: false

  // Passphrase options
  property int passphraseWords: 4
  property string passphraseSeparator: "-"
  property bool passphraseCapitalize: false

  // Generated results
  property string generatedPassword: ""
  property real generatedEntropy: 0.0
  property string generatedType: "password"
  property bool isGenerating: false
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

  Timer {
    id: debounceTimer
    interval: 160
    repeat: false
    onTriggered: genModalRoot.executeRegenerate()
  }

  signal generateRequested(var options)
  signal copyRequested(string text, bool isSensitive, string label)
  signal upgradeRequested()
  signal closeRequested()

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.65)
  visible: active
  z: 110

  function requestLazyRegenerate() {
    debounceTimer.restart()
  }

  function regenerate() {
    debounceTimer.stop()
    executeRegenerate()
  }

  function executeRegenerate() {
    generatedPassword = ""
    if (isEngineOutdated) {
      isGenerating = false
      errorMessage = "omawarden engine is outdated" + (engineVersion ? " (v" + engineVersion + ")" : "") + ". Please upgrade to >= " + requiredVersion + " to use credential generation."
      return
    }
    errorMessage = ""
    isGenerating = true
    generateRequested({
      mode: mode,
      length: passwordLength,
      uppercase: includeUppercase,
      lowercase: includeLowercase,
      numbers: includeNumbers,
      special: includeSpecial,
      avoidAmbiguous: avoidAmbiguous,
      words: passphraseWords,
      separator: passphraseSeparator,
      capitalize: passphraseCapitalize
    })
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
      copyRequested(generatedPassword, true, mode === "passphrase" ? "passphrase" : "password")
      closeRequested()
    }
  }

  function formatStyledPassword(password) {
    if (!password) return ""
    var accentHex = "" + genModalRoot.accent
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

  onActiveChanged: {
    if (active) {
      genModalRoot.forceActiveFocus()
      regenerate()
    } else {
      debounceTimer.stop()
    }
  }

  Keys.onPressed: function(event) {
    if (event.key === Qt.Key_Escape) {
      closeRequested()
      event.accepted = true
    } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
      copyAndClose()
      event.accepted = true
    } else if (event.modifiers & Qt.ControlModifier && (event.key === Qt.Key_G || event.key === Qt.Key_R)) {
      regenerate()
      event.accepted = true
    } else if ((event.modifiers & Qt.ControlModifier) && event.key === Qt.Key_Tab) {
      genModalRoot.mode = (genModalRoot.mode === "password" ? "passphrase" : "password")
      genModalRoot.regenerate()
      event.accepted = true
    } else if ((event.modifiers & Qt.AltModifier) && (event.key === Qt.Key_1 || event.key === Qt.Key_P || event.key === Qt.Key_G)) {
      if (genModalRoot.mode !== "password") {
        genModalRoot.mode = "password"
        genModalRoot.regenerate()
      }
      event.accepted = true
    } else if ((event.modifiers & Qt.AltModifier) && event.key === Qt.Key_2) {
      if (genModalRoot.mode !== "passphrase") {
        genModalRoot.mode = "passphrase"
        genModalRoot.regenerate()
      }
      event.accepted = true
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: genModalRoot.closeRequested()
  }

  // Modal Dialog Card
  Rectangle {
    id: modalBox
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 540)
    height: Math.min(parent.height - 48, 500)
    radius: 10
    color: genModalRoot.cardBackground
    border.color: genModalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 20
      spacing: 14

      // Header: Title and Mode Switcher Tabs
      RowLayout {
        Layout.fillWidth: true
        spacing: 12

        RowLayout {
          spacing: 8
          Text {
            text: "\uf084"
            font.family: genModalRoot.fontFamily
            font.pixelSize: Style.font.subtitle
            color: genModalRoot.accent
          }
          Text {
            text: "Generate Credential"
            color: genModalRoot.foreground
            font.pixelSize: Style.font.subtitle
            font.weight: Font.DemiBold
          }
        }

        Item { Layout.fillWidth: true }

        // Mode Switcher Tabs
        Rectangle {
          implicitHeight: 28
          implicitWidth: modeTabsRow.implicitWidth + 8
          radius: 6
          color: Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.05)
          border.color: genModalRoot.borderColor
          border.width: 1

          RowLayout {
            id: modeTabsRow
            anchors.centerIn: parent
            spacing: 2

            // Password Tab
            Rectangle {
              implicitHeight: 22
              implicitWidth: 72
              radius: 4
              color: genModalRoot.mode === "password" ? genModalRoot.accent : "transparent"
              Text {
                anchors.centerIn: parent
                text: "Password"
                color: genModalRoot.mode === "password" ? genModalRoot.textOnAccent : genModalRoot.muted
                font.pixelSize: Style.font.caption
                font.weight: genModalRoot.mode === "password" ? Font.DemiBold : Font.Normal
              }
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  if (genModalRoot.mode !== "password") {
                    genModalRoot.mode = "password"
                    genModalRoot.regenerate()
                  }
                }
              }
            }

            // Passphrase Tab
            Rectangle {
              implicitHeight: 22
              implicitWidth: 78
              radius: 4
              color: genModalRoot.mode === "passphrase" ? genModalRoot.accent : "transparent"
              Text {
                anchors.centerIn: parent
                text: "Passphrase"
                color: genModalRoot.mode === "passphrase" ? genModalRoot.textOnAccent : genModalRoot.muted
                font.pixelSize: Style.font.caption
                font.weight: genModalRoot.mode === "passphrase" ? Font.DemiBold : Font.Normal
              }
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  if (genModalRoot.mode !== "passphrase") {
                    genModalRoot.mode = "passphrase"
                    genModalRoot.regenerate()
                  }
                }
              }
            }
          }
        }
      }

      // Error Alert Banner (Version Unsupported / CLI Error Notice Window)
      Rectangle {
        visible: Boolean(genModalRoot.errorMessage)
        Layout.fillWidth: true
        implicitHeight: errRow.implicitHeight + 12
        radius: 6
        color: Qt.rgba(0.94, 0.27, 0.27, 0.15)
        border.color: "#ef4444"
        border.width: 1

        RowLayout {
          id: errRow
          anchors.fill: parent
          anchors.margins: 6
          spacing: 6

          Text {
            text: "\uf06a"
            font.family: genModalRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: "#f87171"
          }

          Text {
            id: errText
            text: genModalRoot.errorMessage
            color: "#fca5a5"
            font.pixelSize: Style.font.bodySmall
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }

          // Upgrade Button (shown when engine is outdated or upgrade required)
          Rectangle {
            visible: genModalRoot.isEngineOutdated || /outdated|upgrade/i.test(genModalRoot.errorMessage)
            implicitHeight: 22
            implicitWidth: upgradeBtnRow.implicitWidth + 12
            radius: 4
            color: upgradeMouse.containsMouse ? Qt.lighter(genModalRoot.accent, 1.15) : genModalRoot.accent

            RowLayout {
              id: upgradeBtnRow
              anchors.centerIn: parent
              spacing: 4
              Text {
                text: "\uf019"
                font.family: genModalRoot.fontFamily
                font.pixelSize: Style.font.caption
                color: genModalRoot.textOnAccent
              }
              Text {
                text: "Upgrade"
                font.pixelSize: Style.font.caption
                font.weight: Font.DemiBold
                color: genModalRoot.textOnAccent
              }
            }

            MouseArea {
              id: upgradeMouse
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              hoverEnabled: true
              onClicked: genModalRoot.upgradeRequested()
            }
          }
        }
      }

      // Generated Value Box
      Rectangle {
        Layout.fillWidth: true
        Layout.preferredHeight: Math.max(52, genSecretText.contentHeight + 20)
        Behavior on Layout.preferredHeight { NumberAnimation { duration: 120 } }
        radius: 8
        color: Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.05)
        border.color: genModalRoot.borderColor
        border.width: 1

        RowLayout {
          anchors.fill: parent
          anchors.leftMargin: 14
          anchors.rightMargin: 10
          anchors.topMargin: 8
          anchors.bottomMargin: 8
          spacing: 10

          TextEdit {
            id: genSecretText
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            readOnly: true
            selectByMouse: !genModalRoot.errorMessage && Boolean(genModalRoot.generatedPassword)
            cursorVisible: false
            wrapMode: TextEdit.WrapAnywhere
            textFormat: TextEdit.RichText
            text: genModalRoot.errorMessage ? "—" : (genModalRoot.generatedPassword ? genModalRoot.formatStyledPassword(genModalRoot.generatedPassword) : "Generating...")
            color: genModalRoot.errorMessage ? genModalRoot.muted : genModalRoot.foreground
            font.pixelSize: (genModalRoot.generatedPassword.length > 32) ? Style.font.bodySmall : Style.font.subtitle
            font.family: "monospace"
            font.weight: Font.Medium
            clip: true
          }

          // Regenerate Button
          Rectangle {
            Layout.preferredWidth: 32
            Layout.preferredHeight: 32
            Layout.alignment: Qt.AlignVCenter
            radius: 6
            opacity: genModalRoot.isEngineOutdated ? 0.4 : 1.0
            color: regenHover.containsMouse ? Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.15) : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.05)
            border.color: genModalRoot.borderColor
            border.width: 1

            Text {
              anchors.centerIn: parent
              text: "\uf021"
              font.family: genModalRoot.fontFamily
              color: genModalRoot.accent
              font.pixelSize: Style.font.body
            }

            MouseArea {
              id: regenHover
              anchors.fill: parent
              enabled: !genModalRoot.isEngineOutdated
              cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
              hoverEnabled: true
              onClicked: genModalRoot.regenerate()
            }
          }
        }
      }

      // Password Complexity / Strength Indicator (Outside the Secret Box)
      RowLayout {
        id: strengthBarRow
        Layout.fillWidth: true
        Layout.preferredHeight: 16
        opacity: (!genModalRoot.errorMessage && Boolean(genModalRoot.generatedPassword)) ? 1.0 : 0.0
        Behavior on opacity { NumberAnimation { duration: 150 } }
        spacing: 8

        // 5-segment strength meter
        RowLayout {
          spacing: 4
          Repeater {
            model: 5
            Rectangle {
              implicitWidth: 26
              implicitHeight: 4
              radius: 2
              color: (index < genModalRoot.strengthLevel) ? genModalRoot.strengthColor : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.12)
            }
          }
        }

        RowLayout {
          spacing: 5
          Text {
            text: "Strength:"
            color: genModalRoot.muted
            font.pixelSize: Style.font.caption
          }
          Text {
            text: genModalRoot.strengthLabel
            color: genModalRoot.strengthColor
            font.pixelSize: Style.font.caption
            font.weight: Font.DemiBold
          }
        }

        Item { Layout.fillWidth: true }
      }

      // Settings Controls Area (Switchable based on Mode)
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true

        ColumnLayout {
          width: modalBox.width - 40
          spacing: 14

          // --- Password Mode Controls ---
          ColumnLayout {
            Layout.fillWidth: true
            visible: genModalRoot.mode === "password"
            spacing: 12

            // Length Slider
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              RowLayout {
                Layout.fillWidth: true
                Text {
                  text: "Length"
                  color: genModalRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.Medium
                }
                Item { Layout.fillWidth: true }
                Text {
                  text: String(genModalRoot.passwordLength)
                  color: genModalRoot.accent
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.DemiBold
                }
              }

              Slider {
                id: lengthSlider
                Layout.fillWidth: true
                from: 5
                to: 128
                stepSize: 1
                value: genModalRoot.passwordLength
                onMoved: {
                  genModalRoot.passwordLength = Math.round(value)
                  genModalRoot.requestLazyRegenerate()
                }
              }

              Text {
                text: "Use 14 or more characters for a strong password."
                color: genModalRoot.muted
                font.pixelSize: Style.font.caption
              }
            }

            // Options Checkboxes
            GridLayout {
              Layout.fillWidth: true
              columns: 2
              rowSpacing: 10
              columnSpacing: 16

              // Uppercase
              RowLayout {
                spacing: 8
                Rectangle {
                  width: 16; height: 16; radius: 3
                  color: genModalRoot.includeUppercase ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                  border.color: genModalRoot.borderColor; border.width: 1
                  Text {
                    anchors.centerIn: parent
                    visible: genModalRoot.includeUppercase
                    text: "\uf00c"; font.family: genModalRoot.fontFamily
                    color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                  }
                  MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      genModalRoot.includeUppercase = !genModalRoot.includeUppercase
                      genModalRoot.requestLazyRegenerate()
                    }
                  }
                }
                Text { text: "Uppercase (A-Z)"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
              }

              // Lowercase
              RowLayout {
                spacing: 8
                Rectangle {
                  width: 16; height: 16; radius: 3
                  color: genModalRoot.includeLowercase ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                  border.color: genModalRoot.borderColor; border.width: 1
                  Text {
                    anchors.centerIn: parent
                    visible: genModalRoot.includeLowercase
                    text: "\uf00c"; font.family: genModalRoot.fontFamily
                    color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                  }
                  MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      genModalRoot.includeLowercase = !genModalRoot.includeLowercase
                      genModalRoot.requestLazyRegenerate()
                    }
                  }
                }
                Text { text: "Lowercase (a-z)"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
              }

              // Numbers
              RowLayout {
                spacing: 8
                Rectangle {
                  width: 16; height: 16; radius: 3
                  color: genModalRoot.includeNumbers ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                  border.color: genModalRoot.borderColor; border.width: 1
                  Text {
                    anchors.centerIn: parent
                    visible: genModalRoot.includeNumbers
                    text: "\uf00c"; font.family: genModalRoot.fontFamily
                    color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                  }
                  MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      genModalRoot.includeNumbers = !genModalRoot.includeNumbers
                      genModalRoot.requestLazyRegenerate()
                    }
                  }
                }
                Text { text: "Numbers (0-9)"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
              }

              // Special
              RowLayout {
                spacing: 8
                Rectangle {
                  width: 16; height: 16; radius: 3
                  color: genModalRoot.includeSpecial ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                  border.color: genModalRoot.borderColor; border.width: 1
                  Text {
                    anchors.centerIn: parent
                    visible: genModalRoot.includeSpecial
                    text: "\uf00c"; font.family: genModalRoot.fontFamily
                    color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                  }
                  MouseArea {
                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      genModalRoot.includeSpecial = !genModalRoot.includeSpecial
                      genModalRoot.requestLazyRegenerate()
                    }
                  }
                }
                Text { text: "Special (!@#$%^&*)"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
              }
            }

            // Avoid Ambiguous
            RowLayout {
              spacing: 8
              Rectangle {
                width: 16; height: 16; radius: 3
                color: genModalRoot.avoidAmbiguous ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                border.color: genModalRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: genModalRoot.avoidAmbiguous
                  text: "\uf00c"; font.family: genModalRoot.fontFamily
                  color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea {
                  anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    genModalRoot.avoidAmbiguous = !genModalRoot.avoidAmbiguous
                    genModalRoot.requestLazyRegenerate()
                  }
                }
              }
              ColumnLayout {
                spacing: 2
                Text { text: "Avoid Ambiguous Characters"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
                Text { text: "Excludes 0, O, o, 1, l, I, | to prevent visual confusion"; color: genModalRoot.muted; font.pixelSize: Style.font.caption }
              }
            }
          }

          // --- Passphrase Mode Controls ---
          ColumnLayout {
            Layout.fillWidth: true
            visible: genModalRoot.mode === "passphrase"
            spacing: 12

            // Words Slider
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              RowLayout {
                Layout.fillWidth: true
                Text {
                  text: "Number of Words"
                  color: genModalRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.Medium
                }
                Item { Layout.fillWidth: true }
                Text {
                  text: String(genModalRoot.passphraseWords)
                  color: genModalRoot.accent
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.DemiBold
                }
              }

              Slider {
                id: wordsSlider
                Layout.fillWidth: true
                from: 3
                to: 20
                stepSize: 1
                value: genModalRoot.passphraseWords
                onMoved: {
                  genModalRoot.passphraseWords = Math.round(value)
                  genModalRoot.requestLazyRegenerate()
                }
              }
            }

            // Separator Selector
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 6

              Text {
                text: "Word Separator"
                color: genModalRoot.foreground
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }

              RowLayout {
                spacing: 8

                Repeater {
                  model: [
                    { label: "Hyphen (-)", val: "-" },
                    { label: "Period (.)", val: "." },
                    { label: "Underscore (_)", val: "_" },
                    { label: "Space ( )", val: " " }
                  ]

                  Rectangle {
                    implicitHeight: 26
                    implicitWidth: sepText.implicitWidth + 14
                    radius: 4
                    color: genModalRoot.passphraseSeparator === modelData.val ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                    border.color: genModalRoot.borderColor
                    border.width: 1

                    Text {
                      id: sepText
                      anchors.centerIn: parent
                      text: modelData.label
                      color: genModalRoot.passphraseSeparator === modelData.val ? genModalRoot.textOnAccent : genModalRoot.muted
                      font.pixelSize: Style.font.caption
                    }

                    MouseArea {
                      anchors.fill: parent
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        genModalRoot.passphraseSeparator = modelData.val
                        genModalRoot.requestLazyRegenerate()
                      }
                    }
                  }
                }
              }
            }

            // Capitalize Checkbox
            RowLayout {
              spacing: 8
              Rectangle {
                width: 16; height: 16; radius: 3
                color: genModalRoot.passphraseCapitalize ? genModalRoot.accent : Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
                border.color: genModalRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: genModalRoot.passphraseCapitalize
                  text: "\uf00c"; font.family: genModalRoot.fontFamily
                  color: genModalRoot.textOnAccent; font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea {
                  anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    genModalRoot.passphraseCapitalize = !genModalRoot.passphraseCapitalize
                    genModalRoot.requestLazyRegenerate()
                  }
                }
              }
              Text { text: "Capitalize Each Word (Title Case)"; color: genModalRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }
          }
        }
      }

      // Action Buttons Footer
      RowLayout {
        Layout.fillWidth: true
        spacing: 10

        // Cancel / Close
        Rectangle {
          Layout.preferredHeight: 34
          Layout.preferredWidth: 80
          radius: 6
          color: Qt.rgba(genModalRoot.foreground.r, genModalRoot.foreground.g, genModalRoot.foreground.b, 0.08)
          border.color: genModalRoot.borderColor
          border.width: 1

          Text {
            anchors.centerIn: parent
            text: "Close"
            color: genModalRoot.muted
            font.pixelSize: Style.font.bodySmall
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: genModalRoot.closeRequested()
          }
        }

        Item { Layout.fillWidth: true }

        // Copy Credential Button
        Rectangle {
          id: copyBtnBox
          readonly property bool canCopy: !genModalRoot.errorMessage && Boolean(genModalRoot.generatedPassword)
          Layout.preferredHeight: 34
          Layout.preferredWidth: copyBtnRow.implicitWidth + 24
          radius: 6
          opacity: canCopy ? 1.0 : 0.4
          color: genModalRoot.accent

          RowLayout {
            id: copyBtnRow
            anchors.centerIn: parent
            spacing: 8
            Text {
              text: "\uf0c5"
              font.family: genModalRoot.fontFamily
              color: genModalRoot.textOnAccent
              font.pixelSize: Style.font.bodySmall
            }
            Text {
              text: "Copy to Clipboard (↵)"
              color: genModalRoot.textOnAccent
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.DemiBold
            }
          }

          MouseArea {
            anchors.fill: parent
            enabled: copyBtnBox.canCopy
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: {
              if (copyBtnBox.canCopy) {
                genModalRoot.copyAndClose()
              }
            }
          }
        }
      }
    }
  }
}
