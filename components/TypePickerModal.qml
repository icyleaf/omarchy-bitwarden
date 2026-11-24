import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Lightweight centered picker for choosing the cipher type to create (Ctrl+N).
// Keyboard-driven: single-key L / N / S, Up / Down navigation, Enter to confirm,
// Esc to dismiss, and repeated Ctrl+N cycles the highlighted option.
Rectangle {
  id: pickerRoot

  property bool active: false
  property int selectedIndex: 0
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  readonly property var options: [
    { type: "login", label: "Login", hint: "L" },
    { type: "note", label: "Secure Note", hint: "N" },
    { type: "ssh_key", label: "SSH Key", hint: "S" }
  ]

  signal typeSelected(string cipherType)
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.6)
  visible: active

  function cycleSelection() {
    if (!options || options.length === 0) return
    selectedIndex = (selectedIndex + 1) % options.length
  }

  // Emits the highlighted cipher type. Closing is left to the parent via the
  // typeSelected handler so the `active: root.showTypePicker` binding survives.
  function confirmSelection() {
    if (!options || options.length === 0) return
    var option = options[Math.max(0, Math.min(selectedIndex, options.length - 1))]
    typeSelected(option.type)
  }

  // Requests dismissal without selecting; the parent closes via closeRequested.
  function dismiss() {
    closeRequested()
  }

  // Resolves a single-key hint ("L" / "N") to its option index, or -1.
  function optionIndexForKey(key) {
    if (!options) return -1
    for (var i = 0; i < options.length; i++) {
      var hint = options[i].hint
      if (hint && hint.length === 1 && key === hint.toUpperCase().charCodeAt(0)) return i
    }
    return -1
  }

  // Single keyboard seam shared by the live focus trap and the test runner.
  // Returns true when the key was consumed.
  function handleKey(key, modifiers) {
    if (key === Qt.Key_Escape) {
      dismiss()
      return true
    }
    if (key === Qt.Key_Return || key === Qt.Key_Enter) {
      confirmSelection()
      return true
    }
    if (key === Qt.Key_Down) {
      cycleSelection()
      return true
    }
    if (key === Qt.Key_Up) {
      if (options && options.length > 0) selectedIndex = (selectedIndex - 1 + options.length) % options.length
      return true
    }
    if ((modifiers & Qt.ControlModifier) && key === Qt.Key_N) {
      cycleSelection()
      return true
    }
    // Single-key shortcuts must not fire under a modifier hold (Ctrl+N above
    // is the cycle key, so Ctrl+L / Ctrl+N never pick a type directly).
    if (modifiers & Qt.ControlModifier) return false
    var hinted = optionIndexForKey(key)
    if (hinted !== -1) {
      selectedIndex = hinted
      confirmSelection()
      return true
    }
    return false
  }

  MouseArea {
    anchors.fill: parent
    onClicked: pickerRoot.dismiss()
  }

  // Picker Card
  Rectangle {
    id: pickerBox
    anchors.centerIn: parent
    width: Math.min(parent.width - 64, 340)
    height: pickerColumn.implicitHeight + 24
    radius: Style.cornerRadius
    color: pickerRoot.cardBackground
    border.color: pickerRoot.borderColor
    border.width: 1
    focus: true

    Keys.onPressed: function(event) {
      if (pickerRoot.handleKey(event.key, event.modifiers)) event.accepted = true
    }

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      id: pickerColumn
      anchors.fill: parent
      anchors.margins: 12
      spacing: 8

      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: "\uf067"
          font.family: pickerRoot.fontFamily
          font.pixelSize: Style.font.subtitle
          color: pickerRoot.accent
        }

        Text {
          text: "Create New Item"
          color: pickerRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.Medium
          Layout.fillWidth: true
        }

        Text {
          text: "Esc"
          color: pickerRoot.muted
          font.pixelSize: Style.font.caption
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: pickerRoot.borderColor
      }

      Repeater {
        model: pickerRoot.options

        delegate: Rectangle {
          id: optionDelegate
          property bool isSelected: index === pickerRoot.selectedIndex
          width: pickerColumn.width
          height: 40
          radius: 5
          color: isSelected ? Qt.rgba(pickerRoot.accent.r, pickerRoot.accent.g, pickerRoot.accent.b, 0.25) : (optionMouse.containsMouse ? Qt.rgba(pickerRoot.foreground.r, pickerRoot.foreground.g, pickerRoot.foreground.b, 0.05) : "transparent")
          border.color: isSelected ? pickerRoot.accent : "transparent"
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 10
            spacing: 8

            Text {
              text: modelData.label
              color: optionDelegate.isSelected ? pickerRoot.accent : pickerRoot.foreground
              font.pixelSize: Style.font.body
              font.weight: Font.Medium
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            Rectangle {
              implicitHeight: 20
              implicitWidth: hintText.implicitWidth + 10
              radius: 3
              color: Qt.rgba(pickerRoot.foreground.r, pickerRoot.foreground.g, pickerRoot.foreground.b, 0.08)
              border.color: pickerRoot.borderColor
              border.width: 1

              Text {
                id: hintText
                anchors.centerIn: parent
                text: modelData.hint
                color: pickerRoot.muted
                font.pixelSize: Style.font.caption
              }
            }
          }

          MouseArea {
            id: optionMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              pickerRoot.selectedIndex = index
              pickerRoot.confirmSelection()
            }
          }
        }
      }
    }
  }

  onActiveChanged: {
    if (active) {
      selectedIndex = 0
      pickerBox.forceActiveFocus()
    }
  }
}
