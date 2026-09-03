import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: modalRoot

  property bool active: false
  property string mode: "create" // "create" | "import" | "export"
  property var item: null
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""
  property bool isBusy: false
  property string errorMessage: ""

  // Form states
  property string itemName: ""
  property string algorithm: "ed25519"
  property string comment: ""
  property string notes: ""
  property bool exportToLocal: true
  property string outDir: "~/.ssh"

  property string importName: ""
  property string privateKeyPath: "~/.ssh/"
  property string publicKeyPath: ""
  property string importNotes: ""

  property string exportOutDir: "~/.ssh"
  property string exportPrivFile: ""
  property string exportPubFile: ""

  signal createRequested(var payload)
  signal importRequested(var payload)
  signal exportRequested(var payload)
  signal closeRequested()

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.65)
  visible: active

  function resetForm() {
    errorMessage = ""
    isBusy = false
    itemName = ""
    algorithm = "ed25519"
    comment = ""
    notes = ""
    exportToLocal = true
    outDir = "~/.ssh"

    importName = ""
    privateKeyPath = "~/.ssh/"
    publicKeyPath = ""
    importNotes = ""

    if (item) {
      var safeName = (item.name || "id_ssh_key").toLowerCase().replace(/[\s\/]+/g, "_")
      exportPrivFile = safeName
      exportPubFile = safeName + ".pub"
    } else {
      exportPrivFile = "id_ssh_key"
      exportPubFile = "id_ssh_key.pub"
    }
    exportOutDir = "~/.ssh"
  }

  onActiveChanged: {
    if (active) {
      resetForm()
      Qt.callLater(function() {
        if (mode === "create" && createNameInput) {
          createNameInput.forceActiveFocus()
        } else if (mode === "import" && importNameInput) {
          importNameInput.forceActiveFocus()
        } else if (mode === "export" && exportDirInput) {
          exportDirInput.forceActiveFocus()
        }
      })
    }
  }

  function submitCurrentMode() {
    if (isBusy) return
    errorMessage = ""

    if (mode === "create") {
      var trimmedName = itemName.trim()
      if (!trimmedName) {
        errorMessage = "Please enter an item name."
        if (createNameInput) createNameInput.forceActiveFocus()
        return
      }
      createRequested({
        name: trimmedName,
        algorithm: algorithm,
        comment: comment.trim(),
        notes: notes.trim(),
        exportToLocal: exportToLocal,
        outDir: outDir.trim()
      })
    } else if (mode === "import") {
      var trimmedImpName = importName.trim()
      if (!trimmedImpName) {
        errorMessage = "Please enter an item name."
        if (importNameInput) importNameInput.forceActiveFocus()
        return
      }
      var trimmedPriv = privateKeyPath.trim()
      if (!trimmedPriv || trimmedPriv === "~/.ssh" || trimmedPriv === "~/.ssh/") {
        errorMessage = "Please specify the private key file path."
        if (importPrivInput) importPrivInput.forceActiveFocus()
        return
      }
      importRequested({
        name: trimmedImpName,
        privateKeyPath: trimmedPriv,
        publicKeyPath: publicKeyPath.trim(),
        notes: importNotes.trim()
      })
    } else if (mode === "export") {
      if (!item) {
        errorMessage = "No SSH key item selected."
        return
      }
      var trimmedOutDir = exportOutDir.trim()
      if (!trimmedOutDir) {
        errorMessage = "Please enter an export directory."
        if (exportDirInput) exportDirInput.forceActiveFocus()
        return
      }
      exportRequested({
        item: item,
        outDir: trimmedOutDir,
        privateKeyFile: exportPrivFile.trim(),
        publicKeyFile: exportPubFile.trim()
      })
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: {
      if (!modalRoot.isBusy) modalRoot.closeRequested()
    }
  }

  // Modal Dialog Box
  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 520)
    height: Math.min(parent.height - 48, 480)
    radius: 8
    color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
    border.color: modalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 16
      spacing: 12

      // Modal Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: modalRoot.mode === "create" ? "\uf067" : (modalRoot.mode === "import" ? "\uf093" : "\uf019")
          font.family: modalRoot.fontFamily
          font.pixelSize: 14
          color: modalRoot.accent
        }

        Text {
          text: modalRoot.mode === "create" ? "Generate SSH Key" : (modalRoot.mode === "import" ? "Import SSH Key" : "Export SSH Key")
          color: modalRoot.foreground
          font.pixelSize: 13
          font.weight: Font.DemiBold
        }

        Item { Layout.fillWidth: true }

        Rectangle {
          implicitWidth: 22
          implicitHeight: 22
          radius: 4
          color: closeMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : "transparent"

          Text {
            anchors.centerIn: parent
            text: "\uf00d"
            font.family: modalRoot.fontFamily
            font.pixelSize: 11
            color: closeMouse.containsMouse ? modalRoot.foreground : Qt.darker(modalRoot.foreground, 1.5)
          }

          MouseArea {
            id: closeMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (!modalRoot.isBusy) modalRoot.closeRequested()
            }
          }
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: modalRoot.borderColor
      }

      // Error Alert Banner
      Rectangle {
        visible: Boolean(modalRoot.errorMessage)
        Layout.fillWidth: true
        implicitHeight: errText.implicitHeight + 12
        radius: 4
        color: Qt.rgba(0.94, 0.27, 0.27, 0.15)
        border.color: "#ef4444"
        border.width: 1

        RowLayout {
          anchors.fill: parent
          anchors.margins: 6
          spacing: 6

          Text {
            text: "\uf06a"
            font.family: modalRoot.fontFamily
            font.pixelSize: 11
            color: "#f87171"
          }

          Text {
            id: errText
            text: modalRoot.errorMessage
            color: "#fca5a5"
            font.pixelSize: 11
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }
      }

      // Form Area (Scrollable)
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        ColumnLayout {
          width: modalCard.width - 32
          spacing: 10

          // ==========================================
          // 1. CREATE MODE
          // ==========================================
          ColumnLayout {
            visible: modalRoot.mode === "create"
            Layout.fillWidth: true
            spacing: 10

            // Item Name
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Item Name *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: createNameInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: createNameInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: commentInput
                  KeyNavigation.backtab: outDirInput
                  text: modalRoot.itemName
                  onTextChanged: modalRoot.itemName = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }
            }

            // Algorithm Selector
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Algorithm"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              RowLayout {
                Layout.fillWidth: true
                spacing: 6

                Repeater {
                  model: [
                    { id: "ed25519", label: "Ed25519 (Recommended)" },
                    { id: "rsa-2048", label: "RSA 2048" },
                    { id: "rsa-4096", label: "RSA 4096" },
                    { id: "ecdsa-p256", label: "ECDSA P-256" }
                  ]

                  Rectangle {
                    property bool isSelected: modalRoot.algorithm === modelData.id
                    implicitHeight: 26
                    implicitWidth: algoText.implicitWidth + 12
                    radius: 4
                    color: isSelected ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.2) : (algoMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(0, 0, 0, 0.2))
                    border.color: isSelected ? modalRoot.accent : modalRoot.borderColor
                    border.width: 1

                    Text {
                      id: algoText
                      anchors.centerIn: parent
                      text: modelData.label
                      color: parent.isSelected ? modalRoot.accent : (algoMouse.containsMouse ? modalRoot.foreground : Qt.darker(modalRoot.foreground, 1.3))
                      font.pixelSize: 10
                      font.weight: parent.isSelected ? Font.DemiBold : Font.Normal
                    }

                    MouseArea {
                      id: algoMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: modalRoot.algorithm = modelData.id
                    }
                  }
                }
              }
            }

            // Comment
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Key Comment (optional)"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: commentInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: commentInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: notesInput
                  KeyNavigation.backtab: createNameInput
                  text: modalRoot.comment
                  onTextChanged: modalRoot.comment = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }

                Text {
                  anchors.left: parent.left
                  anchors.leftMargin: 8
                  anchors.verticalCenter: parent.verticalCenter
                  text: "e.g. your_email@example.com"
                  color: Qt.darker(modalRoot.foreground, 2.0)
                  font.pixelSize: 11
                  visible: !commentInput.text
                }
              }
            }

            // Notes
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Notes (optional)"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 54
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: notesInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                Flickable {
                  anchors.fill: parent
                  anchors.margins: 6
                  clip: true

                  TextArea.flickable: TextArea {
                    id: notesInput
                    color: modalRoot.foreground
                    background: null
                    padding: 0
                    font.pixelSize: 11
                    wrapMode: Text.Wrap
                    selectByMouse: true
                    activeFocusOnTab: true
                    text: modalRoot.notes
                    onTextChanged: modalRoot.notes = text
                    Keys.onTabPressed: function(event) {
                      outDirInput.forceActiveFocus()
                      event.accepted = true
                    }
                    Keys.onBacktabPressed: function(event) {
                      commentInput.forceActiveFocus()
                      event.accepted = true
                    }
                  }
                }
              }
            }

            // Local Export Checkbox & OutDir
            RowLayout {
              Layout.fillWidth: true
              spacing: 8

              Rectangle {
                implicitWidth: 16
                implicitHeight: 16
                radius: 3
                color: modalRoot.exportToLocal ? modalRoot.accent : Qt.rgba(0, 0, 0, 0.3)
                border.color: modalRoot.exportToLocal ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                Text {
                  anchors.centerIn: parent
                  text: "\uf00c"
                  font.family: modalRoot.fontFamily
                  font.pixelSize: 9
                  color: "#ffffff"
                  visible: modalRoot.exportToLocal
                }

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: modalRoot.exportToLocal = !modalRoot.exportToLocal
                }
              }

              Text {
                text: "Also export keypair to local directory:"
                color: modalRoot.foreground
                font.pixelSize: 11
              }

              Rectangle {
                Layout.fillWidth: true
                height: 26
                radius: 4
                enabled: modalRoot.exportToLocal
                color: modalRoot.exportToLocal ? Qt.rgba(0, 0, 0, 0.3) : Qt.rgba(0, 0, 0, 0.1)
                border.color: outDirInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: outDirInput
                  anchors.fill: parent
                  anchors.leftMargin: 6
                  anchors.rightMargin: 6
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.exportToLocal ? modalRoot.foreground : Qt.darker(modalRoot.foreground, 2.0)
                  font.pixelSize: 11
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: createNameInput
                  KeyNavigation.backtab: notesInput
                  text: modalRoot.outDir
                  onTextChanged: modalRoot.outDir = text
                }
              }
            }
          }

          // ==========================================
          // 2. IMPORT MODE
          // ==========================================
          ColumnLayout {
            visible: modalRoot.mode === "import"
            Layout.fillWidth: true
            spacing: 10

            // Import Name
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Item Name *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: importNameInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: importNameInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: importPrivInput
                  KeyNavigation.backtab: importNotesInput
                  text: modalRoot.importName
                  onTextChanged: modalRoot.importName = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }
            }

            // Private Key File Path
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Private Key File Path *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: importPrivInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: importPrivInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: importPubInput
                  KeyNavigation.backtab: importNameInput
                  text: modalRoot.privateKeyPath
                  onTextChanged: modalRoot.privateKeyPath = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }

              Text {
                text: "Defaults to ~/.ssh/ (e.g. ~/.ssh/id_ed25519 or ~/.ssh/id_rsa)"
                color: Qt.darker(modalRoot.foreground, 2.0)
                font.pixelSize: 10
              }
            }

            // Public Key File Path (Optional)
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Public Key File Path (optional - auto-derived if omitted)"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: importPubInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: importPubInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: importNotesInput
                  KeyNavigation.backtab: importPrivInput
                  text: modalRoot.publicKeyPath
                  onTextChanged: modalRoot.publicKeyPath = text
                }
              }
            }

            // Import Notes
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Notes (optional)"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 54
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: importNotesInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                Flickable {
                  anchors.fill: parent
                  anchors.margins: 6
                  clip: true

                  TextArea.flickable: TextArea {
                    id: importNotesInput
                    color: modalRoot.foreground
                    background: null
                    padding: 0
                    font.pixelSize: 11
                    wrapMode: Text.Wrap
                    selectByMouse: true
                    activeFocusOnTab: true
                    text: modalRoot.importNotes
                    onTextChanged: modalRoot.importNotes = text
                    Keys.onTabPressed: function(event) {
                      importNameInput.forceActiveFocus()
                      event.accepted = true
                    }
                    Keys.onBacktabPressed: function(event) {
                      importPubInput.forceActiveFocus()
                      event.accepted = true
                    }
                  }
                }
              }
            }
          }

          // ==========================================
          // 3. EXPORT MODE
          // ==========================================
          ColumnLayout {
            visible: modalRoot.mode === "export"
            Layout.fillWidth: true
            spacing: 10

            // Item Summary Card
            Rectangle {
              Layout.fillWidth: true
              implicitHeight: itemSummaryCol.implicitHeight + 16
              radius: 4
              color: Qt.rgba(0, 0, 0, 0.25)
              border.color: modalRoot.borderColor
              border.width: 1

              ColumnLayout {
                id: itemSummaryCol
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4

                RowLayout {
                  spacing: 6
                  Text {
                    text: "\uf084"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: 12
                    color: modalRoot.accent
                  }
                  Text {
                    text: modalRoot.item ? (modalRoot.item.name || "SSH Key") : ""
                    color: modalRoot.foreground
                    font.pixelSize: 12
                    font.weight: Font.DemiBold
                  }
                }

                Text {
                  visible: Boolean(modalRoot.item && modalRoot.item.ssh_key && modalRoot.item.ssh_key.fingerprint)
                  text: "Fingerprint: " + (modalRoot.item && modalRoot.item.ssh_key ? (modalRoot.item.ssh_key.fingerprint || "") : "")
                  color: Qt.darker(modalRoot.foreground, 1.5)
                  font.pixelSize: 10
                  font.family: "monospace"
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                }
              }
            }

            // Export Directory
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Destination Directory *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: exportDirInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: exportDirInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: exportPrivInput
                  KeyNavigation.backtab: exportPubInput
                  text: modalRoot.exportOutDir
                  onTextChanged: modalRoot.exportOutDir = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }
            }

            // Private Key Filename
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Private Key Filename *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: exportPrivInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: exportPrivInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: exportPubInput
                  KeyNavigation.backtab: exportDirInput
                  text: modalRoot.exportPrivFile
                  onTextChanged: {
                    modalRoot.exportPrivFile = text
                    if (!exportPubInput.activeFocus) {
                      modalRoot.exportPubFile = text + ".pub"
                    }
                  }
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }
            }

            // Public Key Filename
            ColumnLayout {
              Layout.fillWidth: true
              spacing: 4

              Text {
                text: "Public Key Filename *"
                color: Qt.darker(modalRoot.foreground, 1.4)
                font.pixelSize: 11
                font.weight: Font.Medium
              }

              Rectangle {
                Layout.fillWidth: true
                height: 30
                radius: 4
                color: Qt.rgba(0, 0, 0, 0.3)
                border.color: exportPubInput.activeFocus ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                TextInput {
                  id: exportPubInput
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  verticalAlignment: Text.AlignVCenter
                  color: modalRoot.foreground
                  font.pixelSize: 12
                  selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: exportDirInput
                  KeyNavigation.backtab: exportPrivInput
                  text: modalRoot.exportPubFile
                  onTextChanged: modalRoot.exportPubFile = text
                  Keys.onReturnPressed: modalRoot.submitCurrentMode()
                }
              }
            }
          }
        }
      }

      // Dialog Footer Action Buttons
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Item { Layout.fillWidth: true }

        // Cancel Button
        Rectangle {
          implicitHeight: 28
          implicitWidth: 70
          radius: 4
          color: cancelMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : "transparent"
          border.color: modalRoot.borderColor
          border.width: 1

          Text {
            anchors.centerIn: parent
            text: "Cancel"
            color: cancelMouse.containsMouse ? modalRoot.foreground : Qt.darker(modalRoot.foreground, 1.3)
            font.pixelSize: 11
          }

          MouseArea {
            id: cancelMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (!modalRoot.isBusy) modalRoot.closeRequested()
            }
          }
        }

        // Submit Button
        Rectangle {
          implicitHeight: 28
          implicitWidth: 90
          radius: 4
          color: submitMouse.containsMouse ? Qt.lighter(modalRoot.accent, 1.1) : modalRoot.accent
          opacity: modalRoot.isBusy ? 0.6 : 1.0

          RowLayout {
            anchors.centerIn: parent
            spacing: 6

            Text {
              visible: modalRoot.isBusy
              text: "\uf110"
              font.family: modalRoot.fontFamily
              font.pixelSize: 11
              color: "#ffffff"
            }

            Text {
              text: modalRoot.isBusy ? "Processing..." : (modalRoot.mode === "create" ? "Generate" : (modalRoot.mode === "import" ? "Import" : "Export"))
              color: "#ffffff"
              font.pixelSize: 11
              font.weight: Font.DemiBold
            }
          }

          MouseArea {
            id: submitMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: modalRoot.isBusy ? Qt.ArrowCursor : Qt.PointingHandCursor
            onClicked: modalRoot.submitCurrentMode()
          }
        }
      }
    }
  }
}
