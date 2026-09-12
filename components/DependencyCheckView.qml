import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: depViewRoot

  property var dependencyModel: defaultModel
  property var missingPackages: []
  property bool isChecking: false
  property bool isInstalling: false

  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property color background: Qt.rgba(0, 0, 0, 0.2)
  property color cardBackground: Qt.rgba(0, 0, 0, 0.25)
  property string fontFamily: ""

  signal recheckRequested()
  signal installRequested()

  ListModel {
    id: defaultModel

    ListElement {
      pkgName: "omawarden"
      aurPkgName: "omawarden-bin"
      required: true
      title: "Bitwarden Engine & Daemon"
      description: "High-performance Rust backend providing end-to-end encryption, TOTP generation, and Unix domain socket IPC (distributed via AUR omawarden-bin)."
      status: "idle"     // "idle" | "checking" | "installed" | "missing"
      version: ""
    }

    ListElement {
      pkgName: "libsecret"
      aurPkgName: "libsecret"
      required: true
      title: "Secret Service & Keyring"
      description: "Provides secret-tool CLI for securely persisting vault session tokens and API credentials in the system keyring."
      status: "idle"
      version: ""
    }

    ListElement {
      pkgName: "wl-clipboard"
      aurPkgName: "wl-clipboard"
      required: true
      title: "Wayland Clipboard Utilities"
      description: "Provides wl-copy and wl-paste for secure password and TOTP copying with auto-clearing timeout."
      status: "idle"
      version: ""
    }
  }

  function parsePacmanStdout(output) {
    var text = (output || "").trim()
    if (!text) return

    var lines = text.split("\n")
    for (var i = 0; i < lines.length; i++) {
      var match = lines[i].trim().match(/^(\S+)\s+(.+)$/)
      if (match) {
        var name = match[1]
        var ver = match[2]
        for (var j = 0; j < dependencyModel.count; j++) {
          var item = dependencyModel.get(j)
          if (item.pkgName === name || item.aurPkgName === name || (item.pkgName === "omawarden" && name === "omawarden-bin")) {
            dependencyModel.setProperty(j, "status", "installed")
            dependencyModel.setProperty(j, "version", ver)
            break
          }
        }
      }
    }
  }

  function parsePacmanStderr(errOutput) {
    var text = (errOutput || "").trim()
    if (!text) return

    var lines = text.split("\n")
    for (var i = 0; i < lines.length; i++) {
      var match = lines[i].trim().match(/package '([^']+)' was not found/)
      if (match) {
        var missingName = match[1]
        for (var j = 0; j < dependencyModel.count; j++) {
          var item = dependencyModel.get(j)
          if (item.pkgName === missingName || item.aurPkgName === missingName) {
            dependencyModel.setProperty(j, "status", "missing")
            dependencyModel.setProperty(j, "version", "")
            break
          }
        }
      }
    }
  }

  function finalizeCheck() {
    var missing = []
    for (var i = 0; i < dependencyModel.count; i++) {
      var item = dependencyModel.get(i)
      if (item.status === "checking") {
        dependencyModel.setProperty(i, "status", "missing")
        missing.push(item.pkgName)
      } else if (item.status === "missing") {
        missing.push(item.pkgName)
      }
    }
    depViewRoot.missingPackages = missing
    return missing
  }

  function resetToChecking() {
    depViewRoot.missingPackages = []
    for (var i = 0; i < dependencyModel.count; i++) {
      dependencyModel.setProperty(i, "status", "checking")
      dependencyModel.setProperty(i, "version", "")
    }
  }

  function getInstallPackageNames() {
    var list = []
    for (var i = 0; i < depViewRoot.missingPackages.length; i++) {
      var name = depViewRoot.missingPackages[i]
      if (name === "omawarden") {
        list.push("omawarden-bin")
      } else {
        list.push(name)
      }
    }
    return list
  }

  Flickable {
    id: flickable
    anchors.fill: parent
    contentWidth: width
    contentHeight: Math.max(height, mainColumn.implicitHeight + 40)
    boundsBehavior: Flickable.StopAtBounds
    clip: true

    ColumnLayout {
      id: mainColumn
      anchors.centerIn: parent
      width: Math.min(parent.width - 48, 640)
      spacing: 16

      // 1. Header
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          spacing: 10

          Text {
            text: "\uf0ad"
            font.family: depViewRoot.fontFamily
            font.pixelSize: 22
            color: depViewRoot.accent
          }

          Text {
            text: "System Dependencies Required"
            color: depViewRoot.foreground
            font.pixelSize: 16
            font.bold: true
          }

          Rectangle {
            height: 20
            width: setupBadge.implicitWidth + 12
            radius: 4
            color: Qt.rgba(255, 255, 255, 0.08)
            border.color: depViewRoot.borderColor
            border.width: 1

            Text {
              id: setupBadge
              anchors.centerIn: parent
              text: "Prerequisite Setup"
              color: depViewRoot.accent
              font.pixelSize: 10
              font.bold: true
            }
          }
        }

        Text {
          text: "Omarchy Bitwarden requires native Arch / AUR packages to provide background encryption, system keyring session caching, and Wayland clipboard management."
          color: Qt.darker(depViewRoot.foreground, 1.6)
          font.pixelSize: 11
          wrapMode: Text.WordWrap
          Layout.fillWidth: true
        }
      }

      // 2. Package Cards List
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 10

        Repeater {
          model: depViewRoot.dependencyModel

          delegate: Rectangle {
            Layout.fillWidth: true
            implicitHeight: cardLayout.implicitHeight + 20
            radius: 8
            color: {
              if (model.status === "installed") return Qt.rgba(0.18, 0.45, 0.32, 0.2)
              if (model.status === "missing") return Qt.rgba(0.55, 0.2, 0.25, 0.2)
              return depViewRoot.cardBackground
            }
            border.color: {
              if (model.status === "installed") return Qt.rgba(0.2, 0.7, 0.4, 0.4)
              if (model.status === "missing") return Qt.rgba(0.9, 0.3, 0.4, 0.4)
              return depViewRoot.borderColor
            }
            border.width: 1

            RowLayout {
              id: cardLayout
              anchors.fill: parent
              anchors.margins: 12
              spacing: 12

              // State Indicator Dot
              Rectangle {
                width: 10
                height: 10
                radius: 5
                color: {
                  if (model.status === "installed") return "#a6e3a1"
                  if (model.status === "missing") return "#f38ba8"
                  if (model.status === "checking") return "#f9e2af"
                  return Qt.darker(depViewRoot.foreground, 2)
                }
              }

              // Details
              ColumnLayout {
                Layout.fillWidth: true
                spacing: 3

                RowLayout {
                  spacing: 8

                  Text {
                    text: model.pkgName
                    color: depViewRoot.foreground
                    font.pixelSize: 13
                    font.bold: true
                  }

                  Rectangle {
                    height: 18
                    width: reqTagText.implicitWidth + 8
                    radius: 3
                    color: Qt.rgba(255, 255, 255, 0.08)
                    Text {
                      id: reqTagText
                      anchors.centerIn: parent
                      text: (model.pkgName === "omawarden") ? "AUR: omawarden-bin" : "Core System Package"
                      color: (model.pkgName === "omawarden") ? depViewRoot.accent : Qt.darker(depViewRoot.foreground, 1.4)
                      font.pixelSize: 10
                      font.bold: true
                    }
                  }

                  Text {
                    text: model.version ? ("v" + model.version) : ""
                    color: "#a6e3a1"
                    font.pixelSize: 11
                    font.bold: true
                    visible: model.status === "installed" && Boolean(model.version)
                  }
                }

                Text {
                  text: model.title
                  color: Qt.darker(depViewRoot.foreground, 1.3)
                  font.pixelSize: 11
                  font.weight: Font.DemiBold
                }

                Text {
                  text: model.description
                  color: Qt.darker(depViewRoot.foreground, 1.6)
                  font.pixelSize: 10
                  wrapMode: Text.WordWrap
                  Layout.fillWidth: true
                }
              }

              // Status Badge Pill
              Rectangle {
                implicitWidth: statusText.implicitWidth + 16
                implicitHeight: 24
                radius: 12
                color: {
                  if (model.status === "installed") return Qt.rgba(0.18, 0.45, 0.32, 0.5)
                  if (model.status === "missing") return Qt.rgba(0.55, 0.2, 0.25, 0.5)
                  if (model.status === "checking") return Qt.rgba(0.5, 0.4, 0.1, 0.5)
                  return Qt.rgba(255, 255, 255, 0.08)
                }
                border.color: {
                  if (model.status === "installed") return "#a6e3a1"
                  if (model.status === "missing") return "#f38ba8"
                  if (model.status === "checking") return "#f9e2af"
                  return depViewRoot.borderColor
                }
                border.width: 1

                Text {
                  id: statusText
                  anchors.centerIn: parent
                  text: {
                    if (model.status === "installed") return "✓ Ready"
                    if (model.status === "missing") return "✗ Missing"
                    if (model.status === "checking") return "⏳ Checking"
                    return "Pending"
                  }
                  color: {
                    if (model.status === "installed") return "#a6e3a1"
                    if (model.status === "missing") return "#f38ba8"
                    if (model.status === "checking") return "#f9e2af"
                    return depViewRoot.foreground
                  }
                  font.pixelSize: 11
                  font.bold: true
                }
              }
            }
          }
        }
      }

      // 3. Action Buttons & Info
      RowLayout {
        Layout.fillWidth: true
        spacing: 12

        // Recheck Button
        Rectangle {
          implicitHeight: 36
          implicitWidth: recheckTxt.implicitWidth + 24
          radius: 6
          color: recheckMouse.pressed ? Qt.rgba(255, 255, 255, 0.12) : (recheckMouse.containsMouse ? Qt.rgba(255, 255, 255, 0.08) : Qt.rgba(255, 255, 255, 0.04))
          border.color: depViewRoot.borderColor
          border.width: 1

          Text {
            id: recheckTxt
            anchors.centerIn: parent
            text: depViewRoot.isChecking ? "Checking..." : "↻ Recheck"
            color: depViewRoot.isChecking ? Qt.darker(depViewRoot.foreground, 2) : depViewRoot.foreground
            font.pixelSize: 11
            font.bold: true
          }

          MouseArea {
            id: recheckMouse
            anchors.fill: parent
            enabled: !depViewRoot.isChecking && !depViewRoot.isInstalling
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: depViewRoot.recheckRequested()
          }
        }

        // One-Click Install Button
        Rectangle {
          id: installBtn
          property bool hasMissing: depViewRoot.missingPackages.length > 0
          Layout.fillWidth: true
          implicitHeight: 36
          radius: 6
          color: {
            if (depViewRoot.isChecking || depViewRoot.isInstalling || !installBtn.hasMissing) {
              return Qt.rgba(255, 255, 255, 0.08)
            }
            return installMouse.pressed ? Qt.darker(depViewRoot.accent, 1.2) : (installMouse.containsMouse ? Qt.lighter(depViewRoot.accent, 1.1) : depViewRoot.accent)
          }

          Text {
            id: installBtnText
            anchors.centerIn: parent
            text: {
              if (depViewRoot.isChecking) return "Checking Dependencies..."
              if (depViewRoot.isInstalling) return "Installing in Floating Terminal..."
              if (installBtn.hasMissing) return "⚡ One-Click Install Missing Dependencies (" + depViewRoot.getInstallPackageNames().join(", ") + ")"
              return "✓ All Dependencies Installed"
            }
            color: {
              if (!installBtn.hasMissing && !depViewRoot.isChecking && !depViewRoot.isInstalling) return "#a6e3a1"
              if (depViewRoot.isChecking || depViewRoot.isInstalling) return Qt.darker(depViewRoot.foreground, 2)
              return "#ffffff"
            }
            font.pixelSize: 12
            font.bold: true
          }

          MouseArea {
            id: installMouse
            anchors.fill: parent
            enabled: installBtn.hasMissing && !depViewRoot.isChecking && !depViewRoot.isInstalling
            hoverEnabled: true
            cursorShape: (installBtn.hasMissing && !depViewRoot.isChecking && !depViewRoot.isInstalling) ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: depViewRoot.installRequested()
          }
        }
      }

      Text {
        text: "Automatically launches an Omarchy floating presentation terminal running paru / yay / pacman to install prerequisites."
        color: Qt.darker(depViewRoot.foreground, 2.2)
        font.pixelSize: 10
        horizontalAlignment: Text.AlignHCenter
        Layout.fillWidth: true
      }
    }
  }
}
