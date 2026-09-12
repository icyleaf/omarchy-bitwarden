import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io

FloatingWindow {
  id: root
  title: "Omarchy Bitwarden - 依赖检测"
  visible: true
  implicitWidth: 600
  implicitHeight: 480
  color: "#181825"

  // -------------------------------------------------------------
  // Dependencies Data
  // -------------------------------------------------------------
  ListModel {
    id: dependencyModel

    ListElement {
      pkgName: "omawarden"
      required: true
      title: "Omarchy Bitwarden 后台守护进程与 Rust 引擎"
      description: "专为 Omarchy 设计的高性能纯 Rust 引擎，通过常驻 Unix Socket IPC 提供端到端解密、TOTP 生成与高速凭据检索（分发自 Pacman / AUR）"
      status: "idle"     // "idle" | "checking" | "installed" | "missing"
      version: ""
    }

    ListElement {
      pkgName: "libsecret"
      required: true
      title: "系统密钥环与 Secret Service 支持"
      description: "提供 secret-tool 命令行工具，用于系统密钥环（Keyring）的会话令牌与 API 凭据安全存储与静默续期"
      status: "idle"
      version: ""
    }

    ListElement {
      pkgName: "wl-clipboard"
      required: true
      title: "Wayland 原生剪贴板管理"
      description: "提供 wl-copy / wl-paste 工具，用于安全复制密码、用户名、动态 TOTP 验证码及阅后即焚自动清除"
      status: "idle"
      version: ""
    }
  }

  // -------------------------------------------------------------
  // Checking & Installation Logic
  // -------------------------------------------------------------
  property bool isChecking: false
  property var missingPackages: []

  function checkAllDependencies() {
    missingPackages = []
    var names = []
    for (var i = 0; i < dependencyModel.count; i++) {
      dependencyModel.setProperty(i, "status", "checking")
      dependencyModel.setProperty(i, "version", "")
      names.push(dependencyModel.get(i).pkgName)
    }

    root.isChecking = true
    pacmanCheckProc.running = false
    pacmanCheckProc.command = ["pacman", "-Q"].concat(names)
    pacmanCheckProc.running = true
  }

  function installMissingPackages() {
    if (root.missingPackages.length === 0) return

    var pkgs = root.missingPackages.join(" ")
    // Automatically use AUR helper (paru / yay) if present, or fallback to sudo pacman
    var installCmd = "if command -v paru >/dev/null 2>&1; then paru -S --needed " + pkgs +
                     "; elif command -v yay >/dev/null 2>&1; then yay -S --needed " + pkgs +
                     "; else sudo pacman -S --needed " + pkgs + "; fi"

    // Launch floating terminal with Omarchy presentation wrapper
    installProc.running = false
    installProc.command = ["omarchy-launch-floating-terminal-with-presentation", installCmd]
    installProc.running = true
  }

  // Package check process
  Process {
    id: pacmanCheckProc
    running: false

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var output = (text || "").trim()
        if (!output) return

        var lines = output.split("\n")
        for (var i = 0; i < lines.length; i++) {
          var match = lines[i].trim().match(/^(\S+)\s+(.+)$/)
          if (match) {
            var name = match[1]
            var ver = match[2]
            for (var j = 0; j < dependencyModel.count; j++) {
              if (dependencyModel.get(j).pkgName === name) {
                dependencyModel.setProperty(j, "status", "installed")
                dependencyModel.setProperty(j, "version", ver)
                break
              }
            }
          }
        }
      }
    }

    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var errOutput = (text || "").trim()
        if (!errOutput) return

        var lines = errOutput.split("\n")
        for (var i = 0; i < lines.length; i++) {
          var match = lines[i].trim().match(/package '([^']+)' was not found/)
          if (match) {
            var missingName = match[1]
            for (var j = 0; j < dependencyModel.count; j++) {
              if (dependencyModel.get(j).pkgName === missingName) {
                dependencyModel.setProperty(j, "status", "missing")
                dependencyModel.setProperty(j, "version", "")
                break
              }
            }
          }
        }
      }
    }

    onExited: function(code) {
      root.isChecking = false
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
      root.missingPackages = missing
    }
  }

  // Package installation process
  Process {
    id: installProc
    running: false
    onExited: function(code) {
      // Recheck dependencies when the installer terminal window closes
      root.checkAllDependencies()
    }
  }

  Component.onCompleted: {
    checkAllDependencies()
  }

  // -------------------------------------------------------------
  // UI Presentation
  // -------------------------------------------------------------
  FocusScope {
    id: mainScope
    anchors.fill: parent
    anchors.margins: 24
    focus: true

    Shortcut {
      sequence: "Escape"
      onActivated: Qt.quit()
    }

    ColumnLayout {
      anchors.fill: parent
      spacing: 16

      // Header Bar
      RowLayout {
        Layout.fillWidth: true
        spacing: 12

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 4

          RowLayout {
            spacing: 8
            Text {
              text: "Omarchy Bitwarden"
              color: "#cdd6f4"
              font.pixelSize: 18
              font.bold: true
            }

            Rectangle {
              height: 20
              width: tagText.implicitWidth + 12
              radius: 4
              color: "#313244"
              Text {
                id: tagText
                anchors.centerIn: parent
                text: "依赖检测"
                color: "#89b4fa"
                font.pixelSize: 11
                font.bold: true
              }
            }
          }

          Text {
            text: "检查插件运行所需的 pacman / AUR 系统依赖包及安装状态"
            color: "#a6adc8"
            font.pixelSize: 12
          }
        }

        Button {
          id: refreshBtn
          text: root.isChecking ? "检测中..." : "↻ 重新检查"
          enabled: !root.isChecking
          onClicked: root.checkAllDependencies()

          background: Rectangle {
            color: refreshBtn.down ? "#45475a" : (refreshBtn.hovered ? "#585b70" : "#313244")
            radius: 6
            border.color: "#6c7086"
            border.width: 1
          }
          contentItem: Text {
            text: refreshBtn.text
            color: root.isChecking ? "#6c7086" : "#cdd6f4"
            font.pixelSize: 12
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
          }
        }
      }

      // Dependencies List
      Rectangle {
        Layout.fillWidth: true
        Layout.fillHeight: true
        color: "#1e1e2e"
        radius: 10
        border.color: "#313244"
        border.width: 1
        clip: true

        ListView {
          id: listView
          anchors.fill: parent
          anchors.margins: 10
          spacing: 10
          model: dependencyModel

          delegate: Rectangle {
            width: listView.width
            implicitHeight: cardLayout.implicitHeight + 20
            radius: 8
            color: model.status === "installed" ? "#1b2b25" : (model.status === "missing" ? "#2b1c20" : "#24273a")
            border.color: model.status === "installed" ? "#2e6f56" : (model.status === "missing" ? "#7c2f38" : "#363a4f")
            border.width: 1

            RowLayout {
              id: cardLayout
              anchors.fill: parent
              anchors.margins: 12
              spacing: 12

              // State Indicator Dot
              Rectangle {
                width: 12
                height: 12
                radius: 6
                color: {
                  if (model.status === "installed") return "#a6e3a1"
                  if (model.status === "missing") return "#f38ba8"
                  if (model.status === "checking") return "#f9e2af"
                  return "#6c7086"
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
                    color: "#cdd6f4"
                    font.pixelSize: 14
                    font.bold: true
                  }

                  Rectangle {
                    height: 18
                    width: reqText.implicitWidth + 8
                    radius: 3
                    color: "#45475a"
                    Text {
                      id: reqText
                      anchors.centerIn: parent
                      text: "核心依赖"
                      color: "#f9e2af"
                      font.pixelSize: 10
                      font.bold: true
                    }
                  }

                  Text {
                    text: model.version ? ("v" + model.version) : ""
                    color: "#a6e3a1"
                    font.pixelSize: 12
                    font.bold: true
                    visible: model.status === "installed" && model.version.length > 0
                  }
                }

                Text {
                  text: model.title
                  color: "#bac2de"
                  font.pixelSize: 12
                  font.bold: true
                }

                Text {
                  text: model.description
                  color: "#a6adc8"
                  font.pixelSize: 11
                  wrapMode: Text.WordWrap
                  Layout.fillWidth: true
                }
              }

              // Status Badge
              Rectangle {
                implicitWidth: statusText.implicitWidth + 16
                implicitHeight: 26
                radius: 13
                color: {
                  if (model.status === "installed") return "#1e3a2f"
                  if (model.status === "missing") return "#3e1e24"
                  if (model.status === "checking") return "#3e3820"
                  return "#313244"
                }

                Text {
                  id: statusText
                  anchors.centerIn: parent
                  text: {
                    if (model.status === "installed") return "✓ 已就绪"
                    if (model.status === "missing") return "✗ 未安装"
                    if (model.status === "checking") return "⏳ 检测中"
                    return "就绪"
                  }
                  color: {
                    if (model.status === "installed") return "#a6e3a1"
                    if (model.status === "missing") return "#f38ba8"
                    if (model.status === "checking") return "#f9e2af"
                    return "#bac2de"
                  }
                  font.pixelSize: 11
                  font.bold: true
                }
              }
            }
          }
        }
      }

      // Bottom Bar: One-Click Install & Status
      RowLayout {
        Layout.fillWidth: true
        spacing: 12

        Text {
          text: "按 Esc 退出窗口"
          color: "#585b70"
          font.pixelSize: 12
        }

        Item { Layout.fillWidth: true }

        Button {
          id: installBtn
          property bool hasMissing: root.missingPackages.length > 0

          text: {
            if (root.isChecking) return "正在检测中..."
            if (hasMissing) return "⚡ 一键安装缺失依赖 (" + root.missingPackages.join(", ") + ")"
            return "✓ 所有依赖均已就绪"
          }

          enabled: hasMissing && !root.isChecking && !installProc.running
          onClicked: root.installMissingPackages()

          background: Rectangle {
            implicitHeight: 38
            implicitWidth: installBtnText.implicitWidth + 28
            radius: 8
            color: {
              if (!installBtn.hasMissing) return "#2e473b"
              return installBtn.down ? "#74c7ec" : (installBtn.hovered ? "#89b4fa" : "#89b4fa")
            }
          }

          contentItem: Text {
            id: installBtnText
            text: installBtn.text
            color: installBtn.hasMissing ? "#11111b" : "#a6e3a1"
            font.pixelSize: 13
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
          }
        }
      }
    }
  }
}
