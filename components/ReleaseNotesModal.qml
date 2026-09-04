import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: releaseModalRoot

  property bool active: false
  property string version: ""
  property string releaseTitle: ""
  property string releaseNotes: ""
  property string releaseUrl: ""
  property bool isDownloadingCli: false
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  signal closeRequested()
  signal updateRequested()

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.6)
  visible: active
  z: 100

  Keys.onEscapePressed: releaseModalRoot.closeRequested()

  function escapeHtml(text) {
    if (!text) return ""
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
  }

  function formatInlineMarkdown(text) {
    if (!text) return ""
    var escaped = escapeHtml(text)

    // Markdown link: [Title](url)
    escaped = escaped.replace(/\[([^\]]+)\]\((https?:\/\/[^\s\)]+)\)/g, function(match, title, url) {
      return "<a href='" + url + "' style='color: #60a5fa; text-decoration: underline;'>" + title + "</a>"
    })

    // GitHub PR link: https://github.com/.../pull/123 -> #123
    escaped = escaped.replace(/(https?:\/\/github\.com\/[^\/\s]+\/[^\/\s]+\/pull\/(\d+))/g, function(match, url, prNum) {
      return "<a href='" + url + "' style='color: #60a5fa; text-decoration: underline;'>#" + prNum + "</a>"
    })

    // GitHub Commit link: https://github.com/.../commit/abcdef123 -> abcdef1
    escaped = escaped.replace(/(https?:\/\/github\.com\/[^\/\s]+\/[^\/\s]+\/commit\/([a-f0-9]{7,40}))/g, function(match, url, sha) {
      return "<a href='" + url + "' style='color: #60a5fa; text-decoration: underline; font-family: monospace;'>" + sha.substring(0, 7) + "</a>"
    })

    // GitHub Compare link: https://github.com/.../compare/v1...v2 -> v1...v2
    escaped = escaped.replace(/(https?:\/\/github\.com\/[^\/\s]+\/[^\/\s]+\/compare\/([^\s\<\>\)]+))/g, function(match, url, range) {
      return "<a href='" + url + "' style='color: #60a5fa; text-decoration: underline;'>" + range + "</a>"
    })

    // Other plain URLs
    escaped = escaped.replace(/(^|[\s\(])(https?:\/\/[^\s<\)]+)/g, function(match, prefix, url) {
      return prefix + "<a href='" + url + "' style='color: #60a5fa; text-decoration: underline;'>" + url + "</a>"
    })

    // Bold: **text**
    escaped = escaped.replace(/\*\*([^*]+)\*\*/g, "<b style='color: #ffffff;'>$1</b>")

    // Inline code: `code`
    escaped = escaped.replace(/`([^`]+)`/g, "<span style='background-color: rgba(255,255,255,0.12); color: #f1f5f9; font-family: monospace; font-size: 10px; padding: 1px 3px;'>$1</span>")

    // GitHub user/bot mentions: @user
    escaped = escaped.replace(/@([a-zA-Z0-9_-]+(?:\[bot\])?)/g, "<span style='color: #93c5fd; font-weight: 500;'>@$1</span>")

    return escaped
  }

  function renderMarkdown(raw) {
    if (!raw || !raw.trim()) {
      return "<div style='color: #94a3b8; font-size: 11px;'>No release notes found for this version.</div>"
    }

    var lines = raw.split("\n")
    var html = ""

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim()
      if (!line) continue

      // Headers: #, ##, ###, ####
      if (line.match(/^#{1,4}\s+/)) {
        var hText = line.replace(/^#{1,4}\s+/, "")
        html += "<div style='font-size: 13px; font-weight: bold; color: #ffffff; margin-top: 8px; margin-bottom: 12px;'>" + escapeHtml(hText) + "</div>"
        continue
      }

      // Unordered list items: * or -
      if (line.match(/^[\*\-]\s+/)) {
        var itemText = line.replace(/^[\*\-]\s+/, "")
        html += "<div style='margin-top: 3px; margin-bottom: 4px; color: #cbd5e1; font-size: 11px; line-height: 1.4;'><span style='color: #60a5fa;'>• </span>" + formatInlineMarkdown(itemText) + "</div>"
        continue
      }

      // Ordered list items: 1. or 1)
      var numMatch = line.match(/^(\d+[\.\)])\s+/)
      if (numMatch) {
        var numPrefix = numMatch[1]
        var numItemText = line.substring(numPrefix.length).trim()
        html += "<div style='margin-top: 3px; margin-bottom: 4px; color: #cbd5e1; font-size: 11px; line-height: 1.4;'><span style='color: #60a5fa; font-weight: 600;'>" + numPrefix + " </span>" + formatInlineMarkdown(numItemText) + "</div>"
        continue
      }

      // Normal paragraph
      html += "<div style='margin-top: 12px; margin-bottom: 4px; color: #cbd5e1; font-size: 11px; line-height: 1.4;'>" + formatInlineMarkdown(line) + "</div>"
    }

    return html
  }

  MouseArea {
    anchors.fill: parent
    onClicked: releaseModalRoot.closeRequested()
  }

  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 560)
    height: Math.min(parent.height - 48, 460)
    radius: 8
    color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
    border.color: releaseModalRoot.borderColor
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
          text: "\uf15c"
          font.family: releaseModalRoot.fontFamily
          font.pixelSize: 14
          color: releaseModalRoot.accent
        }

        Text {
          text: releaseModalRoot.releaseTitle ? ("Release: " + releaseModalRoot.releaseTitle) : ("Release Notes (v" + releaseModalRoot.version + ")")
          color: releaseModalRoot.foreground
          font.pixelSize: 13
          font.weight: Font.DemiBold
          elide: Text.ElideRight
          Layout.fillWidth: true
        }

        Rectangle {
          implicitWidth: 22
          implicitHeight: 22
          radius: 4
          color: closeMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : "transparent"

          Text {
            anchors.centerIn: parent
            text: "\uf00d"
            font.family: releaseModalRoot.fontFamily
            font.pixelSize: 12
            color: releaseModalRoot.foreground
          }

          MouseArea {
            id: closeMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: releaseModalRoot.closeRequested()
          }
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: releaseModalRoot.borderColor
      }

      // Scrollable Release Notes Content
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        TextEdit {
          id: notesTextEdit
          width: modalCard.width - 32
          text: releaseModalRoot.renderMarkdown(releaseModalRoot.releaseNotes)
          textFormat: Text.RichText
          color: releaseModalRoot.foreground
          font.pixelSize: 11
          font.family: "sans-serif"
          wrapMode: Text.Wrap
          readOnly: true
          selectByMouse: true
          cursorVisible: false
          selectionColor: releaseModalRoot.accent
          onLinkActivated: function(link) {
            Qt.openUrlExternally(link)
          }
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: releaseModalRoot.borderColor
      }

      // Footer Actions
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        // Open in Browser Button
        Rectangle {
          visible: Boolean(releaseModalRoot.releaseUrl)
          implicitHeight: 26
          implicitWidth: extBtnRow.implicitWidth + 14
          radius: 4
          color: extMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(0, 0, 0, 0.2)
          border.color: releaseModalRoot.borderColor
          border.width: 1

          RowLayout {
            id: extBtnRow
            anchors.centerIn: parent
            spacing: 5

            Text {
              text: "\uf08e"
              font.family: releaseModalRoot.fontFamily
              color: Qt.darker(releaseModalRoot.foreground, 1.4)
              font.pixelSize: 10
            }

            Text {
              text: "Open on GitHub"
              color: releaseModalRoot.foreground
              font.pixelSize: 10
              font.weight: Font.Medium
            }
          }

          MouseArea {
            id: extMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (releaseModalRoot.releaseUrl) {
                Qt.openUrlExternally(releaseModalRoot.releaseUrl)
              }
            }
          }
        }

        Item { Layout.fillWidth: true }

        // Close Button
        Rectangle {
          implicitHeight: 26
          implicitWidth: closeBtnText.implicitWidth + 16
          radius: 4
          color: Qt.rgba(1, 1, 1, 0.08)
          border.color: releaseModalRoot.borderColor
          border.width: 1

          Text {
            id: closeBtnText
            anchors.centerIn: parent
            text: "Close"
            color: releaseModalRoot.foreground
            font.pixelSize: 10
            font.weight: Font.Medium
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: releaseModalRoot.closeRequested()
          }
        }

        // Update Engine Button
        Rectangle {
          implicitHeight: 26
          implicitWidth: upBtnText.implicitWidth + 16
          radius: 4
          color: "#22c55e"

          Text {
            id: upBtnText
            anchors.centerIn: parent
            text: releaseModalRoot.isDownloadingCli ? "Updating..." : ("Update to v" + releaseModalRoot.version)
            color: "#ffffff"
            font.pixelSize: 10
            font.weight: Font.Medium
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            enabled: !releaseModalRoot.isDownloadingCli
            onClicked: releaseModalRoot.updateRequested()
          }
        }
      }
    }
  }
}
