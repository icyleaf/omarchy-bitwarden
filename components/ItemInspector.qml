import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ScrollView {
  id: inspectorRoot

  property var item: null
  property var currentTotp: ({ code: "", ttl: 30, period: 30 })
  property bool showPasswordRevealed: false
  property bool showPrivateKeyRevealed: false
  property bool showCardNumberRevealed: false
  property bool showCardCodeRevealed: false
  property var activeAttachmentPreview: null
  property string loadingAttachmentId: ""
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  onItemChanged: {
    showCardNumberRevealed = false
    showCardCodeRevealed = false
  }

  signal copyRequested(string text, bool isSensitive, string label)
  signal viewAttachmentRequested(var item, var att)
  signal downloadAttachmentRequested(var item, var att)
  signal closePreviewRequested()
  signal togglePasswordRevealed()
  signal togglePrivateKeyRevealed()

  clip: true
  ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
  ScrollBar.vertical: ScrollBar {
    id: inspVScrollBar
    policy: ScrollBar.AsNeeded
    contentItem: Rectangle {
      implicitWidth: 4
      radius: 2
      color: inspVScrollBar.pressed ? Qt.rgba(1, 1, 1, 0.4) : (inspVScrollBar.hovered ? Qt.rgba(1, 1, 1, 0.25) : Qt.rgba(1, 1, 1, 0.15))
    }
  }

  function getHostname(uri) {
    if (!uri) return ""
    var str = String(uri).trim()
    var match = str.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?#]+)/i)
    return match ? match[1] : ""
  }

  function getFaviconUrl(item) {
    if (!item) return ""
    if (item.type_name !== "login" && item.category !== "login") return ""
    if (!item.login || !item.login.uris || item.login.uris.length === 0) return ""
    for (var i = 0; i < item.login.uris.length; i++) {
      var u = item.login.uris[i]
      var uriStr = (typeof u === "string") ? u : (u && u.uri ? u.uri : "")
      var domain = getHostname(uriStr)
      if (domain && domain.indexOf(".") !== -1) {
        return "https://icons.bitwarden.net/" + domain + "/icon.png"
      }
    }
    return ""
  }

  function getItemIcon(item) {
    if (!item) return "\uf084"
    if (item.type_name === "card") return "\uf09d"
    if (item.type_name === "identity") return "\uf2c2"
    if (item.type_name === "note") return "\uf0f6"
    if (item.type_name === "ssh_key" || item.category === "ssh_key") return "\uf084"
    return "\uf084"
  }

  function formatMaskedCardNumber(num) {
    if (!num) return "•••• •••• •••• ••••"
    var clean = String(num).replace(/\s+/g, "")
    if (clean.length > 4) {
      var last4 = clean.slice(-4)
      return "•••• •••• •••• " + last4
    }
    return "•••• •••• •••• ••••"
  }

  function isAttachmentPreviewable(filename) {
    if (!filename) return false
    var dotIdx = filename.lastIndexOf(".")
    if (dotIdx === -1) return false
    var ext = filename.slice(dotIdx + 1).toLowerCase()
    var previewableExts = [
      "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico",
      "txt", "md", "markdown", "json", "yaml", "yml", "toml", "csv", "tsv", "log",
      "sh", "bash", "zsh", "py", "js", "ts", "jsx", "tsx", "html", "htm", "css", "scss", "sass", "less",
      "xml", "conf", "config", "ini", "env", "pem", "key", "pub", "crt", "cer",
      "diff", "patch", "sql", "lua", "c", "cpp", "cc", "cxx", "h", "hpp", "rs", "go", "java", "kt", "kts", "rb", "php"
    ]
    return previewableExts.indexOf(ext) !== -1
  }

  function getAttachmentIcon(filename) {
    if (!filename) return "\uf15b"
    var ext = filename.split(".").pop().toLowerCase()
    if (["png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico"].indexOf(ext) !== -1) return "\uf03e"
    if (["txt", "md", "json", "yaml", "yml", "toml", "csv", "log", "sh", "py", "js", "ts", "html", "css", "xml", "conf", "ini", "env", "sql", "rs", "go", "c", "cpp"].indexOf(ext) !== -1) return "\uf0f6"
    if (["pdf"].indexOf(ext) !== -1) return "\uf1c1"
    if (["zip", "tar", "gz", "7z", "rar"].indexOf(ext) !== -1) return "\uf1c6"
    return "\uf15b"
  }

  function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return "0 B"
    var k = 1024
    var sizes = ["B", "KB", "MB", "GB"]
    var i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
  }

  ColumnLayout {
    width: inspectorRoot.width - 16
    spacing: 12

    // ----------------------------------------------------
    // 1. ATTACHMENT FULL PREVIEW OVERLAY (If active)
    // ----------------------------------------------------
    ColumnLayout {
      visible: inspectorRoot.activeAttachmentPreview !== null
      Layout.fillWidth: true
      spacing: 10

      // Preview Toolbar
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Rectangle {
          implicitHeight: 24
          implicitWidth: backBtnRow.implicitWidth + 10
          radius: 4
          color: backMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
          border.color: inspectorRoot.borderColor
          border.width: 1

          RowLayout {
            id: backBtnRow
            anchors.centerIn: parent
            spacing: 4
            Text {
              text: "\uf060"
              font.family: inspectorRoot.fontFamily
              color: inspectorRoot.foreground
              font.pixelSize: 10
            }
            Text { text: "Back to Item"; color: inspectorRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
          }
          MouseArea {
            id: backMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: inspectorRoot.closePreviewRequested()
          }
        }

        Text {
          text: inspectorRoot.getAttachmentIcon(inspectorRoot.activeAttachmentPreview ? inspectorRoot.activeAttachmentPreview.filename : "")
          font.family: inspectorRoot.fontFamily
          font.pixelSize: 14
          color: inspectorRoot.accent
        }

        Text {
          text: inspectorRoot.activeAttachmentPreview ? (inspectorRoot.activeAttachmentPreview.filename || "Attachment") : ""
          color: inspectorRoot.foreground
          font.pixelSize: 12
          font.weight: Font.Medium
          elide: Text.ElideRight
          Layout.fillWidth: true
        }

        // Open Externally
        GhostIconButton {
          iconText: "\uf08e"
          tooltip: "Open file externally"
          onClicked: {
            if (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.path) {
              Qt.openUrlExternally("file://" + inspectorRoot.activeAttachmentPreview.path)
            }
          }
        }
      }

      Rectangle { Layout.fillWidth: true; height: 1; color: inspectorRoot.borderColor }

      // Preview Content: Image
      Item {
        visible: Boolean(inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.is_image)
        Layout.fillWidth: true
        Layout.preferredHeight: 320

        Image {
          anchors.fill: parent
          anchors.margins: 4
          fillMode: Image.PreserveAspectFit
          source: (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.is_image) ? ("file://" + inspectorRoot.activeAttachmentPreview.path) : ""
          smooth: true
          asynchronous: true
        }
      }

      // Preview Content: Text / Code
      ColumnLayout {
        visible: Boolean(inspectorRoot.activeAttachmentPreview && !inspectorRoot.activeAttachmentPreview.is_image && inspectorRoot.activeAttachmentPreview.is_text)
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          Text {
            text: "Text Content Preview:"
            color: Qt.darker(inspectorRoot.foreground, 1.4)
            font.pixelSize: 11
          }
          Item { Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy text"
            onClicked: {
              if (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.text_content) {
                inspectorRoot.copyRequested(inspectorRoot.activeAttachmentPreview.text_content, false, "attachment text")
              }
            }
          }
        }

        Rectangle {
          Layout.fillWidth: true
          Layout.preferredHeight: 240
          radius: 4
          color: Qt.rgba(0, 0, 0, 0.3)
          border.color: inspectorRoot.borderColor
          border.width: 1

          ScrollView {
            anchors.fill: parent
            anchors.margins: 8
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            TextArea {
              readOnly: true
              wrapMode: Text.WrapAnywhere
              color: inspectorRoot.foreground
              font.pixelSize: 11
              font.family: "monospace"
              text: (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.text_content) ? inspectorRoot.activeAttachmentPreview.text_content : ""
              background: null
            }
          }
        }
      }

      // Preview Content: Binary / Non-previewable fallback
      ColumnLayout {
        visible: Boolean(inspectorRoot.activeAttachmentPreview && !inspectorRoot.activeAttachmentPreview.is_image && !inspectorRoot.activeAttachmentPreview.is_text)
        Layout.fillWidth: true
        spacing: 12
        Layout.topMargin: 20
        Layout.bottomMargin: 20

        Text {
          Layout.alignment: Qt.AlignHCenter
          text: "\uf15b"
          font.family: inspectorRoot.fontFamily
          font.pixelSize: 36
          color: Qt.darker(inspectorRoot.foreground, 1.8)
        }

        Text {
          Layout.alignment: Qt.AlignHCenter
          text: "Preview not available for this file format"
          color: Qt.darker(inspectorRoot.foreground, 1.4)
          font.pixelSize: 12
          font.weight: Font.Medium
        }

        Rectangle {
          Layout.alignment: Qt.AlignHCenter
          implicitHeight: 28
          implicitWidth: dlRow.implicitWidth + 20
          radius: 4
          color: dlMouse.containsMouse ? Qt.rgba(inspectorRoot.accent.r, inspectorRoot.accent.g, inspectorRoot.accent.b, 0.3) : Qt.rgba(inspectorRoot.accent.r, inspectorRoot.accent.g, inspectorRoot.accent.b, 0.15)
          border.color: inspectorRoot.accent
          border.width: 1

          RowLayout {
            id: dlRow
            anchors.centerIn: parent
            spacing: 6
            Text {
              text: "\uf019"
              font.family: inspectorRoot.fontFamily
              color: inspectorRoot.accent
              font.pixelSize: 12
            }
            Text {
              text: "Open or Save File"
              color: inspectorRoot.foreground
              font.pixelSize: 11
              font.weight: Font.Medium
            }
          }

          MouseArea {
            id: dlMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.path) {
                Qt.openUrlExternally("file://" + inspectorRoot.activeAttachmentPreview.path)
              }
            }
          }
        }
      }
    }

    // ----------------------------------------------------
    // 2. NORMAL ITEM INSPECTOR VIEW
    // ----------------------------------------------------
    ColumnLayout {
      visible: inspectorRoot.activeAttachmentPreview === null && inspectorRoot.item !== null
      Layout.fillWidth: true
      spacing: 12

      // Header: Icon + Name + Badges
      RowLayout {
        Layout.fillWidth: true
        spacing: 10

        Item {
          id: inspIconContainer
          Layout.preferredWidth: 24
          Layout.preferredHeight: 24

          property string favUrl: inspectorRoot.getFaviconUrl(inspectorRoot.item)

          Image {
            id: inspFaviconImg
            anchors.fill: parent
            asynchronous: true
            cache: true
            fillMode: Image.PreserveAspectFit
            source: inspIconContainer.favUrl
            visible: inspIconContainer.favUrl !== "" && status === Image.Ready
          }

          Text {
            anchors.centerIn: parent
            visible: !inspFaviconImg.visible
            text: inspectorRoot.getItemIcon(inspectorRoot.item)
            font.family: inspectorRoot.fontFamily
            font.pixelSize: 18
            color: Qt.darker(inspectorRoot.foreground, 1.3)
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: 3

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Text {
              text: inspectorRoot.item ? (inspectorRoot.item.name || "Untitled") : ""
              color: inspectorRoot.foreground
              font.pixelSize: 14
              font.weight: Font.DemiBold
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            // Monochrome Favorite Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.favorite)
              implicitHeight: 18
              implicitWidth: favRow.implicitWidth + 10
              radius: 3
              color: Qt.rgba(1, 1, 1, 0.08)
              border.color: Qt.rgba(1, 1, 1, 0.15)
              border.width: 1

              RowLayout {
                id: favRow
                anchors.centerIn: parent
                spacing: 3
                Text {
                  text: "\uf005"
                  font.family: inspectorRoot.fontFamily
                  font.pixelSize: 9
                  color: Qt.darker(inspectorRoot.foreground, 1.2)
                }
                Text {
                  text: "Favorite"
                  color: Qt.darker(inspectorRoot.foreground, 1.2)
                  font.pixelSize: 10
                  font.weight: Font.Medium
                }
              }
            }

            // Organization Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.organization_name)
              implicitHeight: 18
              implicitWidth: orgText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(0.9, 0.6, 0.2, 0.2)
              border.color: Qt.rgba(0.9, 0.6, 0.2, 0.5)
              border.width: 1

              Text {
                id: orgText
                anchors.centerIn: parent
                text: "\uf1ad " + (inspectorRoot.item ? (inspectorRoot.item.organization_name || "") : "")
                font.family: inspectorRoot.fontFamily
                color: "#fbbf24"
                font.pixelSize: 10
                font.weight: Font.Medium
              }
            }

            // Folder Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.folder_name)
              implicitHeight: 18
              implicitWidth: folderText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(0.4, 0.7, 1.0, 0.2)
              border.color: Qt.rgba(0.4, 0.7, 1.0, 0.5)
              border.width: 1

              Text {
                id: folderText
                anchors.centerIn: parent
                text: "\uf07b " + (inspectorRoot.item ? (inspectorRoot.item.folder_name || "") : "")
                font.family: inspectorRoot.fontFamily
                color: "#60a5fa"
                font.pixelSize: 10
                font.weight: Font.Medium
              }
            }
          }

          Text {
            text: inspectorRoot.item ? (inspectorRoot.item.sub_title || inspectorRoot.item.type_name || "Item") : ""
            color: Qt.darker(inspectorRoot.foreground, 1.6)
            font.pixelSize: 11
          }
        }
      }

      Rectangle { Layout.fillWidth: true; height: 1; color: inspectorRoot.borderColor }

      // --------------------------------------------------
      // LOGIN CREDENTIALS SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.login)
        Layout.fillWidth: true
        spacing: 8

        // Username
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.username)
          Layout.fillWidth: true
          spacing: 8

          Text { text: "Username:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.login) ? (inspectorRoot.item.login.username || "") : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.weight: Font.Medium
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy username"
            onClicked: inspectorRoot.copyRequested(inspectorRoot.item.login.username, false, "username")
          }
        }

        // Password
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.password)
          Layout.fillWidth: true
          spacing: 8

          Text { text: "Password:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: inspectorRoot.showPasswordRevealed ? (inspectorRoot.item.login.password || "") : "••••••••••••••••"
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: inspectorRoot.showPasswordRevealed ? "monospace" : "sans-serif"
            font.weight: Font.Medium
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: inspectorRoot.showPasswordRevealed ? "\uf070" : "\uf06e"
            tooltip: inspectorRoot.showPasswordRevealed ? "Hide password" : "Show password"
            onClicked: inspectorRoot.togglePasswordRevealed()
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy password"
            onClicked: inspectorRoot.copyRequested(inspectorRoot.item.login.password, true, "password")
          }
        }

        // Websites / URIs list
        Repeater {
          model: (inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.uris) ? inspectorRoot.item.login.uris : []

          RowLayout {
            id: uriRowItem
            Layout.fillWidth: true
            spacing: 8

            property string rawUri: (typeof modelData === "string") ? modelData : (modelData && modelData.uri ? modelData.uri : "")

            Text { text: (index === 0 ? "Website:" : ""); color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
            Text {
              text: uriRowItem.rawUri
              color: inspectorRoot.foreground
              font.pixelSize: 11
              font.weight: Font.Medium
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            GhostIconButton {
              iconText: "\uf08e"
              tooltip: "Open website"
              onClicked: {
                var u = uriRowItem.rawUri
                if (u && !u.match(/^https?:\/\//i)) u = "https://" + u
                Qt.openUrlExternally(u)
              }
            }

            GhostIconButton {
              iconText: "\uf0c5"
              tooltip: "Copy website URL"
              onClicked: inspectorRoot.copyRequested(uriRowItem.rawUri, false, "website URL")
            }
          }
        }

        // TOTP Countdown & Verification Code
        ColumnLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.totp)
          Layout.fillWidth: true
          spacing: 4

          RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Text { text: "TOTP Code:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
            Text {
              text: inspectorRoot.currentTotp.code || "Generating..."
              color: inspectorRoot.accent
              font.pixelSize: 13
              font.family: "monospace"
              font.weight: Font.Bold
              Layout.fillWidth: true
            }
            Text {
              text: (inspectorRoot.currentTotp.ttl || 30) + "s"
              color: (inspectorRoot.currentTotp.ttl > 5) ? Qt.darker(inspectorRoot.foreground, 1.5) : "#f87171"
              font.pixelSize: 10
            }
            GhostIconButton {
              iconText: "\uf0c5"
              tooltip: "Copy TOTP code"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.currentTotp.code, true, "TOTP code")
            }
          }

          // Progress Bar
          Rectangle {
            Layout.fillWidth: true
            height: 3
            radius: 2
            color: Qt.rgba(1, 1, 1, 0.1)

            Rectangle {
              height: parent.height
              radius: 2
              width: parent.width * ((inspectorRoot.currentTotp.ttl || 30) / (inspectorRoot.currentTotp.period || 30))
              color: (inspectorRoot.currentTotp.ttl > 5) ? inspectorRoot.accent : "#f87171"
            }
          }
        }
      }

      // --------------------------------------------------
      // CARD DETAILS SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.card)
        Layout.fillWidth: true
        spacing: 8

        // Cardholder
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.cardholderName)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Cardholder:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.card) ? (inspectorRoot.item.card.cardholderName || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy cardholder"
            onClicked: inspectorRoot.copyRequested(inspectorRoot.item.card.cardholderName, false, "cardholder name")
          }
        }

        // Card Brand
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.brand)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Brand:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.card) ? (inspectorRoot.item.card.brand || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }

        // Card Number (Protected)
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.number)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Card Number:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.card) ? (inspectorRoot.showCardNumberRevealed ? (inspectorRoot.item.card.number || "") : inspectorRoot.formatMaskedCardNumber(inspectorRoot.item.card.number)) : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: "monospace"
            font.weight: Font.Medium
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: inspectorRoot.showCardNumberRevealed ? "\uf070" : "\uf06e"
            tooltip: inspectorRoot.showCardNumberRevealed ? "Hide card number" : "Show card number"
            onClicked: inspectorRoot.showCardNumberRevealed = !inspectorRoot.showCardNumberRevealed
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy card number"
            onClicked: inspectorRoot.copyRequested(inspectorRoot.item.card.number, true, "card number")
          }
        }

        // Expires
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && (inspectorRoot.item.card.expMonth || inspectorRoot.item.card.expYear))
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Expires:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.card) ? ((inspectorRoot.item.card.expMonth || "") + " / " + (inspectorRoot.item.card.expYear || "")) : ""; color: inspectorRoot.foreground; font.pixelSize: 11; font.family: "monospace"; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy expiration date"
            onClicked: inspectorRoot.copyRequested((inspectorRoot.item.card.expMonth || "") + "/" + (inspectorRoot.item.card.expYear || ""), false, "expiration date")
          }
        }

        // Security Code / CVV (Protected)
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.code)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Security Code:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.card) ? (inspectorRoot.showCardCodeRevealed ? (inspectorRoot.item.card.code || "") : "•••") : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: "monospace"
            font.weight: Font.Medium
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: inspectorRoot.showCardCodeRevealed ? "\uf070" : "\uf06e"
            tooltip: inspectorRoot.showCardCodeRevealed ? "Hide CVV" : "Show CVV"
            onClicked: inspectorRoot.showCardCodeRevealed = !inspectorRoot.showCardCodeRevealed
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy CVV"
            onClicked: inspectorRoot.copyRequested(inspectorRoot.item.card.code, true, "CVV")
          }
        }
      }

      // --------------------------------------------------
      // IDENTITY DETAILS SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity)
        Layout.fillWidth: true
        spacing: 8

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && (inspectorRoot.item.identity.firstName || inspectorRoot.item.identity.lastName))
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Full Name:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.identity) ? [inspectorRoot.item.identity.title, inspectorRoot.item.identity.firstName, inspectorRoot.item.identity.middleName, inspectorRoot.item.identity.lastName].filter(Boolean).join(" ") : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy full name"
            onClicked: {
              var n = [inspectorRoot.item.identity.title, inspectorRoot.item.identity.firstName, inspectorRoot.item.identity.middleName, inspectorRoot.item.identity.lastName].filter(Boolean).join(" ")
              inspectorRoot.copyRequested(n, false, "full name")
            }
          }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && inspectorRoot.item.identity.email)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Email:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.identity) ? (inspectorRoot.item.identity.email || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy email"
            onClicked: { if (inspectorRoot.item && inspectorRoot.item.identity) inspectorRoot.copyRequested(inspectorRoot.item.identity.email, false, "email") }
          }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && inspectorRoot.item.identity.phone)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Phone:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.identity) ? (inspectorRoot.item.identity.phone || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy phone"
            onClicked: { if (inspectorRoot.item && inspectorRoot.item.identity) inspectorRoot.copyRequested(inspectorRoot.item.identity.phone, false, "phone number") }
          }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && (inspectorRoot.item.identity.address1 || inspectorRoot.item.identity.city))
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Address:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.identity) ? [inspectorRoot.item.identity.address1, inspectorRoot.item.identity.address2, inspectorRoot.item.identity.city, inspectorRoot.item.identity.state, inspectorRoot.item.identity.postalCode, inspectorRoot.item.identity.country].filter(Boolean).join(", ") : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy address"
            onClicked: {
              var a = [inspectorRoot.item.identity.address1, inspectorRoot.item.identity.address2, inspectorRoot.item.identity.city, inspectorRoot.item.identity.state, inspectorRoot.item.identity.postalCode, inspectorRoot.item.identity.country].filter(Boolean).join(", ")
              inspectorRoot.copyRequested(a, false, "address")
            }
          }
        }
      }

      // --------------------------------------------------
      // SECURE NOTE SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.notes)
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          Text { text: "Notes:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11 }
          Item { Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy notes"
            onClicked: { if (inspectorRoot.item) inspectorRoot.copyRequested(inspectorRoot.item.notes, false, "notes") }
          }
        }

        Rectangle {
          Layout.fillWidth: true
          implicitHeight: Math.min(notesText.implicitHeight + 16, 160)
          radius: 4
          color: Qt.rgba(0, 0, 0, 0.25)
          border.color: inspectorRoot.borderColor
          border.width: 1

          ScrollView {
            anchors.fill: parent
            anchors.margins: 8
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            Text {
              id: notesText
              text: inspectorRoot.item ? (inspectorRoot.item.notes || "") : ""
              color: inspectorRoot.foreground
              font.pixelSize: 11
              wrapMode: Text.WrapAnywhere
            }
          }
        }
      }

      // Empty Secure Note Placeholder
      Rectangle {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.type_name === "note" && !inspectorRoot.item.notes && (!inspectorRoot.item.fields || inspectorRoot.item.fields.length === 0) && (!inspectorRoot.item.attachments || inspectorRoot.item.attachments.length === 0))
        Layout.fillWidth: true
        height: 60
        radius: 4
        color: Qt.rgba(0, 0, 0, 0.15)
        border.color: inspectorRoot.borderColor
        border.width: 1

        RowLayout {
          anchors.centerIn: parent
          spacing: 4
          Text {
            text: "\uf0f6"
            font.family: inspectorRoot.fontFamily
            color: Qt.darker(inspectorRoot.foreground, 1.8)
            font.pixelSize: 11
          }
          Text {
            text: "This secure note has no text or custom fields."
            color: Qt.darker(inspectorRoot.foreground, 1.8)
            font.pixelSize: 11
          }
        }
      }

      // --------------------------------------------------
      // CUSTOM FIELDS SECTION (Weakened subtle borders)
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.fields && inspectorRoot.item.fields.length > 0)
        Layout.fillWidth: true
        spacing: 6

        Text {
          text: "Custom Fields (" + (inspectorRoot.item && inspectorRoot.item.fields ? inspectorRoot.item.fields.length : 0) + "):"
          color: Qt.darker(inspectorRoot.foreground, 1.5)
          font.pixelSize: 11
        }

        Repeater {
          model: (inspectorRoot.item && inspectorRoot.item.fields) ? inspectorRoot.item.fields : []

          Rectangle {
            id: customFieldCard
            Layout.fillWidth: true
            height: 36
            radius: 4
            color: Qt.rgba(0, 0, 0, 0.15)
            border.color: Qt.rgba(1, 1, 1, 0.04)
            border.width: 1

            property bool isHiddenField: Boolean(modelData && modelData.type === 1)
            property bool isRevealed: false

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: 10
              anchors.rightMargin: 10
              spacing: 8

              Text {
                text: (modelData.name || "Field") + ":"
                color: Qt.darker(inspectorRoot.foreground, 1.5)
                font.pixelSize: 11
                Layout.preferredWidth: Math.min(implicitWidth, 120)
                elide: Text.ElideRight
              }

              Text {
                text: (modelData.type === 1 && !customFieldCard.isRevealed) ? "••••••••••••••••" : (modelData.value || "")
                color: inspectorRoot.foreground
                font.pixelSize: 11
                font.family: (modelData.type === 1) ? "monospace" : "sans-serif"
                elide: Text.ElideRight
                Layout.fillWidth: true
              }

              // Ghost Reveal Button (for hidden custom fields)
              GhostIconButton {
                visible: modelData.type === 1
                iconText: customFieldCard.isRevealed ? "\uf070" : "\uf06e"
                tooltip: customFieldCard.isRevealed ? "Hide field" : "Show field"
                onClicked: customFieldCard.isRevealed = !customFieldCard.isRevealed
              }

              // Ghost Copy Button
              GhostIconButton {
                iconText: "\uf0c5"
                tooltip: "Copy field value"
                onClicked: inspectorRoot.copyRequested(modelData.value || "", modelData.type === 1, modelData.name || "field")
              }
            }
          }
        }
      }

      // --------------------------------------------------
      // SSH KEY SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key)
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.key_type)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Key Type:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.ssh_key) ? (inspectorRoot.item.ssh_key.key_type || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.fingerprint)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Fingerprint:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item && inspectorRoot.item.ssh_key) ? (inspectorRoot.item.ssh_key.fingerprint || "") : ""; color: inspectorRoot.foreground; font.pixelSize: 11; font.family: "monospace"; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy fingerprint"
            onClicked: { if (inspectorRoot.item && inspectorRoot.item.ssh_key) inspectorRoot.copyRequested(inspectorRoot.item.ssh_key.fingerprint, false, "fingerprint") }
          }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.public_key)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Public Key:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: "Available"; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy public key"
            onClicked: { if (inspectorRoot.item && inspectorRoot.item.ssh_key) inspectorRoot.copyRequested(inspectorRoot.item.ssh_key.public_key, false, "SSH public key") }
          }
        }

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.private_key)
          Layout.fillWidth: true
          spacing: 8
          Text { text: "Private Key:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.showPrivateKeyRevealed ? "Revealed" : "Encrypted (Hidden)"; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          GhostIconButton {
            iconText: inspectorRoot.showPrivateKeyRevealed ? "\uf070" : "\uf06e"
            tooltip: inspectorRoot.showPrivateKeyRevealed ? "Hide private key" : "Show private key"
            onClicked: inspectorRoot.togglePrivateKeyRevealed()
          }
          GhostIconButton {
            iconText: "\uf0c5"
            tooltip: "Copy private key"
            onClicked: { if (inspectorRoot.item && inspectorRoot.item.ssh_key) inspectorRoot.copyRequested(inspectorRoot.item.ssh_key.private_key, true, "SSH private key") }
          }
        }
      }

      // --------------------------------------------------
      // ATTACHMENTS LIST SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.attachments && inspectorRoot.item.attachments.length > 0)
        Layout.fillWidth: true
        spacing: 6

        Text {
          text: "Attachments (" + (inspectorRoot.item ? (inspectorRoot.item.attachments ? inspectorRoot.item.attachments.length : 0) : 0) + "):"
          color: Qt.darker(inspectorRoot.foreground, 1.5)
          font.pixelSize: 11
        }

        Repeater {
          model: (inspectorRoot.item && inspectorRoot.item.attachments) ? inspectorRoot.item.attachments : []

          Rectangle {
            Layout.fillWidth: true
            height: 38
            radius: 4
            color: Qt.rgba(0, 0, 0, 0.2)
            border.color: inspectorRoot.borderColor
            border.width: 1

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              spacing: 8

              Text {
                text: inspectorRoot.getAttachmentIcon(modelData.fileName)
                font.family: inspectorRoot.fontFamily
                font.pixelSize: 14
                color: Qt.darker(inspectorRoot.foreground, 1.4)
              }

              ColumnLayout {
                Layout.fillWidth: true
                spacing: 1

                Text {
                  text: modelData.fileName || "attachment"
                  color: inspectorRoot.foreground
                  font.pixelSize: 11
                  font.weight: Font.Medium
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                }
                Text {
                  text: modelData.sizeName || inspectorRoot.formatFileSize(modelData.size)
                  color: Qt.darker(inspectorRoot.foreground, 1.8)
                  font.pixelSize: 10
                }
              }

              // View / Preview Ghost Button (Only for previewable attachments)
              GhostIconButton {
                visible: inspectorRoot.isAttachmentPreviewable(modelData.fileName)
                iconText: (inspectorRoot.loadingAttachmentId === (modelData.id || modelData.fileName)) ? "\uf021" : "\uf06e"
                tooltip: "Preview attachment"
                onClicked: inspectorRoot.viewAttachmentRequested(inspectorRoot.item, modelData)
              }

              // Download Ghost Button
              GhostIconButton {
                iconText: "\uf019"
                tooltip: "Download attachment"
                onClicked: inspectorRoot.downloadAttachmentRequested(inspectorRoot.item, modelData)
              }
            }
          }
        }
      }
    }
  }
}
