import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ScrollView {
  id: inspectorRoot

  property var item: null
  property var currentTotp: ({ code: "", ttl: 30, period: 30 })
  property bool showPasswordRevealed: false
  property bool showPrivateKeyRevealed: false
  property var activeAttachmentPreview: null
  property string loadingAttachmentId: ""
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color border: Qt.rgba(1, 1, 1, 0.1)

  signal copyRequested(string text, bool isSensitive, string label)
  signal viewAttachmentRequested(var item, var att)
  signal downloadAttachmentRequested(var item, var att)
  signal closePreviewRequested()
  signal togglePasswordRevealed()
  signal togglePrivateKeyRevealed()

  clip: true
  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded; active: true }

  function getItemIcon(item) {
    if (!item) return "🔑"
    if (item.type_name === "card") return "💳"
    if (item.type_name === "identity") return "🪪"
    if (item.type_name === "note") return "📝"
    if (item.type_name === "ssh_key" || item.category === "ssh_key") return "🔐"
    return "🔑"
  }

  function getAttachmentIcon(filename) {
    if (!filename) return "📄"
    var ext = filename.split(".").pop().toLowerCase()
    if (["png", "jpg", "jpeg", "gif", "svg", "webp", "bmp"].indexOf(ext) !== -1) return "🖼️"
    if (["txt", "md", "json", "yaml", "yml", "csv", "log", "sh", "py", "js", "ts", "html", "css"].indexOf(ext) !== -1) return "📝"
    if (["pdf"].indexOf(ext) !== -1) return "📕"
    if (["zip", "tar", "gz", "7z", "rar"].indexOf(ext) !== -1) return "📦"
    return "📄"
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
          border.color: Qt.rgba(1, 1, 1, 0.15)
          border.width: 1

          RowLayout {
            id: backBtnRow
            anchors.centerIn: parent
            spacing: 4
            Text { text: "← Back to Item"; color: inspectorRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
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
          font.pixelSize: 14
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
        Rectangle {
          implicitHeight: 24
          implicitWidth: openExtText.implicitWidth + 10
          radius: 4
          color: openExtMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.1) : Qt.rgba(1, 1, 1, 0.05)
          border.color: Qt.rgba(1, 1, 1, 0.15)
          border.width: 1

          Text {
            id: openExtText
            anchors.centerIn: parent
            text: "↗ Open"
            color: inspectorRoot.foreground
            font.pixelSize: 11
          }
          MouseArea {
            id: openExtMouse
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

      Rectangle { Layout.fillWidth: true; height: 1; color: inspectorRoot.border }

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
          Rectangle {
            implicitHeight: 20
            implicitWidth: copyTxtText.implicitWidth + 8
            radius: 3
            color: Qt.rgba(1, 1, 1, 0.08)
            Text {
              id: copyTxtText
              anchors.centerIn: parent
              text: "Copy Text"
              color: inspectorRoot.accent
              font.pixelSize: 10
            }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: {
                if (inspectorRoot.activeAttachmentPreview && inspectorRoot.activeAttachmentPreview.text_content) {
                  inspectorRoot.copyRequested(inspectorRoot.activeAttachmentPreview.text_content, false, "attachment text")
                }
              }
            }
          }
        }

        Rectangle {
          Layout.fillWidth: true
          Layout.preferredHeight: 240
          radius: 4
          color: Qt.rgba(0, 0, 0, 0.3)
          border.color: inspectorRoot.border
          border.width: 1

          ScrollView {
            anchors.fill: parent
            anchors.margins: 8
            clip: true

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

        Text {
          text: inspectorRoot.getItemIcon(inspectorRoot.item)
          font.pixelSize: 22
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
                text: "🏢 " + (inspectorRoot.item ? (inspectorRoot.item.organization_name || "") : "")
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
                text: "📁 " + (inspectorRoot.item ? (inspectorRoot.item.folder_name || "") : "")
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

      Rectangle { Layout.fillWidth: true; height: 1; color: inspectorRoot.border }

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

          Text { text: "Username:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 70 }
          Text {
            text: (inspectorRoot.item && inspectorRoot.item.login) ? (inspectorRoot.item.login.username || "") : ""
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.weight: Font.Medium
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
          Rectangle {
            implicitHeight: 20
            implicitWidth: cpUserText.implicitWidth + 8
            radius: 3
            color: Qt.rgba(1, 1, 1, 0.08)
            Text { id: cpUserText; anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: inspectorRoot.copyRequested(inspectorRoot.item.login.username, false, "username")
            }
          }
        }

        // Password
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.password)
          Layout.fillWidth: true
          spacing: 8

          Text { text: "Password:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 70 }
          Text {
            text: inspectorRoot.showPasswordRevealed ? (inspectorRoot.item.login.password || "") : "••••••••••••••••"
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: inspectorRoot.showPasswordRevealed ? "monospace" : "sans-serif"
            font.weight: Font.Medium
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
          Rectangle {
            implicitHeight: 20
            implicitWidth: revPwdText.implicitWidth + 8
            radius: 3
            color: Qt.rgba(1, 1, 1, 0.08)
            Text { id: revPwdText; anchors.centerIn: parent; text: inspectorRoot.showPasswordRevealed ? "Hide" : "Show"; color: inspectorRoot.foreground; font.pixelSize: 10 }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: inspectorRoot.togglePasswordRevealed()
            }
          }
          Rectangle {
            implicitHeight: 20
            implicitWidth: cpPwdText.implicitWidth + 8
            radius: 3
            color: Qt.rgba(1, 1, 1, 0.08)
            Text { id: cpPwdText; anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: inspectorRoot.copyRequested(inspectorRoot.item.login.password, true, "password")
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

            Text { text: "TOTP Code:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 70 }
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
            Rectangle {
              implicitHeight: 20
              implicitWidth: cpTotpText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(1, 1, 1, 0.08)
              Text { id: cpTotpText; anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: inspectorRoot.copyRequested(inspectorRoot.currentTotp.code, true, "TOTP code")
              }
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
        spacing: 6

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.cardholderName)
          Layout.fillWidth: true
          Text { text: "Cardholder:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.item.card.cardholderName || ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.number)
          Layout.fillWidth: true
          Text { text: "Card Number:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: inspectorRoot.showPasswordRevealed ? (inspectorRoot.item.card.number || "") : "•••• •••• •••• ••••"
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: "monospace"
            Layout.fillWidth: true
          }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.card.number, true, "card number") }
          }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && (inspectorRoot.item.card.expMonth || inspectorRoot.item.card.expYear))
          Layout.fillWidth: true
          Text { text: "Expires:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: (inspectorRoot.item.card.expMonth || "") + "/" + (inspectorRoot.item.card.expYear || ""); color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.card && inspectorRoot.item.card.code)
          Layout.fillWidth: true
          Text { text: "Security Code:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: inspectorRoot.showPasswordRevealed ? (inspectorRoot.item.card.code || "") : "•••"
            color: inspectorRoot.foreground
            font.pixelSize: 11
            font.family: "monospace"
            Layout.fillWidth: true
          }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.card.code, true, "CVV") }
          }
        }
      }

      // --------------------------------------------------
      // IDENTITY DETAILS SECTION
      // --------------------------------------------------
      ColumnLayout {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity)
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && (inspectorRoot.item.identity.firstName || inspectorRoot.item.identity.lastName))
          Layout.fillWidth: true
          Text { text: "Full Name:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: [inspectorRoot.item.identity.title, inspectorRoot.item.identity.firstName, inspectorRoot.item.identity.middleName, inspectorRoot.item.identity.lastName].filter(Boolean).join(" ")
            color: inspectorRoot.foreground
            font.pixelSize: 11
            Layout.fillWidth: true
          }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && inspectorRoot.item.identity.email)
          Layout.fillWidth: true
          Text { text: "Email:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.item.identity.email || ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.identity.email, false, "email") }
          }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && inspectorRoot.item.identity.phone)
          Layout.fillWidth: true
          Text { text: "Phone:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.item.identity.phone || ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity && (inspectorRoot.item.identity.address1 || inspectorRoot.item.identity.city))
          Layout.fillWidth: true
          Text { text: "Address:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text {
            text: [inspectorRoot.item.identity.address1, inspectorRoot.item.identity.address2, inspectorRoot.item.identity.city, inspectorRoot.item.identity.state, inspectorRoot.item.identity.postalCode, inspectorRoot.item.identity.country].filter(Boolean).join(", ")
            color: inspectorRoot.foreground
            font.pixelSize: 11
            elide: Text.ElideRight
            Layout.fillWidth: true
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
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.notes, false, "notes") }
          }
        }

        Rectangle {
          Layout.fillWidth: true
          implicitHeight: Math.min(notesText.implicitHeight + 16, 160)
          radius: 4
          color: Qt.rgba(0, 0, 0, 0.25)
          border.color: inspectorRoot.border
          border.width: 1

          ScrollView {
            anchors.fill: parent
            anchors.margins: 8
            clip: true

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
          Text { text: "Key Type:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.item.ssh_key.key_type || ""; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.fingerprint)
          Layout.fillWidth: true
          Text { text: "Fingerprint:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.item.ssh_key.fingerprint || ""; color: inspectorRoot.foreground; font.pixelSize: 11; font.family: "monospace"; Layout.fillWidth: true }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.public_key)
          Layout.fillWidth: true
          Text { text: "Public Key:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: "Available"; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.ssh_key.public_key, false, "SSH public key") }
          }
        }
        RowLayout {
          visible: Boolean(inspectorRoot.item && inspectorRoot.item.ssh_key && inspectorRoot.item.ssh_key.private_key)
          Layout.fillWidth: true
          Text { text: "Private Key:"; color: Qt.darker(inspectorRoot.foreground, 1.5); font.pixelSize: 11; Layout.preferredWidth: 80 }
          Text { text: inspectorRoot.showPrivateKeyRevealed ? "Revealed" : "Encrypted (Hidden)"; color: inspectorRoot.foreground; font.pixelSize: 11; Layout.fillWidth: true }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: inspectorRoot.showPrivateKeyRevealed ? "Hide" : "Show"; color: inspectorRoot.foreground; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.togglePrivateKeyRevealed() }
          }
          Rectangle {
            implicitHeight: 20; implicitWidth: 40; radius: 3; color: Qt.rgba(1, 1, 1, 0.08)
            Text { anchors.centerIn: parent; text: "Copy"; color: inspectorRoot.accent; font.pixelSize: 10 }
            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: inspectorRoot.copyRequested(inspectorRoot.item.ssh_key.private_key, true, "SSH private key") }
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
            border.color: inspectorRoot.border
            border.width: 1

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: 8
              anchors.rightMargin: 8
              spacing: 8

              Text {
                text: inspectorRoot.getAttachmentIcon(modelData.fileName)
                font.pixelSize: 14
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

              // View / Preview Button
              Rectangle {
                implicitHeight: 22
                implicitWidth: viewAttText.implicitWidth + 10
                radius: 3
                color: Qt.rgba(1, 1, 1, 0.08)

                Text {
                  id: viewAttText
                  anchors.centerIn: parent
                  text: (inspectorRoot.loadingAttachmentId === (modelData.id || modelData.fileName)) ? "Loading..." : "View"
                  color: inspectorRoot.accent
                  font.pixelSize: 10
                }
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: inspectorRoot.viewAttachmentRequested(inspectorRoot.item, modelData)
                }
              }

              // Download Button
              Rectangle {
                implicitHeight: 22
                implicitWidth: dlAttText.implicitWidth + 10
                radius: 3
                color: Qt.rgba(1, 1, 1, 0.08)

                Text {
                  id: dlAttText
                  anchors.centerIn: parent
                  text: "Download"
                  color: inspectorRoot.foreground
                  font.pixelSize: 10
                }
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: inspectorRoot.downloadAttachmentRequested(inspectorRoot.item, modelData)
                }
              }
            }
          }
        }
      }
    }
  }
}
