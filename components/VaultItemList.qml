import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: itemListRoot

  property var items: []
  property int selectedIndex: 0
  property string searchQuery: ""
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color selectedBackground: Qt.rgba(0.23, 0.51, 0.96, 0.25)
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  signal itemSelected(int index)
  signal itemTriggered(int index)

  onSelectedIndexChanged: {
    if (selectedIndex >= 0 && items && selectedIndex < items.length) {
      if (listView.currentIndex !== selectedIndex) {
        listView.currentIndex = selectedIndex
      }
      listView.positionViewAtIndex(selectedIndex, ListView.Contain)
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

  function getSubtitle(item) {
    if (!item) return ""
    if (item.type_name === "login" && item.login && item.login.username) return item.login.username
    if (item.type_name === "card" && item.card && item.card.brand) return item.card.brand
    if (item.type_name === "identity" && item.identity && item.identity.email) return item.identity.email
    if (item.type_name === "ssh_key" && item.ssh_key && item.ssh_key.key_type) return item.ssh_key.key_type
    return item.sub_title || ""
  }

  // Empty List View
  Item {
    anchors.fill: parent
    visible: !itemListRoot.items || itemListRoot.items.length === 0

    ColumnLayout {
      anchors.centerIn: parent
      spacing: 8

      Text {
        Layout.alignment: Qt.AlignHCenter
        text: "\uf002"
        font.family: itemListRoot.fontFamily
        font.pixelSize: 28
        color: Qt.darker(itemListRoot.foreground, 1.8)
      }

      Text {
        Layout.alignment: Qt.AlignHCenter
        text: itemListRoot.searchQuery ? "No matching items found" : "Vault is empty"
        color: Qt.darker(itemListRoot.foreground, 1.4)
        font.pixelSize: 12
        font.weight: Font.Medium
      }

      Text {
        visible: Boolean(itemListRoot.searchQuery)
        Layout.alignment: Qt.AlignHCenter
        text: "Try a different keyword or press Tab to switch category"
        color: Qt.darker(itemListRoot.foreground, 2.0)
        font.pixelSize: 11
      }
    }
  }

  // Active Item List
  ListView {
    id: listView
    anchors.fill: parent
    anchors.rightMargin: 6
    visible: Boolean(itemListRoot.items && itemListRoot.items.length > 0)
    model: itemListRoot.items
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    currentIndex: itemListRoot.selectedIndex
    spacing: 2

    ScrollBar.vertical: ScrollBar {
      id: vScrollBar
      anchors.right: parent.right
      anchors.rightMargin: -5
      policy: ScrollBar.AsNeeded
      contentItem: Rectangle {
        implicitWidth: 4
        radius: 2
        color: vScrollBar.pressed ? Qt.rgba(1, 1, 1, 0.4) : (vScrollBar.hovered ? Qt.rgba(1, 1, 1, 0.25) : Qt.rgba(1, 1, 1, 0.15))
      }
    }

    onCurrentIndexChanged: {
      if (currentIndex !== itemListRoot.selectedIndex) {
        itemListRoot.itemSelected(currentIndex)
      }
    }

    delegate: Rectangle {
      id: itemDelegate
      property bool isSelected: index === itemListRoot.selectedIndex
      width: listView.width
      height: 48
      radius: 6
      color: isSelected ? itemListRoot.selectedBackground : (delegateMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.04) : "transparent")
      border.color: isSelected ? Qt.rgba(itemListRoot.accent.r, itemListRoot.accent.g, itemListRoot.accent.b, 0.6) : "transparent"
      border.width: 1

      RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        spacing: 10

        // Type Icon (Favicon with fallback)
        Item {
          id: iconContainer
          Layout.preferredWidth: 20
          Layout.preferredHeight: 20

          property string favUrl: itemListRoot.getFaviconUrl(modelData)

          Image {
            id: faviconImg
            anchors.fill: parent
            asynchronous: true
            cache: true
            fillMode: Image.PreserveAspectFit
            source: iconContainer.favUrl
            visible: iconContainer.favUrl !== "" && status === Image.Ready
          }

          Text {
            anchors.centerIn: parent
            visible: !faviconImg.visible
            text: itemListRoot.getItemIcon(modelData)
            font.family: itemListRoot.fontFamily
            font.pixelSize: 14
            color: itemDelegate.isSelected ? "#ffffff" : Qt.darker(itemListRoot.foreground, 1.4)
          }
        }

        // Title and Subtitle Column
        ColumnLayout {
          Layout.fillWidth: true
          spacing: 2

          RowLayout {
            Layout.fillWidth: true
            spacing: 6

            Text {
              text: modelData.name || "Untitled"
              color: itemDelegate.isSelected ? "#ffffff" : itemListRoot.foreground
              font.pixelSize: 12
              font.weight: Font.Medium
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            // Organization Badge
            Rectangle {
              visible: Boolean(modelData.organization_name)
              implicitHeight: 16
              implicitWidth: orgText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(0.9, 0.6, 0.2, 0.2)
              border.color: Qt.rgba(0.9, 0.6, 0.2, 0.5)
              border.width: 1

              Text {
                id: orgText
                anchors.centerIn: parent
                text: "\uf1ad " + (modelData.organization_name || "")
                font.family: itemListRoot.fontFamily
                color: "#fbbf24"
                font.pixelSize: 9
                font.weight: Font.Medium
              }
            }

            // Folder Badge
            Rectangle {
              visible: Boolean(modelData.folder_name)
              implicitHeight: 16
              implicitWidth: folderText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(0.4, 0.7, 1.0, 0.2)
              border.color: Qt.rgba(0.4, 0.7, 1.0, 0.5)
              border.width: 1

              Text {
                id: folderText
                anchors.centerIn: parent
                text: "\uf07b " + (modelData.folder_name || "")
                font.family: itemListRoot.fontFamily
                color: "#60a5fa"
                font.pixelSize: 9
                font.weight: Font.Medium
              }
            }

            // Attachment Indicator
            Text {
              visible: Boolean(modelData.attachments && modelData.attachments.length > 0)
              text: "\uf0c6"
              font.family: itemListRoot.fontFamily
              font.pixelSize: 11
              color: itemDelegate.isSelected ? "#ffffff" : Qt.darker(itemListRoot.foreground, 1.5)
            }

            // Monochrome Favorite Indicator (Always at the far right)
            Text {
              visible: Boolean(modelData.favorite)
              text: "\uf005"
              font.family: itemListRoot.fontFamily
              font.pixelSize: 11
              color: itemDelegate.isSelected ? "#ffffff" : Qt.darker(itemListRoot.foreground, 1.4)
            }
          }

          // Subtitle / Username
          Text {
            property string sub: itemListRoot.getSubtitle(modelData)
            visible: Boolean(sub)
            text: sub
            color: itemDelegate.isSelected ? Qt.rgba(1, 1, 1, 0.8) : Qt.darker(itemListRoot.foreground, 1.6)
            font.pixelSize: 11
            elide: Text.ElideRight
            Layout.fillWidth: true
          }
        }
      }

      MouseArea {
        id: delegateMouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: {
          itemListRoot.selectedIndex = index
          itemListRoot.itemSelected(index)
        }
        onDoubleClicked: {
          itemListRoot.selectedIndex = index
          itemListRoot.itemTriggered(index)
        }
      }
    }
  }
}
