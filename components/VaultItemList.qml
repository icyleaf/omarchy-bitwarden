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
  property color border: Qt.rgba(1, 1, 1, 0.1)

  signal itemSelected(int index)
  signal itemTriggered(int index)

  function getItemIcon(item) {
    if (!item) return "🔑"
    if (item.type_name === "card") return "💳"
    if (item.type_name === "identity") return "🪪"
    if (item.type_name === "note") return "📝"
    if (item.type_name === "ssh_key" || item.category === "ssh_key") return "🔐"
    return "🔑"
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
        text: "🔍"
        font.pixelSize: 28
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
    visible: Boolean(itemListRoot.items && itemListRoot.items.length > 0)
    model: itemListRoot.items
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    currentIndex: itemListRoot.selectedIndex

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

        // Type Icon
        Text {
          text: itemListRoot.getItemIcon(modelData)
          font.pixelSize: 16
          Layout.preferredWidth: 20
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
                text: "🏢 " + (modelData.organization_name || "")
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
                text: "📁 " + (modelData.folder_name || "")
                color: "#60a5fa"
                font.pixelSize: 9
                font.weight: Font.Medium
              }
            }

            // Attachment Indicator
            Text {
              visible: Boolean(modelData.attachments && modelData.attachments.length > 0)
              text: "📎"
              font.pixelSize: 10
              color: Qt.darker(itemListRoot.foreground, 1.5)
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

    ScrollBar.vertical: ScrollBar {
      policy: ScrollBar.AsNeeded
      active: true
    }
  }
}
