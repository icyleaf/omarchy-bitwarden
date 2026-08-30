import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

RowLayout {
  id: tabRoot

  property var categoryList: ["all", "login", "card", "identity", "note", "ssh_key"]
  property string activeCategory: "all"
  property var rawVaultItems: []
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)

  signal categorySelected(string category)

  spacing: 4

  function getCategoryLabel(cat) {
    switch (cat) {
      case "all": return "All"
      case "login": return "Logins"
      case "card": return "Cards"
      case "identity": return "Identities"
      case "note": return "Notes"
      case "ssh_key": return "SSH Keys"
      default: return cat
    }
  }

  function getCategoryCount(cat) {
    if (!rawVaultItems || rawVaultItems.length === 0) return 0
    if (cat === "all") return rawVaultItems.length
    return rawVaultItems.filter(function(i) {
      return (i.type_name === cat) || (cat === "ssh_key" && (i.type_name === "ssh_key" || i.category === "ssh_key"))
    }).length
  }

  Repeater {
    model: tabRoot.categoryList

    Rectangle {
      id: tabItem
      property string cat: modelData
      property bool isSelected: tabRoot.activeCategory === cat

      implicitHeight: 24
      implicitWidth: tabRow.implicitWidth + 14
      radius: 4
      color: isSelected ? Qt.rgba(tabRoot.accent.r, tabRoot.accent.g, tabRoot.accent.b, 0.2) : (tabMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
      border.color: isSelected ? tabRoot.accent : "transparent"
      border.width: 1

      RowLayout {
        id: tabRow
        anchors.centerIn: parent
        spacing: 4

        Text {
          text: tabRoot.getCategoryLabel(cat)
          color: isSelected ? tabRoot.accent : (tabMouse.containsMouse ? tabRoot.foreground : Qt.darker(tabRoot.foreground, 1.3))
          font.pixelSize: 11
          font.weight: isSelected ? Font.DemiBold : Font.Normal
        }

        Text {
          property int count: tabRoot.getCategoryCount(cat)
          visible: count > 0
          text: count
          color: isSelected ? tabRoot.accent : Qt.darker(tabRoot.foreground, 1.8)
          font.pixelSize: 10
        }
      }

      MouseArea {
        id: tabMouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: tabRoot.categorySelected(cat)
      }
    }
  }
}
