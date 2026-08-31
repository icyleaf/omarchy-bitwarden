import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
  id: searchHeaderRoot

  property alias searchQuery: searchInputField.text
  property alias searchField: searchInputField
  property alias categoryTabBar: catBar
  property var categoryList: ["all", "login", "card", "identity", "note", "ssh_key"]
  property string activeCategory: "all"
  property var rawVaultItems: []
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  readonly property string fontFamily: Style.font.menuFamily

  signal categorySelected(string category)
  signal clearSearchRequested()

  spacing: 6
  Layout.fillWidth: true

  // 1. Search Box Bar
  Rectangle {
    Layout.fillWidth: true
    height: 34
    radius: 6
    color: Qt.rgba(0, 0, 0, 0.25)
    border.color: searchInputField.activeFocus ? searchHeaderRoot.accent : searchHeaderRoot.borderColor
    border.width: 1

    RowLayout {
      anchors.fill: parent
      anchors.leftMargin: 10
      anchors.rightMargin: 10
      spacing: 6

      Text {
        text: "\uf002"
        font.family: searchHeaderRoot.fontFamily
        font.pixelSize: 12
        color: Qt.darker(searchHeaderRoot.foreground, 1.4)
        Layout.alignment: Qt.AlignVCenter
      }

      Item {
        Layout.fillWidth: true
        Layout.fillHeight: true

        TextInput {
          id: searchInputField
          anchors.fill: parent
          verticalAlignment: TextInput.AlignVCenter
          color: searchHeaderRoot.foreground
          font.pixelSize: 12
          selectByMouse: true
          clip: true
          activeFocusOnTab: true
        }

        Text {
          anchors.fill: parent
          verticalAlignment: Text.AlignVCenter
          text: "Search Bitwarden vault (names, usernames, notes, tags)..."
          color: Qt.darker(searchHeaderRoot.foreground, 2.0)
          font.pixelSize: 12
          visible: !searchInputField.text
        }
      }

      // Clear search button
      Text {
        visible: Boolean(searchInputField.text)
        text: "\uf00d"
        font.family: searchHeaderRoot.fontFamily
        color: clearMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.5)
        font.pixelSize: 11
        Layout.alignment: Qt.AlignVCenter

        MouseArea {
          id: clearMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: {
            searchInputField.text = ""
            searchHeaderRoot.clearSearchRequested()
            searchInputField.forceActiveFocus()
          }
        }
      }
    }
  }

  // 2. Category Tab Bar
  CategoryTabBar {
    id: catBar
    categoryList: searchHeaderRoot.categoryList
    activeCategory: searchHeaderRoot.activeCategory
    rawVaultItems: searchHeaderRoot.rawVaultItems
    foreground: searchHeaderRoot.foreground
    accent: searchHeaderRoot.accent
    borderColor: searchHeaderRoot.borderColor
    onCategorySelected: function(cat) {
      searchHeaderRoot.categorySelected(cat)
    }
  }
}
