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
  property color background: "#1f2937"
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""
  property bool modalsActive: false

  signal categorySelected(string category)
  signal clearSearchRequested()
  signal createSshKeyRequested()
  signal importSshKeyRequested()
  signal copyUsernameRequested()
  signal copyTotpRequested()
  signal openUrlRequested()
  signal actionPaletteRequested()
  signal exportSshKeyRequested()

  function focusSearch() {
    searchInputField.forceActiveFocus()
  }

  spacing: 6
  Layout.fillWidth: true

  onVisibleChanged: {
    if (visible) {
      Qt.callLater(function() {
        focusSearch()
      })
    }
  }

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
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          color: searchHeaderRoot.foreground
          font.family: "sans-serif"
          font.pixelSize: 12
          selectByMouse: true
          clip: true

          Keys.priority: Keys.BeforeItem
          Keys.onPressed: function(event) {
            if (searchHeaderRoot.modalsActive) return

            if (event.modifiers & Qt.ControlModifier) {
              if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                searchHeaderRoot.copyTotpRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_U) {
                searchHeaderRoot.copyUsernameRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_O) {
                searchHeaderRoot.openUrlRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_K) {
                searchHeaderRoot.actionPaletteRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_E) {
                searchHeaderRoot.exportSshKeyRequested()
                event.accepted = true
              }
            }
          }
        }

        Text {
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: "Search Bitwarden vault (names, usernames, notes, tags)..."
          color: Qt.darker(searchHeaderRoot.foreground, 2.0)
          font.family: "sans-serif"
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

  // 2. Category Tab Bar & Action Buttons
  RowLayout {
    Layout.fillWidth: true
    spacing: 8

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

    Item { Layout.fillWidth: true }

    // SSH Key Category Actions
    RowLayout {
      visible: searchHeaderRoot.activeCategory === "ssh_key"
      spacing: 4

      Rectangle {
        implicitWidth: 18
        implicitHeight: 18
        radius: 4
        color: createMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"

        Text {
          anchors.centerIn: parent
          text: "\uf067"
          font.family: searchHeaderRoot.fontFamily
          font.pixelSize: 10
          color: createMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.4)
        }

        MouseArea {
          id: createMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: searchHeaderRoot.createSshKeyRequested()

          ToolTip.visible: containsMouse
          ToolTip.delay: 300
          ToolTip.text: "Generate SSH Key"
        }
      }

      Rectangle {
        implicitWidth: 18
        implicitHeight: 18
        radius: 4
        color: importMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"

        Text {
          anchors.centerIn: parent
          text: "\uf093"
          font.family: searchHeaderRoot.fontFamily
          font.pixelSize: 10
          color: importMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.4)
        }

        MouseArea {
          id: importMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: searchHeaderRoot.importSshKeyRequested()

          ToolTip.visible: containsMouse
          ToolTip.delay: 300
          ToolTip.text: "Import SSH Key"
        }
      }
    }
  }
}
