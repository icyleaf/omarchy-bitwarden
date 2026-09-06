import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: dropdownRoot

  property string title: "Scope"
  property string currentValue: "all"
  property var items: [] // [{ id: string, name: string, icon: string, count: int }]
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""
  property bool alignRight: false
  property int maxLabelWidth: 110

  property alias isOpen: popup.opened

  signal selected(string id)
  signal resetRequested()
  signal closed()

  function open() {
    popup.open()
  }

  function close() {
    popup.close()
  }

  function cycleNext() {
    if (!items || items.length <= 1) return
    var nextIdx = 0
    if (popup.opened) {
      nextIdx = (popup.highlightedIndex + 1) % items.length
      popup.highlightedIndex = nextIdx
      menuListView.currentIndex = nextIdx
      dropdownRoot.selected(items[nextIdx].id)
    } else {
      for (var i = 0; i < items.length; i++) {
        if (items[i].id === currentValue) {
          nextIdx = (i + 1) % items.length
          break
        }
      }
      dropdownRoot.selected(items[nextIdx].id)
    }
  }

  property var currentItem: {
    var val = currentValue
    var list = items
    if (!list || list.length === 0) return null
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === val) return list[i]
    }
    return list[0]
  }

  property bool isFiltered: currentValue !== "all"

  implicitHeight: 24
  implicitWidth: capsuleRect.implicitWidth

  // Capsule Trigger Button
  Rectangle {
    id: capsuleRect
    anchors.verticalCenter: parent.verticalCenter
    implicitHeight: 24
    implicitWidth: capsuleRow.implicitWidth + (dropdownRoot.isFiltered ? 18 : 12)
    radius: 4
    color: dropdownRoot.isFiltered ? Qt.rgba(dropdownRoot.accent.r, dropdownRoot.accent.g, dropdownRoot.accent.b, 0.18) : (capsuleMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(1, 1, 1, 0.04))
    border.color: dropdownRoot.isFiltered ? dropdownRoot.accent : (capsuleMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.2) : dropdownRoot.borderColor)
    border.width: 1

    MouseArea {
      id: capsuleMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: {
        if (popup.opened) popup.close()
        else popup.open()
      }
    }

    RowLayout {
      id: capsuleRow
      z: 1
      anchors.centerIn: parent
      spacing: 5

      Text {
        text: dropdownRoot.currentItem ? (dropdownRoot.currentItem.icon || "\uf009") : "\uf009"
        font.family: dropdownRoot.fontFamily
        font.pixelSize: 11
        color: dropdownRoot.isFiltered ? dropdownRoot.accent : (capsuleMouse.containsMouse ? dropdownRoot.foreground : Qt.darker(dropdownRoot.foreground, 1.4))
      }

      Text {
        text: dropdownRoot.currentItem ? dropdownRoot.currentItem.name : dropdownRoot.title
        font.family: "sans-serif"
        font.pixelSize: 11
        font.weight: dropdownRoot.isFiltered ? Font.DemiBold : Font.Normal
        color: dropdownRoot.isFiltered ? dropdownRoot.accent : (capsuleMouse.containsMouse ? dropdownRoot.foreground : Qt.darker(dropdownRoot.foreground, 1.2))
        elide: Text.ElideRight
        Layout.maximumWidth: dropdownRoot.maxLabelWidth
      }

      // Caret Down
      Text {
        text: "\uf0d7"
        font.family: dropdownRoot.fontFamily
        font.pixelSize: 9
        color: dropdownRoot.isFiltered ? dropdownRoot.accent : Qt.darker(dropdownRoot.foreground, 1.6)
      }

      // Inline Reset Button (When Filtered)
      Rectangle {
        visible: dropdownRoot.isFiltered
        implicitWidth: 14
        implicitHeight: 14
        radius: 7
        color: resetMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.2) : "transparent"

        Text {
          anchors.centerIn: parent
          text: "\uf00d"
          font.family: dropdownRoot.fontFamily
          font.pixelSize: 9
          color: dropdownRoot.accent
        }

        MouseArea {
          id: resetMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: function(mouse) {
            mouse.accepted = true
            if (popup.opened) popup.close()
            dropdownRoot.selected("all")
            dropdownRoot.resetRequested()
          }
        }
      }
    }
  }

  // Dropdown Popup Menu
  Popup {
    id: popup
    y: capsuleRect.height + 6
    x: dropdownRoot.alignRight ? (capsuleRect.width - width) : 0
    width: Math.max(190, capsuleRect.width)
    implicitHeight: Math.min(260, (dropdownRoot.items ? dropdownRoot.items.length * 30 + 12 : 60))
    padding: 6
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    property int highlightedIndex: 0

    onClosed: {
      dropdownRoot.closed()
    }

    onOpened: {
      highlightedIndex = 0
      if (dropdownRoot.items) {
        for (var i = 0; i < dropdownRoot.items.length; i++) {
          if (dropdownRoot.items[i].id === dropdownRoot.currentValue) {
            highlightedIndex = i
            break
          }
        }
      }
      menuListView.currentIndex = highlightedIndex
      menuListView.positionViewAtIndex(highlightedIndex, ListView.Contain)
      menuListView.forceActiveFocus()
    }

    background: Rectangle {
      color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
      border.color: dropdownRoot.borderColor
      border.width: 1
      radius: 6
    }

    contentItem: ListView {
      id: menuListView
      focus: true
      model: dropdownRoot.items
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      currentIndex: popup.highlightedIndex
      spacing: 2

      onCurrentIndexChanged: {
        positionViewAtIndex(currentIndex, ListView.Contain)
      }

      ScrollBar.vertical: ScrollBar {
        policy: ScrollBar.AsNeeded
      }

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (!dropdownRoot.items || dropdownRoot.items.length === 0) return

        if (event.key === Qt.Key_Down) {
          popup.highlightedIndex = (popup.highlightedIndex + 1) % dropdownRoot.items.length
          menuListView.currentIndex = popup.highlightedIndex
          event.accepted = true
        } else if (event.key === Qt.Key_Up) {
          popup.highlightedIndex = (popup.highlightedIndex - 1 + dropdownRoot.items.length) % dropdownRoot.items.length
          menuListView.currentIndex = popup.highlightedIndex
          event.accepted = true
        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) {
          if (popup.highlightedIndex >= 0 && popup.highlightedIndex < dropdownRoot.items.length) {
            dropdownRoot.selected(dropdownRoot.items[popup.highlightedIndex].id)
            popup.close()
            event.accepted = true
          }
        } else if (event.key === Qt.Key_Escape) {
          popup.close()
          event.accepted = true
        }
      }

      delegate: Rectangle {
        required property int index
        required property var modelData
        width: menuListView.width
        implicitHeight: 28
        radius: 4
        property bool isSelected: modelData.id === dropdownRoot.currentValue
        property bool isHighlighted: index === popup.highlightedIndex
        color: isSelected ? Qt.rgba(dropdownRoot.accent.r, dropdownRoot.accent.g, dropdownRoot.accent.b, 0.2) : ((itemMouse.containsMouse || isHighlighted) ? Qt.rgba(1, 1, 1, 0.08) : "transparent")

        RowLayout {
          anchors.fill: parent
          anchors.leftMargin: 8
          anchors.rightMargin: 8
          spacing: 6

          Text {
            text: modelData.icon || "\uf009"
            font.family: dropdownRoot.fontFamily
            font.pixelSize: 11
            color: isSelected ? dropdownRoot.accent : Qt.darker(dropdownRoot.foreground, 1.4)
          }

          Text {
            text: modelData.name || ""
            color: isSelected ? dropdownRoot.accent : dropdownRoot.foreground
            font.pixelSize: 11
            font.weight: isSelected ? Font.DemiBold : Font.Normal
            elide: Text.ElideRight
            Layout.fillWidth: true
            Layout.preferredWidth: 0
          }

          Text {
            visible: modelData.count !== undefined && modelData.count !== null
            text: String(modelData.count)
            color: isSelected ? dropdownRoot.accent : Qt.darker(dropdownRoot.foreground, 2.0)
            font.pixelSize: 10
          }

          Text {
            visible: isSelected
            text: "\uf00c"
            font.family: dropdownRoot.fontFamily
            font.pixelSize: 10
            color: dropdownRoot.accent
          }
        }

        MouseArea {
          id: itemMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onPositionChanged: {
            popup.highlightedIndex = index
            menuListView.currentIndex = index
          }
          onClicked: {
            dropdownRoot.selected(modelData.id)
            popup.close()
          }
        }
      }
    }
  }
}
