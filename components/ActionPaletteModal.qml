import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: paletteRoot

  property bool active: false
  property var actions: []
  property int selectedIndex: 0
  property string actionFilterQuery: ""
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)

  signal actionSelected(var actionItem)
  signal closeRequested()

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.6)
  visible: active

  function getFilteredActions() {
    if (!actions) return []
    if (!actionFilterQuery) return actions
    var q = actionFilterQuery.toLowerCase()
    return actions.filter(function(a) {
      return (a.label && a.label.toLowerCase().indexOf(q) !== -1) || (a.shortcut && a.shortcut.toLowerCase().indexOf(q) !== -1)
    })
  }

  MouseArea {
    anchors.fill: parent
    onClicked: paletteRoot.closeRequested()
  }

  Rectangle {
    id: paletteBox
    anchors.centerIn: parent
    width: Math.min(parent.width - 64, 480)
    height: Math.min(parent.height - 64, 380)
    radius: 8
    color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
    border.color: Qt.rgba(1, 1, 1, 0.15)
    border.width: 1

    MouseArea {
      anchors.fill: parent
      // prevent clicks inside box from bubbling to background dismiss
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 14
      spacing: 10

      // Header Search Bar
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text { text: "⚡"; font.pixelSize: 13 }

        TextInput {
          id: paletteFilterInput
          Layout.fillWidth: true
          color: paletteRoot.foreground
          font.pixelSize: 12
          selectByMouse: true
          clip: true
          text: paletteRoot.actionFilterQuery
          onTextChanged: {
            paletteRoot.actionFilterQuery = text
            paletteRoot.selectedIndex = 0
          }

          Text {
            anchors.fill: parent
            text: "Type an action name..."
            color: Qt.darker(paletteRoot.foreground, 1.8)
            font.pixelSize: 12
            visible: !paletteFilterInput.text
          }
        }

        Text {
          text: "Esc"
          color: Qt.darker(paletteRoot.foreground, 1.8)
          font.pixelSize: 10
        }
      }

      Rectangle { Layout.fillWidth: true; height: 1; color: paletteRoot.borderColor }

      // Action List
      ListView {
        id: paletteListView
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        model: paletteRoot.getFilteredActions()
        currentIndex: paletteRoot.selectedIndex

        delegate: Rectangle {
          id: actionDelegate
          property bool isSelected: index === paletteRoot.selectedIndex
          width: paletteListView.width
          height: 36
          radius: 5
          color: isSelected ? Qt.rgba(paletteRoot.accent.r, paletteRoot.accent.g, paletteRoot.accent.b, 0.25) : (actionMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
          border.color: isSelected ? paletteRoot.accent : "transparent"
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 10
            spacing: 8

            Text {
              text: modelData.icon || "⚡"
              font.pixelSize: 13
            }

            Text {
              text: modelData.label || ""
              color: actionDelegate.isSelected ? "#ffffff" : paletteRoot.foreground
              font.pixelSize: 12
              font.weight: Font.Medium
              elide: Text.ElideRight
              Layout.fillWidth: true
            }

            Rectangle {
              visible: Boolean(modelData.shortcut)
              implicitHeight: 18
              implicitWidth: scText.implicitWidth + 8
              radius: 3
              color: Qt.rgba(1, 1, 1, 0.08)
              border.color: Qt.rgba(1, 1, 1, 0.15)
              border.width: 1

              Text {
                id: scText
                anchors.centerIn: parent
                text: modelData.shortcut || ""
                color: Qt.darker(paletteRoot.foreground, 1.4)
                font.pixelSize: 10
              }
            }
          }

          MouseArea {
            id: actionMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              paletteRoot.selectedIndex = index
              paletteRoot.actionSelected(modelData)
            }
          }
        }
      }
    }
  }

  onActiveChanged: {
    if (active) {
      paletteFilterInput.text = ""
      paletteFilterInput.forceActiveFocus()
    }
  }
}
