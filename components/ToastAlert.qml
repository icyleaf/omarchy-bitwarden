import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons

Item {
  id: toastRoot

  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property string fontFamily: ""
  property int maxMessageWidth: 560

  signal clearRequested()

  visible: Boolean(statusMessage || errorMessage || isBusy)
  implicitHeight: contentRow.implicitHeight + 10
  implicitWidth: contentRow.implicitWidth + 20

  Rectangle {
    anchors.fill: parent
    radius: 6
    color: errorMessage ? Qt.rgba(0.85, 0.15, 0.15, 0.95) : Qt.rgba(0.12, 0.14, 0.18, 0.95)
    border.color: errorMessage ? "#f87171" : (isBusy ? toastRoot.accent : Qt.rgba(1, 1, 1, 0.15))
    border.width: 1

    Behavior on opacity {
      NumberAnimation { duration: 150 }
    }

    RowLayout {
      id: contentRow
      anchors.centerIn: parent
      spacing: 6

      Text {
        text: isBusy ? "\uf021" : (errorMessage ? "\uf071" : "\uf129")
        font.family: toastRoot.fontFamily
        font.pixelSize: Style.font.bodySmall
        color: "#ffffff"
      }

      Text {
        id: messageText
        text: errorMessage || statusMessage || (isBusy ? "Processing..." : "")
        color: "#ffffff"
        font.pixelSize: Style.font.bodySmall
        font.weight: Font.Medium
        elide: Text.ElideRight
        Layout.preferredWidth: implicitWidth
        Layout.maximumWidth: toastRoot.maxMessageWidth

        MouseArea {
          id: messageHoverArea
          anchors.fill: parent
          hoverEnabled: true
          acceptedButtons: Qt.NoButton
          ToolTip.visible: containsMouse && messageText.truncated
          ToolTip.delay: 300
          ToolTip.text: messageText.text
        }
      }

      Text {
        visible: !isBusy && Boolean(errorMessage || statusMessage)
        text: "\uf00d"
        font.family: toastRoot.fontFamily
        color: Qt.rgba(1, 1, 1, 0.6)
        font.pixelSize: Style.font.caption
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: toastRoot.clearRequested()
        }
      }
    }
  }
}
