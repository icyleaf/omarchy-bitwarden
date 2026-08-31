import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: toastRoot

  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  readonly property string fontFamily: Style.font.menuFamily

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
        font.pixelSize: 11
        color: "#ffffff"
      }

      Text {
        text: errorMessage || statusMessage || (isBusy ? "Processing..." : "")
        color: "#ffffff"
        font.pixelSize: 11
        font.weight: Font.Medium
        elide: Text.ElideRight
        Layout.maximumWidth: 320
      }

      Text {
        visible: !isBusy && Boolean(errorMessage || statusMessage)
        text: "\uf00d"
        font.family: toastRoot.fontFamily
        color: Qt.rgba(1, 1, 1, 0.6)
        font.pixelSize: 10
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: toastRoot.clearRequested()
        }
      }
    }
  }
}
