import QtQuick
import QtQuick.Controls

Rectangle {
  id: ghostBtnRoot

  property string iconText: ""
  property int iconPixelSize: 12
  property color foreground: "#ffffff"
  property color iconColor: mouseArea.containsMouse ? foreground : Qt.darker(foreground, 1.4)
  property color hoverBackground: Qt.rgba(1, 1, 1, 0.1)
  property string tooltip: ""

  readonly property string fontFamily: Style.font.menuFamily

  signal clicked()

  implicitWidth: 22
  implicitHeight: 22
  radius: 4
  color: mouseArea.containsMouse ? hoverBackground : "transparent"

  Text {
    anchors.centerIn: parent
    text: ghostBtnRoot.iconText
    color: ghostBtnRoot.iconColor
    font.pixelSize: ghostBtnRoot.iconPixelSize
    font.family: ghostBtnRoot.fontFamily
    verticalAlignment: Text.AlignVCenter
    horizontalAlignment: Text.AlignHCenter
  }

  MouseArea {
    id: mouseArea
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onClicked: ghostBtnRoot.clicked()
  }
}
