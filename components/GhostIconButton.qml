import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: ghostBtnRoot

  property string iconText: ""
  property int iconPixelSize: Style.font.body
  property color foreground: Commons.Color.foreground
  property color muted: Commons.Color.muted
  property color iconColor: mouseArea.containsMouse ? foreground : muted
  property color hoverBackground: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.08)
  property string tooltip: ""
  property string fontFamily: ""

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
