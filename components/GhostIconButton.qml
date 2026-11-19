import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: ghostBtnRoot

  property bool isBusy: false
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
  opacity: (enabled && !isBusy) ? 1.0 : 0.6
  color: (enabled && !isBusy && mouseArea.containsMouse) ? hoverBackground : "transparent"

  ToolTip.visible: Boolean(tooltip && mouseArea.containsMouse)
  ToolTip.delay: 400
  ToolTip.text: tooltip

  Text {
    id: iconLabel
    anchors.centerIn: parent
    text: ghostBtnRoot.isBusy ? "\uf110" : ghostBtnRoot.iconText
    color: ghostBtnRoot.isBusy ? ghostBtnRoot.muted : ghostBtnRoot.iconColor
    font.pixelSize: ghostBtnRoot.iconPixelSize
    font.family: ghostBtnRoot.fontFamily
    verticalAlignment: Text.AlignVCenter
    horizontalAlignment: Text.AlignHCenter
    rotation: 0

    NumberAnimation on rotation {
      running: ghostBtnRoot.isBusy
      from: 0
      to: 360
      loops: Animation.Infinite
      duration: 1000
      onRunningChanged: {
        if (!running) iconLabel.rotation = 0
      }
    }
  }

  MouseArea {
    id: mouseArea
    anchors.fill: parent
    enabled: ghostBtnRoot.enabled && !ghostBtnRoot.isBusy
    hoverEnabled: enabled
    cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
    onClicked: ghostBtnRoot.clicked()
  }
}
