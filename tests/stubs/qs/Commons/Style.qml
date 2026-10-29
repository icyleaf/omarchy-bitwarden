pragma Singleton
import QtQuick

// Stand-in for Omarchy's qs.Commons Style, whose real module needs the
// Quickshell runtime. Lets component tests run under plain `qml6`:
//   qml6 -I tests/stubs tests/tst_ssh_approval_modal.qml
QtObject {
  id: root
  property int fontBaseSize: 12
  function fontPx(mult) {
    return Math.max(1, Math.round(fontBaseSize * mult))
  }
  readonly property QtObject font: QtObject {
    readonly property int caption: root.fontPx(0.833)
    readonly property int bodySmall: root.fontPx(0.917)
    readonly property int body: root.fontPx(1)
    readonly property int subtitle: root.fontPx(1.083)
    readonly property int title: root.fontPx(1.167)
    readonly property int heading: root.fontPx(1.333)
    readonly property int display: root.fontPx(2.0)
    readonly property int displayLarge: root.fontPx(2.333)

    readonly property int iconSmall: bodySmall
    readonly property int icon: title
    readonly property int iconLarge: root.fontPx(1.5)
  }
  readonly property int cornerRadius: 8
}
