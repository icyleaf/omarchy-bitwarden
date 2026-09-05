import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
  id: historyModalRoot

  property bool active: false
  property var item: null
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  property bool allRevealed: false
  property var revealedIndexes: ({})

  signal copyRequested(string text, bool isSensitive, string label)
  signal closeRequested()

  anchors.fill: parent
  color: Qt.rgba(0, 0, 0, 0.65)
  visible: active
  z: 110

  Keys.onEscapePressed: historyModalRoot.closeRequested()

  Keys.onPressed: function(event) {
    if (event.key === Qt.Key_Escape) {
      historyModalRoot.closeRequested()
      event.accepted = true
    } else if (event.modifiers & Qt.ControlModifier) {
      if (event.key === Qt.Key_T) {
        historyModalRoot.toggleAllRevealed()
        event.accepted = true
      }
    }
  }

  onActiveChanged: {
    if (active) {
      allRevealed = false
      revealedIndexes = {}
      historyModalRoot.forceActiveFocus()
    }
  }

  function toggleAllRevealed() {
    allRevealed = !allRevealed
    var copy = {}
    var list = getHistoryList()
    for (var i = 0; i < list.length; i++) {
      copy[i] = allRevealed
    }
    revealedIndexes = copy
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return ""
    try {
      var d = new Date(dateStr)
      if (!isNaN(d.getTime())) {
        var year = d.getFullYear()
        var month = String(d.getMonth() + 1).padStart(2, '0')
        var day = String(d.getDate()).padStart(2, '0')
        var hours = String(d.getHours()).padStart(2, '0')
        var minutes = String(d.getMinutes()).padStart(2, '0')
        return year + "-" + month + "-" + day + " " + hours + ":" + minutes
      }
    } catch (e) {}
    return String(dateStr).substring(0, 16).replace("T", " ")
  }

  function getHistoryList() {
    if (!item || !item.login || !item.login.password_history) return []
    var list = item.login.password_history
    if (!Array.isArray(list)) return []
    // Show newest first
    return list.slice().reverse()
  }

  function isIndexRevealed(idx) {
    if (allRevealed) return true
    return Boolean(revealedIndexes && revealedIndexes[idx])
  }

  function toggleReveal(idx) {
    var list = getHistoryList()
    var copy = {}
    if (allRevealed) {
      for (var i = 0; i < list.length; i++) {
        copy[i] = (i !== idx)
      }
      allRevealed = false
    } else {
      copy = Object.assign({}, revealedIndexes || {})
      copy[idx] = !Boolean(copy[idx])
    }
    revealedIndexes = copy
  }

  MouseArea {
    anchors.fill: parent
    onClicked: historyModalRoot.closeRequested()
  }

  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 520)
    height: Math.min(parent.height - 48, 440)
    radius: 8
    color: Qt.rgba(0.12, 0.14, 0.18, 0.98)
    border.color: historyModalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 16
      spacing: 12

      // Modal Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: "\uf1da"
          font.family: historyModalRoot.fontFamily
          font.pixelSize: 14
          color: historyModalRoot.accent
        }

        Text {
          text: "Password History: " + (historyModalRoot.item ? (historyModalRoot.item.name || "Item") : "")
          color: historyModalRoot.foreground
          font.pixelSize: 13
          font.weight: Font.DemiBold
          elide: Text.ElideRight
          Layout.fillWidth: true
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: historyModalRoot.borderColor
      }

      // Scrollable History Content
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        ColumnLayout {
          width: modalCard.width - 32
          spacing: 8

          Repeater {
            model: historyModalRoot.getHistoryList()

            Rectangle {
              id: entryCard
              property bool isEntryRevealed: historyModalRoot.allRevealed || Boolean(historyModalRoot.revealedIndexes && historyModalRoot.revealedIndexes[index])

              Layout.fillWidth: true
              implicitHeight: entryCol.implicitHeight + 16
              radius: 6
              color: Qt.rgba(0, 0, 0, 0.25)
              border.color: historyModalRoot.borderColor
              border.width: 1

              ColumnLayout {
                id: entryCol
                anchors.fill: parent
                anchors.margins: 8
                spacing: 6

                // Last Used Date
                RowLayout {
                  Layout.fillWidth: true
                  spacing: 6

                  Text {
                    text: (modelData.last_used_date ? historyModalRoot.formatDateTime(modelData.last_used_date) : "Unknown date")
                    color: Qt.darker(historyModalRoot.foreground, 1.5)
                    font.pixelSize: 10
                    font.weight: Font.Medium
                    Layout.fillWidth: true
                  }

                  Text {
                    text: "#" + (historyModalRoot.getHistoryList().length - index)
                    color: Qt.darker(historyModalRoot.foreground, 2.0)
                    font.pixelSize: 9
                  }
                }

                // Password Row
                RowLayout {
                  Layout.fillWidth: true
                  spacing: 8

                  Text {
                    text: entryCard.isEntryRevealed ? ((modelData && modelData.password) ? modelData.password : "") : "••••••••••••••••"
                    color: historyModalRoot.foreground
                    font.pixelSize: 12
                    font.family: entryCard.isEntryRevealed ? "monospace" : "sans-serif"
                    font.weight: Font.Medium
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                  }

                  // Toggle Mask Ghost Button
                  GhostIconButton {
                    iconText: entryCard.isEntryRevealed ? "\uf070" : "\uf06e"
                    tooltip: entryCard.isEntryRevealed ? "Hide password" : "Show password"
                    fontFamily: historyModalRoot.fontFamily
                    onClicked: historyModalRoot.toggleReveal(index)
                  }

                  // Copy Ghost Button
                  GhostIconButton {
                    iconText: "\uf0c5"
                    tooltip: "Copy history password"
                    fontFamily: historyModalRoot.fontFamily
                    onClicked: historyModalRoot.copyRequested((modelData && modelData.password) ? modelData.password : "", true, "history password")
                  }
                }
              }
            }
          }

          // Empty state fallback (just in case)
          Text {
            visible: historyModalRoot.getHistoryList().length === 0
            text: "No password history available for this item."
            color: Qt.darker(historyModalRoot.foreground, 1.8)
            font.pixelSize: 11
            Layout.alignment: Qt.AlignCenter
          }
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: historyModalRoot.borderColor
      }

      // Footer
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: historyModalRoot.getHistoryList().length + " past password(s) recorded"
          color: Qt.darker(historyModalRoot.foreground, 1.8)
          font.pixelSize: 10
          Layout.fillWidth: true
        }

        // Toggle Mask Ghost Button
        GhostIconButton {
          visible: historyModalRoot.getHistoryList().length > 0
          iconText: historyModalRoot.allRevealed ? "\uf070" : "\uf06e"
          tooltip: historyModalRoot.allRevealed ? "Hide all passwords (Ctrl+T)" : "Show all passwords (Ctrl+T)"
          fontFamily: historyModalRoot.fontFamily
          onClicked: historyModalRoot.toggleAllRevealed()
        }

        // Close Button
        Rectangle {
          implicitHeight: 26
          implicitWidth: closeBtnText.implicitWidth + 16
          radius: 4
          color: Qt.rgba(1, 1, 1, 0.08)
          border.color: historyModalRoot.borderColor
          border.width: 1

          Text {
            id: closeBtnText
            anchors.centerIn: parent
            text: "Close"
            color: historyModalRoot.foreground
            font.pixelSize: 10
            font.weight: Font.Medium
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: historyModalRoot.closeRequested()
          }
        }
      }
    }
  }
}
