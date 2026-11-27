import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Dedicated Collection Assignment modal for Organization Ciphers
// (`PUT /ciphers/{id}/collections_v2`). Renders non-writable Collections
// (`read_only && !manage`) as locked/read-only so users can inspect full
// assignment without toggling restricted Collections, and disables submit when
// no Collections remain selected.
Rectangle {
  id: modalRoot

  property bool active: false
  property string itemName: ""
  property string organizationId: ""
  property string organizationName: ""
  property var initialCollectionIds: [] // [colId, ...]
  property var collections: [] // [{ id, organization_id, name, read_only, hide_passwords, manage }]
  property bool isBusy: false
  property string errorMessage: ""

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  property var selectedCollectionIds: []

  readonly property color confirmRole: accent
  readonly property color textOnConfirm: StatusPalette.textOnTint(confirmRole, 1, cardBackground)
  readonly property string title: "Manage Collections"
  readonly property string headline: "Assign collections for \"" + (itemName || "Untitled") + "\""
  readonly property string confirmLabel: "Save Collections"

  readonly property var orgCollections: computeOrgCollections(organizationId)
  readonly property bool canSubmit: !isBusy
    && Boolean(organizationId)
    && Array.isArray(selectedCollectionIds)
    && selectedCollectionIds.length > 0

  signal confirmRequested(var collectionIds)
  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 126

  function isWritableCollection(col) {
    if (!col || !col.id) return false
    var readOnly = (col.read_only === undefined || col.read_only === null) ? true : Boolean(col.read_only)
    var manage = Boolean(col.manage)
    return !readOnly || manage
  }

  function computeOrgCollections(orgId) {
    var out = []
    if (!orgId) return out
    var src = collections || []
    for (var i = 0; i < src.length; i++) {
      var col = src[i]
      if (!col || col.organization_id !== orgId) continue
      out.push(col)
    }
    return out
  }

  function isCollectionSelected(colId) {
    return Array.isArray(selectedCollectionIds) && selectedCollectionIds.indexOf(colId) >= 0
  }

  function toggleCollection(colId) {
    if (isBusy || !colId) return
    var cols = orgCollections
    var targetCol = null
    for (var i = 0; i < cols.length; i++) {
      if (cols[i].id === colId) {
        targetCol = cols[i]
        break
      }
    }
    if (!targetCol || !isWritableCollection(targetCol)) return
    var next = (selectedCollectionIds || []).slice()
    var idx = next.indexOf(colId)
    if (idx >= 0) next.splice(idx, 1)
    else next.push(colId)
    selectedCollectionIds = next
    errorMessage = ""
  }

  function submit() {
    if (isBusy) return
    if (!selectedCollectionIds || selectedCollectionIds.length === 0) {
      errorMessage = "Select at least one collection. An Organization cipher must belong to at least one collection."
      return
    }
    errorMessage = ""
    confirmRequested(selectedCollectionIds.slice())
  }

  function requestClose() {
    if (isBusy) return
    closeRequested()
  }

  function resetSelection() {
    errorMessage = ""
    var src = Array.isArray(initialCollectionIds) ? initialCollectionIds : []
    var clean = []
    for (var i = 0; i < src.length; i++) {
      var cid = String(src[i] || "").trim()
      if (cid && clean.indexOf(cid) < 0) clean.push(cid)
    }
    selectedCollectionIds = clean
  }

  onActiveChanged: {
    if (active) {
      resetSelection()
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: modalRoot.requestClose()
  }

  // Modal Dialog Card
  Rectangle {
    id: modalCard
    objectName: "collectionAssignModalCard"
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 480)
    height: Math.min(parent.height - 48, contentColumn.implicitHeight + 36)
    radius: 10
    color: modalRoot.cardBackground
    border.color: modalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      id: contentColumn
      anchors.fill: parent
      anchors.margins: 18
      spacing: 12

      // Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          text: "\uf02c"
          font.family: modalRoot.fontFamily
          font.pixelSize: Style.font.subtitle
          color: modalRoot.accent
        }

        Text {
          text: modalRoot.title
          color: modalRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.DemiBold
        }

        Item { Layout.fillWidth: true }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: modalRoot.borderColor
      }

      // Error Alert Banner
      Rectangle {
        objectName: "collectionAssignErrorBanner"
        visible: Boolean(modalRoot.errorMessage)
        Layout.fillWidth: true
        implicitHeight: errText.implicitHeight + 12
        radius: 4
        color: StatusPalette.tint(StatusPalette.error, 0.15)
        border.color: StatusPalette.error
        border.width: 1

        RowLayout {
          anchors.fill: parent
          anchors.margins: 6
          spacing: 6

          Text {
            text: "\uf06a"
            font.family: modalRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: StatusPalette.labelOnTint(StatusPalette.error, 0.15, modalRoot.cardBackground)
          }

          Text {
            id: errText
            text: modalRoot.errorMessage
            color: StatusPalette.labelOnTint(StatusPalette.error, 0.15, modalRoot.cardBackground)
            font.pixelSize: Style.font.bodySmall
            Layout.fillWidth: true
            wrapMode: Text.Wrap
          }
        }
      }

      // Headline & Organization Context
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 2

        Text {
          Layout.fillWidth: true
          text: modalRoot.headline
          color: modalRoot.foreground
          font.pixelSize: Style.font.body
          font.weight: Font.Medium
          wrapMode: Text.Wrap
        }

        Text {
          visible: Boolean(modalRoot.organizationName || modalRoot.organizationId)
          Layout.fillWidth: true
          text: "Organization: " + (modalRoot.organizationName || modalRoot.organizationId)
          color: modalRoot.muted
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      // Empty state if no Collections exist for this Organization
      Text {
        visible: modalRoot.orgCollections.length === 0
        Layout.fillWidth: true
        text: "No collections found for this Organization in local cache. Sync the vault and try again."
        color: modalRoot.muted
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }

      // Collection checklist (writable toggleable; read-only locked)
      ColumnLayout {
        visible: modalRoot.orgCollections.length > 0
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          Text {
            text: "Collections (at least one required)"
            color: modalRoot.muted
            font.pixelSize: Style.font.caption
            font.weight: Font.DemiBold
          }

          Item { Layout.fillWidth: true }

          Text {
            text: (modalRoot.selectedCollectionIds ? modalRoot.selectedCollectionIds.length : 0) + " selected"
            color: modalRoot.canSubmit ? modalRoot.accent : modalRoot.muted
            font.pixelSize: Style.font.caption
          }
        }

        ScrollView {
          Layout.fillWidth: true
          Layout.preferredHeight: Math.min(200, Math.max(40, modalRoot.orgCollections.length * 34))
          clip: true
          ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

          ColumnLayout {
            width: parent.width
            spacing: 4

            Repeater {
              model: modalRoot.orgCollections
              delegate: Rectangle {
                property bool writable: modalRoot.isWritableCollection(modelData)
                property bool checked: modalRoot.isCollectionSelected(modelData.id)
                objectName: "collectionRow_" + modelData.id
                Layout.fillWidth: true
                implicitHeight: 30
                radius: 4
                opacity: writable ? 1.0 : 0.65
                color: checked
                  ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, writable ? 0.14 : 0.08)
                  : (writable && colMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06) : "transparent")
                border.color: checked && writable ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  spacing: 8

                  Text {
                    text: writable
                      ? (checked ? "\uf14a" : "\uf096")
                      : "\uf023"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    color: writable
                      ? (checked ? modalRoot.accent : modalRoot.muted)
                      : modalRoot.muted
                  }

                  Text {
                    Layout.fillWidth: true
                    text: modelData.name || modelData.id
                    color: writable ? modalRoot.foreground : modalRoot.muted
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }

                  Text {
                    visible: !writable
                    text: checked ? "Assigned · Read-only" : "Read-only"
                    color: modalRoot.muted
                    font.pixelSize: Style.font.caption
                  }
                }

                MouseArea {
                  id: colMouse
                  anchors.fill: parent
                  enabled: writable && !modalRoot.isBusy
                  hoverEnabled: writable
                  cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                  onClicked: modalRoot.toggleCollection(modelData.id)
                }
              }
            }
          }
        }
      }

      // Footer
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Item { Layout.fillWidth: true }

        Rectangle {
          implicitHeight: 30
          implicitWidth: 76
          radius: 4
          color: cancelMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08) : "transparent"
          border.color: modalRoot.borderColor
          border.width: 1

          Text {
            anchors.centerIn: parent
            text: "Cancel"
            color: cancelMouse.containsMouse ? modalRoot.foreground : modalRoot.muted
            font.pixelSize: Style.font.bodySmall
          }

          MouseArea {
            id: cancelMouse
            anchors.fill: parent
            enabled: !modalRoot.isBusy
            hoverEnabled: true
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.requestClose()
          }
        }

        Rectangle {
          objectName: "collectionAssignConfirmButton"
          implicitHeight: 30
          implicitWidth: Math.max(120, confirmText.implicitWidth + 24)
          radius: 4
          color: modalRoot.canSubmit
            ? (confirmMouse.containsMouse ? Qt.lighter(modalRoot.confirmRole, 1.1) : modalRoot.confirmRole)
            : Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.14)
          opacity: modalRoot.canSubmit ? 1.0 : 0.6

          RowLayout {
            anchors.centerIn: parent
            spacing: 6

            Text {
              visible: modalRoot.isBusy
              text: "\uf110"
              font.family: modalRoot.fontFamily
              font.pixelSize: Style.font.bodySmall
              color: modalRoot.textOnConfirm
            }

            Text {
              id: confirmText
              text: modalRoot.isBusy ? "Saving..." : modalRoot.confirmLabel
              color: modalRoot.canSubmit ? modalRoot.textOnConfirm : modalRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.DemiBold
            }
          }

          MouseArea {
            id: confirmMouse
            anchors.fill: parent
            enabled: modalRoot.canSubmit
            hoverEnabled: true
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: modalRoot.submit()
          }
        }
      }
    }
  }
}
