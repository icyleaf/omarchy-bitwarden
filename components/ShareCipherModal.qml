import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Dedicated Share Cipher modal for personal-to-Organization ownership transfer
// (`PUT /ciphers/{id}/share`). Enforces writable-Organization selection, at least
// one writable Collection, and displays a prominent irreversible transfer warning.
Rectangle {
  id: modalRoot

  property bool active: false
  property string itemName: ""
  property var organizations: [] // [{ id, name }]
  property var collections: [] // [{ id, organization_id, name, read_only, hide_passwords, manage }]
  property bool isBusy: false
  property string errorMessage: ""

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  property string selectedOrganizationId: ""
  property var selectedCollectionIds: []

  readonly property color warningRole: StatusPalette.warn
  readonly property color confirmRole: StatusPalette.warn
  readonly property color textOnConfirm: StatusPalette.textOnTint(confirmRole, 1, cardBackground)
  readonly property color textOnAccent: StatusPalette.textOnTint(accent, 1, cardBackground)
  readonly property string title: "Share to Organization"
  readonly property string headline: "Share \"" + (itemName || "Untitled") + "\" to an Organization"
  readonly property string warningMessage: "Transferring ownership to an Organization is permanent and irreversible. This item can no longer be returned to your personal vault."
  readonly property string confirmLabel: "Share to Organization"

  readonly property var availableOrganizations: computeWritableOrganizations()
  readonly property var availableCollections: computeWritableCollections(selectedOrganizationId)
  readonly property bool canSubmit: !isBusy
    && Boolean(selectedOrganizationId)
    && Array.isArray(selectedCollectionIds)
    && selectedCollectionIds.length > 0

  signal confirmRequested(string organizationId, var collectionIds)
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

  function computeWritableCollections(orgId) {
    var out = []
    if (!orgId) return out
    var src = collections || []
    for (var i = 0; i < src.length; i++) {
      var col = src[i]
      if (!col || col.organization_id !== orgId) continue
      if (isWritableCollection(col)) out.push(col)
    }
    return out
  }

  function computeWritableOrganizations() {
    var out = []
    var orgs = organizations || []
    for (var i = 0; i < orgs.length; i++) {
      var org = orgs[i]
      if (!org || !org.id) continue
      if (computeWritableCollections(org.id).length > 0) {
        out.push(org)
      }
    }
    return out
  }

  function selectOrganization(orgId) {
    if (isBusy) return
    var nextId = String(orgId || "")
    if (nextId === selectedOrganizationId) return
    selectedOrganizationId = nextId
    selectedCollectionIds = []
    errorMessage = ""
  }

  function isCollectionSelected(colId) {
    return Array.isArray(selectedCollectionIds) && selectedCollectionIds.indexOf(colId) >= 0
  }

  function toggleCollection(colId) {
    if (isBusy || !colId) return
    var cols = availableCollections
    var valid = false
    for (var i = 0; i < cols.length; i++) {
      if (cols[i].id === colId) {
        valid = true
        break
      }
    }
    if (!valid) return
    var next = (selectedCollectionIds || []).slice()
    var idx = next.indexOf(colId)
    if (idx >= 0) next.splice(idx, 1)
    else next.push(colId)
    selectedCollectionIds = next
    errorMessage = ""
  }

  function submit() {
    if (isBusy) return
    if (!selectedOrganizationId) {
      errorMessage = "Select a target Organization."
      return
    }
    if (!selectedCollectionIds || selectedCollectionIds.length === 0) {
      errorMessage = "Select at least one writable collection."
      return
    }
    errorMessage = ""
    confirmRequested(selectedOrganizationId, selectedCollectionIds.slice())
  }

  function requestClose() {
    if (isBusy) return
    closeRequested()
  }

  function resetSelection() {
    errorMessage = ""
    selectedCollectionIds = []
    var orgs = computeWritableOrganizations()
    selectedOrganizationId = orgs.length > 0 ? orgs[0].id : ""
  }

  onActiveChanged: {
    if (active) {
      resetSelection()
    }
  }

  onOrganizationsChanged: {
    if (active && !selectedOrganizationId) {
      var orgs = computeWritableOrganizations()
      if (orgs.length > 0) selectedOrganizationId = orgs[0].id
    }
  }

  onCollectionsChanged: {
    if (active && !selectedOrganizationId) {
      var orgs = computeWritableOrganizations()
      if (orgs.length > 0) selectedOrganizationId = orgs[0].id
    }
  }

  MouseArea {
    anchors.fill: parent
    onClicked: modalRoot.requestClose()
  }

  // Modal Dialog Card
  Rectangle {
    id: modalCard
    objectName: "shareCipherModalCard"
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
          text: "\uf1e0"
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
        objectName: "shareErrorBanner"
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

      // Headline
      Text {
        Layout.fillWidth: true
        text: modalRoot.headline
        color: modalRoot.foreground
        font.pixelSize: Style.font.body
        font.weight: Font.Medium
        wrapMode: Text.Wrap
      }

      // Prominent irreversible ownership-transfer warning banner
      Rectangle {
        objectName: "shareWarningBanner"
        Layout.fillWidth: true
        implicitHeight: warningRow.implicitHeight + 16
        radius: 5
        color: StatusPalette.tint(modalRoot.warningRole, 0.15)
        border.color: modalRoot.warningRole
        border.width: 1

        RowLayout {
          id: warningRow
          anchors.fill: parent
          anchors.margins: 8
          spacing: 8

          Text {
            text: "\uf071"
            font.family: modalRoot.fontFamily
            font.pixelSize: Style.font.bodySmall
            color: modalRoot.warningRole
          }

          Text {
            Layout.fillWidth: true
            text: modalRoot.warningMessage
            color: StatusPalette.labelOnTint(modalRoot.warningRole, 0.15, modalRoot.cardBackground)
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.Wrap
          }
        }
      }

      // Empty state if no writable Organizations exist
      Text {
        visible: modalRoot.availableOrganizations.length === 0
        Layout.fillWidth: true
        text: "No Organizations with writable collections are available. Sync the vault or check your collection permissions."
        color: modalRoot.muted
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }

      // Organization selector
      ColumnLayout {
        visible: modalRoot.availableOrganizations.length > 0
        Layout.fillWidth: true
        spacing: 6

        Text {
          text: "Organization"
          color: modalRoot.muted
          font.pixelSize: Style.font.caption
          font.weight: Font.DemiBold
        }

        Flow {
          Layout.fillWidth: true
          spacing: 6

          Repeater {
            model: modalRoot.availableOrganizations
            delegate: Rectangle {
              property bool isSelected: modelData.id === modalRoot.selectedOrganizationId
              implicitHeight: 28
              implicitWidth: orgPillRow.implicitWidth + 16
              radius: 5
              color: isSelected
                ? modalRoot.accent
                : (orgPillMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.08) : "transparent")
              border.color: isSelected ? modalRoot.accent : modalRoot.borderColor
              border.width: 1

              RowLayout {
                id: orgPillRow
                anchors.centerIn: parent
                spacing: 6

                Text {
                  text: "\uf1ad"
                  font.family: modalRoot.fontFamily
                  font.pixelSize: Style.font.caption
                  color: isSelected ? modalRoot.textOnAccent : modalRoot.muted
                }

                Text {
                  text: modelData.name || modelData.id
                  color: isSelected ? modalRoot.textOnAccent : modalRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: isSelected ? Font.DemiBold : Font.Normal
                }
              }

              MouseArea {
                id: orgPillMouse
                anchors.fill: parent
                enabled: !modalRoot.isBusy
                hoverEnabled: true
                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: modalRoot.selectOrganization(modelData.id)
              }
            }
          }
        }
      }

      // Required writable-Collection checklist
      ColumnLayout {
        visible: modalRoot.availableOrganizations.length > 0
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          Layout.fillWidth: true
          spacing: 6

          Text {
            text: "Collections (select at least one)"
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
          Layout.preferredHeight: Math.min(150, Math.max(40, modalRoot.availableCollections.length * 34))
          clip: true
          ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

          ColumnLayout {
            width: parent.width
            spacing: 4

            Repeater {
              model: modalRoot.availableCollections
              delegate: Rectangle {
                property bool checked: modalRoot.isCollectionSelected(modelData.id)
                Layout.fillWidth: true
                implicitHeight: 30
                radius: 4
                color: checked
                  ? Qt.rgba(modalRoot.accent.r, modalRoot.accent.g, modalRoot.accent.b, 0.14)
                  : (colMouse.containsMouse ? Qt.rgba(modalRoot.foreground.r, modalRoot.foreground.g, modalRoot.foreground.b, 0.06) : "transparent")
                border.color: checked ? modalRoot.accent : modalRoot.borderColor
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  spacing: 8

                  Text {
                    text: checked ? "\uf14a" : "\uf096"
                    font.family: modalRoot.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    color: checked ? modalRoot.accent : modalRoot.muted
                  }

                  Text {
                    Layout.fillWidth: true
                    text: modelData.name || modelData.id
                    color: modalRoot.foreground
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }
                }

                MouseArea {
                  id: colMouse
                  anchors.fill: parent
                  enabled: !modalRoot.isBusy
                  hoverEnabled: true
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
          objectName: "shareConfirmButton"
          implicitHeight: 30
          implicitWidth: Math.max(130, confirmText.implicitWidth + 24)
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
              text: modalRoot.isBusy ? "Sharing..." : modalRoot.confirmLabel
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
