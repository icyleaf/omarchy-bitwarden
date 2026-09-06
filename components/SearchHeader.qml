import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
  id: searchHeaderRoot

  property alias searchQuery: searchInputField.text
  property alias searchField: searchInputField
  property alias categoryTabBar: catBar
  property var categoryList: ["all", "login", "card", "identity", "note", "ssh_key"]
  property string activeCategory: "all"
  property var rawVaultItems: []
  property color background: "#1f2937"
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""
  property bool modalsActive: false

  property string activeVaultScope: "all"
  property string activeFolderScope: "all"

  signal categorySelected(string category)
  signal vaultScopeSelected(string scope)
  signal folderScopeSelected(string scope)
  signal clearSearchRequested()
  signal createSshKeyRequested()
  signal importSshKeyRequested()
  signal copyUsernameRequested()
  signal copyTotpRequested()
  signal openUrlRequested()
  signal actionPaletteRequested()
  signal exportSshKeyRequested()

  property alias isScopeDropdownOpen: vaultScopeDropdown.isOpen
  property alias isVaultScopeOpen: vaultScopeDropdown.isOpen
  property alias isFolderScopeOpen: folderScopeDropdown.isOpen

  function openVaultScope() {
    if (vaultScopeDropdown.isOpen) {
      vaultScopeDropdown.cycleNext()
    } else {
      vaultScopeDropdown.open()
    }
  }

  function openFolderScope() {
    if (folderScopeDropdown.isOpen) {
      folderScopeDropdown.cycleNext()
    } else {
      folderScopeDropdown.open()
    }
  }

  function closeScopeDropdowns() {
    vaultScopeDropdown.close()
    folderScopeDropdown.close()
  }

  function computeVaultScopes() {
    var items = searchHeaderRoot.rawVaultItems || []
    var personalCount = 0
    var orgMap = {}
    for (var i = 0; i < items.length; i++) {
      var it = items[i]
      if (!it.organization_id) {
        personalCount++
      } else {
        var orgId = it.organization_id
        var orgName = it.organization_name || "Organization"
        if (!orgMap[orgId]) {
          orgMap[orgId] = { id: orgId, name: orgName, icon: "\uf1ad", count: 0 }
        }
        orgMap[orgId].count++
      }
    }

    var list = [
      { id: "all", name: "All Vaults", icon: "\uf009", count: items.length },
      { id: "personal", name: "Personal", icon: "\uf007", count: personalCount }
    ]

    var orgKeys = Object.keys(orgMap)
    orgKeys.sort(function(a, b) {
      return orgMap[a].name.localeCompare(orgMap[b].name)
    })

    for (var k = 0; k < orgKeys.length; k++) {
      list.push(orgMap[orgKeys[k]])
    }

    return list
  }

  function computeFolderScopes() {
    var items = searchHeaderRoot.rawVaultItems || []
    var noFolderCount = 0
    var folderMap = {}
    for (var i = 0; i < items.length; i++) {
      var it = items[i]
      if (!it.folder_id && !it.folder_name) {
        noFolderCount++
      } else {
        var fId = it.folder_id || it.folder_name
        var fName = it.folder_name || "Folder"
        if (!folderMap[fId]) {
          folderMap[fId] = { id: fId, name: fName, icon: "\uf07b", count: 0 }
        }
        folderMap[fId].count++
      }
    }

    var list = [
      { id: "all", name: "All Folders", icon: "\uf07b", count: items.length }
    ]

    if (noFolderCount > 0) {
      list.push({ id: "none", name: "No Folder", icon: "\uf016", count: noFolderCount })
    }

    var folderKeys = Object.keys(folderMap)
    folderKeys.sort(function(a, b) {
      return folderMap[a].name.localeCompare(folderMap[b].name)
    })

    for (var j = 0; j < folderKeys.length; j++) {
      list.push(folderMap[folderKeys[j]])
    }

    return list
  }

  function focusSearch() {
    searchInputField.forceActiveFocus()
  }

  spacing: 6
  Layout.fillWidth: true

  onVisibleChanged: {
    if (visible) {
      Qt.callLater(function() {
        focusSearch()
      })
    }
  }

  // 1. Search Box Bar
  Rectangle {
    Layout.fillWidth: true
    height: 34
    radius: 6
    color: Qt.rgba(0, 0, 0, 0.25)
    border.color: searchInputField.activeFocus ? searchHeaderRoot.accent : searchHeaderRoot.borderColor
    border.width: 1

    RowLayout {
      anchors.fill: parent
      anchors.leftMargin: 6
      anchors.rightMargin: 6
      spacing: 6

      // Vault / Organization Scope Dropdown (Replaces static magnifying glass)
      ScopeDropdown {
        id: vaultScopeDropdown
        title: "Vault"
        currentValue: searchHeaderRoot.activeVaultScope
        items: searchHeaderRoot.computeVaultScopes()
        foreground: searchHeaderRoot.foreground
        accent: searchHeaderRoot.accent
        borderColor: searchHeaderRoot.borderColor
        fontFamily: searchHeaderRoot.fontFamily
        maxLabelWidth: 120
        Layout.alignment: Qt.AlignVCenter
        onSelected: function(id) {
          searchHeaderRoot.vaultScopeSelected(id)
          searchHeaderRoot.focusSearch()
        }
        onResetRequested: {
          searchHeaderRoot.vaultScopeSelected("all")
          searchHeaderRoot.focusSearch()
        }
        onClosed: {
          searchHeaderRoot.focusSearch()
        }
      }

      Item {
        Layout.fillWidth: true
        Layout.fillHeight: true

        TextInput {
          id: searchInputField
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          color: searchHeaderRoot.foreground
          font.family: "sans-serif"
          font.pixelSize: 12
          selectByMouse: true
          clip: true

          Keys.priority: Keys.BeforeItem
          Keys.onPressed: function(event) {
            if (searchHeaderRoot.modalsActive) return

            if (event.modifiers & Qt.AltModifier) {
              if (event.key === Qt.Key_V || (event.text && event.text.toLowerCase() === "v")) {
                searchHeaderRoot.openVaultScope()
                event.accepted = true
                return
              } else if (event.key === Qt.Key_F || (event.text && event.text.toLowerCase() === "f")) {
                searchHeaderRoot.openFolderScope()
                event.accepted = true
                return
              }
            }

            if (event.modifiers & Qt.ControlModifier) {
              if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                searchHeaderRoot.copyTotpRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_U) {
                searchHeaderRoot.copyUsernameRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_O) {
                searchHeaderRoot.openUrlRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_K) {
                searchHeaderRoot.actionPaletteRequested()
                event.accepted = true
              } else if (event.key === Qt.Key_E) {
                searchHeaderRoot.exportSshKeyRequested()
                event.accepted = true
              }
            }

            if (event.key === Qt.Key_Escape) {
              if (vaultScopeDropdown.isOpen) {
                vaultScopeDropdown.close()
                event.accepted = true
                return
              }
              if (folderScopeDropdown.isOpen) {
                folderScopeDropdown.close()
                event.accepted = true
                return
              }
              if (searchInputField.text.length > 0) {
                searchInputField.text = ""
                searchHeaderRoot.clearSearchRequested()
                event.accepted = true
                return
              }
              if (searchHeaderRoot.activeVaultScope !== "all" || searchHeaderRoot.activeFolderScope !== "all") {
                searchHeaderRoot.vaultScopeSelected("all")
                searchHeaderRoot.folderScopeSelected("all")
                event.accepted = true
                return
              }
            }
          }
        }

        Text {
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: "Search Bitwarden vault (names, usernames, notes, tags)..."
          color: Qt.darker(searchHeaderRoot.foreground, 2.0)
          font.family: "sans-serif"
          font.pixelSize: 12
          visible: !searchInputField.text
        }
      }

      // Clear search button (placed before Folder Scope Dropdown)
      Text {
        visible: Boolean(searchInputField.text)
        text: "\uf00d"
        font.family: searchHeaderRoot.fontFamily
        color: clearMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.5)
        font.pixelSize: 11
        Layout.alignment: Qt.AlignVCenter

        MouseArea {
          id: clearMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: {
            searchInputField.text = ""
            searchHeaderRoot.clearSearchRequested()
            searchInputField.forceActiveFocus()
          }
        }
      }

      // Folder Scope Dropdown
      ScopeDropdown {
        id: folderScopeDropdown
        title: "Folder"
        currentValue: searchHeaderRoot.activeFolderScope
        items: searchHeaderRoot.computeFolderScopes()
        foreground: searchHeaderRoot.foreground
        accent: searchHeaderRoot.accent
        borderColor: searchHeaderRoot.borderColor
        fontFamily: searchHeaderRoot.fontFamily
        alignRight: true
        maxLabelWidth: 110
        Layout.alignment: Qt.AlignVCenter
        onSelected: function(id) {
          searchHeaderRoot.folderScopeSelected(id)
          searchHeaderRoot.focusSearch()
        }
        onResetRequested: {
          searchHeaderRoot.folderScopeSelected("all")
          searchHeaderRoot.focusSearch()
        }
        onClosed: {
          searchHeaderRoot.focusSearch()
        }
      }
    }
  }

  // 2. Category Tab Bar & Action Buttons
  RowLayout {
    Layout.fillWidth: true
    spacing: 8

    CategoryTabBar {
      id: catBar
      categoryList: searchHeaderRoot.categoryList
      activeCategory: searchHeaderRoot.activeCategory
      activeVaultScope: searchHeaderRoot.activeVaultScope
      activeFolderScope: searchHeaderRoot.activeFolderScope
      rawVaultItems: searchHeaderRoot.rawVaultItems
      foreground: searchHeaderRoot.foreground
      accent: searchHeaderRoot.accent
      borderColor: searchHeaderRoot.borderColor
      onCategorySelected: function(cat) {
        searchHeaderRoot.categorySelected(cat)
      }
    }

    Item { Layout.fillWidth: true }

    // SSH Key Category Actions
    RowLayout {
      visible: searchHeaderRoot.activeCategory === "ssh_key"
      spacing: 4

      Rectangle {
        implicitWidth: 18
        implicitHeight: 18
        radius: 4
        color: createMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"

        Text {
          anchors.centerIn: parent
          text: "\uf067"
          font.family: searchHeaderRoot.fontFamily
          font.pixelSize: 10
          color: createMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.4)
        }

        MouseArea {
          id: createMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: searchHeaderRoot.createSshKeyRequested()

          ToolTip.visible: containsMouse
          ToolTip.delay: 300
          ToolTip.text: "Generate SSH Key"
        }
      }

      Rectangle {
        implicitWidth: 18
        implicitHeight: 18
        radius: 4
        color: importMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : "transparent"

        Text {
          anchors.centerIn: parent
          text: "\uf019"
          font.family: searchHeaderRoot.fontFamily
          font.pixelSize: 10
          color: importMouse.containsMouse ? searchHeaderRoot.foreground : Qt.darker(searchHeaderRoot.foreground, 1.4)
        }

        MouseArea {
          id: importMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: searchHeaderRoot.importSshKeyRequested()

          ToolTip.visible: containsMouse
          ToolTip.delay: 300
          ToolTip.text: "Import SSH Key"
        }
      }
    }
  }
}
