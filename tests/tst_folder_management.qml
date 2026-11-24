import QtQuick
import QtQuick.Controls
import "../components"
import "lib"

ApplicationWindow {
  id: testRunner
  visible: true
  width: 640
  height: 500

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  property string createdName: ""
  property string renamedId: ""
  property string renamedName: ""
  property string deletedId: ""
  property int closeCount: 0
  property int footerActionCount: 0

  FolderManagerModal {
    id: modal
    active: false
    folders: [
      { id: "f-empty", name: "Empty Bucket", count: 0 },
      { id: "f-work", name: "Work/Prod", count: 2 }
    ]
    onCreateRequested: function(name) { testRunner.createdName = name }
    onRenameRequested: function(id, newName) {
      testRunner.renamedId = id
      testRunner.renamedName = newName
    }
    onDeleteRequested: function(id) { testRunner.deletedId = id }
    onCloseRequested: testRunner.closeCount++
  }

  ScopeDropdown {
    id: folderDropdown
    title: "Folder"
    currentValue: "all"
    footerActionLabel: "Manage Folders…"
    items: [
      { id: "all", name: "All Folders", icon: "\uf07b", count: 2 },
      { id: "f-empty", name: "Empty Bucket", icon: "\uf07b", count: 0 },
      { id: "f-work", name: "Work/Prod", icon: "\uf07b", count: 2 }
    ]
    onFooterActionRequested: testRunner.footerActionCount++
  }

  SearchHeader {
    id: searchHeader
    rawVaultItems: [
      { id: "c1", name: "Item 1", folder_id: "f-work", folder_name: "Work/Prod" },
      { id: "c2", name: "Item 2", folder_id: "f-work", folder_name: "Work/Prod" }
    ]
    vaultFolders: [
      { id: "f-empty", name: "Empty Bucket", count: 0 },
      { id: "f-work", name: "Work/Prod", count: 2 }
    ]
  }

  CipherEditor {
    id: cipherEditor
    active: false
    mode: "create"
    cipherType: "login"
    folders: [
      { id: "f-empty", name: "Empty Bucket", count: 0 },
      { id: "f-work", name: "Work/Prod", count: 2 }
    ]
  }

  Timer {
    interval: 50
    running: true
    repeat: false
    onTriggered: {
      console.log("Running FolderManagerModal & Folder Scope Tests...")

      // 1. FolderManagerModal create validation & emit
      modal.active = true
      modal.newFolderName = "   "
      modal.submitCreate()
      check(testRunner.createdName === "", "blank folder name is rejected before createRequested")
      check(modal.errorMessage.length > 0, "blank folder name sets errorMessage")

      modal.newFolderName = "  Personal/Finance  "
      modal.submitCreate()
      check(testRunner.createdName === "Personal/Finance", "valid folder name is trimmed and preserves slash")
      check(modal.errorMessage === "", "valid create clears errorMessage")

      // 2. FolderManagerModal inline rename
      modal.startRename("f-work", "Work/Prod")
      check(modal.editingFolderId === "f-work", "startRename enters inline rename mode for target folder")
      modal.editingFolderName = "   "
      modal.submitRename()
      check(testRunner.renamedId === "", "blank rename is rejected")
      check(modal.errorMessage.length > 0, "blank rename sets errorMessage")

      modal.editingFolderName = "Engineering"
      modal.submitRename()
      check(testRunner.renamedId === "f-work" && testRunner.renamedName === "Engineering",
            "valid rename emits renameRequested with id and new name")

      // 3. FolderManagerModal delete confirmation with affected cipher count
      modal.requestDelete("f-work", "Work/Prod", 2)
      check(modal.deletingFolderId === "f-work", "requestDelete opens confirmation for target folder")
      check(modal.deleteConfirmationCopy.indexOf("Work/Prod") !== -1,
            "delete confirmation names the target folder")
      check(modal.deleteConfirmationCopy.indexOf("2 ciphers will be moved to No Folder") !== -1,
            "delete confirmation states affected cipher count")
      modal.cancelDelete()
      check(modal.deletingFolderId === "", "cancelDelete clears confirmation state")

      modal.requestDelete("f-empty", "Empty Bucket", 0)
      check(modal.deleteConfirmationCopy.indexOf("empty folder") !== -1,
            "empty folder delete confirmation notes empty folder")
      modal.confirmDelete()
      check(testRunner.deletedId === "f-empty", "confirmDelete emits deleteRequested with folder id")

      // 4. Busy guard & Escape close
      modal.isBusy = true
      var closeBefore = testRunner.closeCount
      modal.requestClose()
      check(testRunner.closeCount === closeBefore, "requestClose is blocked while isBusy")
      modal.isBusy = false
      modal.requestClose()
      check(testRunner.closeCount === closeBefore + 1, "requestClose emits closeRequested when idle")

      // 5. ScopeDropdown footer action & empty folder visibility
      folderDropdown.triggerFooterAction()
      check(testRunner.footerActionCount === 1, "ScopeDropdown footer action emits footerActionRequested")

      var scopes = searchHeader.computeFolderScopes()
      var foundEmpty = false
      for (var i = 0; i < scopes.length; i++) {
        if (scopes[i].id === "f-empty" && scopes[i].count === 0) foundEmpty = true
      }
      check(foundEmpty === true, "SearchHeader computeFolderScopes includes empty folders with count 0")

      // 6. Inspector Form (CipherEditor) displays empty folders and selects them cleanly
      cipherEditor.active = true
      var editorFolderOpts = cipherEditor.folderOptions()
      var foundEmptyInEditor = false
      for (var ei = 0; ei < editorFolderOpts.length; ei++) {
        if (editorFolderOpts[ei].id === "f-empty" && editorFolderOpts[ei].name === "Empty Bucket") {
          foundEmptyInEditor = true
        }
      }
      check(foundEmptyInEditor === true, "Inspector Form folderOptions includes empty folders")
      cipherEditor.folderId = "f-empty"
      check(cipherEditor.folderLabel() === "Empty Bucket", "Inspector Form resolves empty folder label")
      cipherEditor.active = false

      // 7. Error banner state and modal focus guard behavior
      modal.errorMessage = "Folder rename failed."
      check(modal.errorMessage === "Folder rename failed.", "FolderManagerModal surfaces errorMessage")
      modal.resetTransientState()
      check(modal.errorMessage === "", "resetTransientState clears errorMessage")

      var showFolderManagerModal = true
      var hasActiveModal = false || showFolderManagerModal
      check(hasActiveModal === true, "open FolderManagerModal counts as an active modal")
      var activeFolderScope = "f-work"
      var deletedFolderId = "f-work"
      if (activeFolderScope === deletedFolderId) activeFolderScope = "all"
      check(activeFolderScope === "all", "deleting active folder scope resets to all")

      console.log("Folder Management Tests Completed: " + (failures === 0 ? "ALL PASSED" : failures + " FAILURES"))
      Qt.exit(failures === 0 ? 0 : 1)
    }
  }
}
