import QtQuick
import QtQuick.Controls

Item {
  id: testRunner
  width: 400
  height: 300

  // State under test reproducing OmarchyBitwarden properties
  property var authState: ({
    status: "unlocked",
    server_url: "https://vault.example.com",
    user_email: "test@example.com",
    has_session: true
  })

  property var rawVaultItems: []
  property var filteredItems: []
  property string lastVaultItemsRawText: ""
  property real lastSyncTime: 0
  property string searchQuery: ""
  property string activeCategory: "all"
  property string activeVaultScope: "all"
  property string activeFolderScope: "all"
  property int selectedIndex: 0

  property bool showPasswordRevealed: false
  property bool showPrivateKeyRevealed: false
  property bool showCardNumberRevealed: false
  property bool showCardCodeRevealed: false
  property bool showCustomHiddenRevealed: false
  property var currentTotp: ({ code: "", ttl: 30, period: 30 })

  property bool showActionPalette: false
  property int actionPaletteIndex: 0
  property var currentAvailableActions: []

  property bool showSshKeyModal: false
  property var sshKeyModalItem: null

  property bool showPasswordHistoryModal: false
  property var activePasswordHistoryItem: null

  property var activeAttachmentPreview: null
  property string loadingAttachmentId: ""

  function clearSensitiveState() {
    testRunner.rawVaultItems = []
    testRunner.filteredItems = []
    testRunner.lastVaultItemsRawText = ""
    testRunner.lastSyncTime = 0
    testRunner.searchQuery = ""
    testRunner.activeCategory = "all"
    testRunner.activeVaultScope = "all"
    testRunner.activeFolderScope = "all"
    testRunner.selectedIndex = 0

    testRunner.showPasswordRevealed = false
    testRunner.showPrivateKeyRevealed = false
    testRunner.showCardNumberRevealed = false
    testRunner.showCardCodeRevealed = false
    testRunner.showCustomHiddenRevealed = false
    testRunner.currentTotp = ({ code: "", ttl: 30, period: 30 })

    testRunner.showActionPalette = false
    testRunner.actionPaletteIndex = 0
    testRunner.currentAvailableActions = []

    testRunner.showPasswordHistoryModal = false
    testRunner.activePasswordHistoryItem = null

    testRunner.showSshKeyModal = false
    testRunner.sshKeyModalItem = null

    testRunner.activeAttachmentPreview = null
    testRunner.loadingAttachmentId = ""
  }

  function doLock() {
    testRunner.clearSensitiveState()
    testRunner.authState = ({
      status: "locked",
      server_url: (testRunner.authState && testRunner.authState.server_url) || "",
      user_email: (testRunner.authState && testRunner.authState.user_email) || "",
      has_session: Boolean(testRunner.authState && testRunner.authState.has_session)
    })
  }

  // Simulated asynchronous handler for vaultListProc
  function simulateVaultListFinished(rawJsonText) {
    if (!testRunner.authState || testRunner.authState.status !== "unlocked") {
      testRunner.clearSensitiveState()
      return
    }
    testRunner.rawVaultItems = JSON.parse(rawJsonText) || []
  }

  // Simulated asynchronous handler for attachmentProc
  function simulateAttachmentFinished(rawJsonText) {
    if (!testRunner.authState || testRunner.authState.status !== "unlocked") {
      testRunner.activeAttachmentPreview = null
      return
    }
    testRunner.activeAttachmentPreview = JSON.parse(rawJsonText)
  }

  // Simulated asynchronous handler for totpGenProc
  function simulateTotpFinished(rawJsonText) {
    if (!testRunner.authState || testRunner.authState.status !== "unlocked") {
      testRunner.currentTotp = ({ code: "", ttl: 30, period: 30 })
      return
    }
    testRunner.currentTotp = JSON.parse(rawJsonText)
  }

  function assert(condition, message) {
    if (!condition) {
      console.error("ASSERTION FAILED: " + message)
      Qt.quit()
      throw new Error("Assertion failed: " + message)
    } else {
      console.log("PASS: " + message)
    }
  }

  Component.onCompleted: {
    console.log("Running Frontend Lock Cleanup and Async Guard Tests...")

    // 1. Populate state with secret-bearing items, modals, and actions
    rawVaultItems = [{ id: "item-1", name: "Secret Item", login: { password: "SecretPassword123" } }]
    filteredItems = rawVaultItems
    lastVaultItemsRawText = JSON.stringify(rawVaultItems)
    searchQuery = "secret"
    showPasswordRevealed = true
    showPrivateKeyRevealed = true
    showCardNumberRevealed = true
    showCardCodeRevealed = true
    showCustomHiddenRevealed = true
    currentTotp = ({ code: "123456", ttl: 25, period: 30 })

    showActionPalette = true
    actionPaletteIndex = 2
    currentAvailableActions = [
      { name: "Copy Password", action: function() { return "SecretPassword123" } }
    ]

    showPasswordHistoryModal = true
    activePasswordHistoryItem = {
      id: "item-1",
      name: "Secret Item",
      passwordHistory: [{ password: "OldPassword1", lastUsedDate: "2026-01-01" }]
    }

    showSshKeyModal = true
    sshKeyModalItem = {
      id: "ssh-1",
      name: "Prod Key",
      ssh_key: { privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----..." }
    }

    activeAttachmentPreview = {
      action: "preview",
      filename: "secret.txt",
      text: "Confidential financial report"
    }
    loadingAttachmentId = "att-123"

    assert(rawVaultItems.length === 1, "Initial vault items populated")
    assert(activePasswordHistoryItem !== null, "Initial password history item populated")
    assert(activeAttachmentPreview !== null, "Initial attachment preview populated")
    assert(sshKeyModalItem !== null, "Initial SSH key item populated")
    assert(currentAvailableActions.length === 1, "Initial action closures populated")

    // 2. Perform doLock()
    doLock()

    // 3. Verify all secrets, closures, modals, and reveal flags are thoroughly wiped
    assert(authState.status === "locked", "Auth state transitioned to locked")
    assert(authState.has_session === true, "Session flag preserved for unlock view")
    assert(rawVaultItems.length === 0, "rawVaultItems wiped on lock")
    assert(filteredItems.length === 0, "filteredItems wiped on lock")
    assert(lastVaultItemsRawText === "", "lastVaultItemsRawText wiped on lock")
    assert(searchQuery === "", "searchQuery reset on lock")

    assert(showPasswordRevealed === false, "showPasswordRevealed reset to false")
    assert(showPrivateKeyRevealed === false, "showPrivateKeyRevealed reset to false")
    assert(showCardNumberRevealed === false, "showCardNumberRevealed reset to false")
    assert(showCardCodeRevealed === false, "showCardCodeRevealed reset to false")
    assert(showCustomHiddenRevealed === false, "showCustomHiddenRevealed reset to false")
    assert(currentTotp.code === "", "currentTotp code wiped")

    assert(showActionPalette === false, "Action palette closed on lock")
    assert(actionPaletteIndex === 0, "Action palette index reset on lock")
    assert(currentAvailableActions.length === 0, "Action closures wiped on lock")

    assert(showPasswordHistoryModal === false, "Password history modal closed on lock")
    assert(activePasswordHistoryItem === null, "activePasswordHistoryItem nulled on lock")

    assert(showSshKeyModal === false, "SSH key modal closed on lock")
    assert(sshKeyModalItem === null, "sshKeyModalItem nulled on lock")

    assert(activeAttachmentPreview === null, "activeAttachmentPreview nulled on lock")
    assert(loadingAttachmentId === "", "loadingAttachmentId reset on lock")

    // 4. Test Late Asynchronous Repopulation Protection:
    // A late vault list response arrives while vault is locked
    var lateVaultJson = JSON.stringify([{ id: "item-2", name: "Late Leaked Item" }])
    simulateVaultListFinished(lateVaultJson)
    assert(rawVaultItems.length === 0, "Late vault list response rejected when locked")

    // A late attachment response arrives while vault is locked
    var lateAttachmentJson = JSON.stringify({ action: "preview", text: "Late Leaked Attachment" })
    simulateAttachmentFinished(lateAttachmentJson)
    assert(activeAttachmentPreview === null, "Late attachment response rejected when locked")

    // A late TOTP response arrives while vault is locked
    var lateTotpJson = JSON.stringify({ code: "654321", ttl: 30, period: 30 })
    simulateTotpFinished(lateTotpJson)
    assert(currentTotp.code === "", "Late TOTP response rejected when locked")

    console.log("All Lock Cleanup and Async Guard tests passed successfully!")
    Qt.quit()
  }
}
