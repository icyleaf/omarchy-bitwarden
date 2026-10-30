import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import qs.Commons
import qs.Commons as Commons
import "IconPolicy.js" as IconPolicy

Item {
  id: authRoot

  property var authState: ({})
  property var config: ({})
  property var cliHealth: ({})
  property bool isBusy: false
  property string loginMethod: "password"
  property bool rememberEmailChecked: true
  property bool show2FAField: false
  property bool isNewDeviceVerification: false
  property int twoFactorProvider: 0
  property var availableTwoFactorProviders: []
  property string fido2Status: ""
  property int resendCooldown: 0
  property int emailSentCount: 0
  property bool isSendingEmail: false
  property bool isInstalling: false
  // ADR-0025: true when the engine reports quick unlock is enabled and a
  // soft-locked key is retained; shows the system-authentication button.
  property bool quickUnlockAvailable: false
  property bool showServerConfig: false
  property bool enableMtlsChecked: false
  property color foreground: Commons.Color.menu.text
  property color accent: Commons.Color.menu.selectedText
  property color borderColor: Commons.Color.menu.border
  property color muted: Commons.Color.muted
  // Label/glyph color for accent-filled controls. The accent fill itself can
  // be light or dark per theme, so pick the contrasting pole by luminance —
  // Commons.Color.menu.selectedText cannot be used here because it is what
  // fills those controls (root maps accent := Color.menu.selectedText).
  readonly property color textOnAccent: StatusPalette.textOn(accent)
  property string fontFamily: ""

  readonly property string curServerUrl: (authServerUrlInput && authServerUrlInput.text.trim()) ? authServerUrlInput.text.trim() : ((config && config.server_url) ? config.server_url : "")
  readonly property bool isOfficialServer: IconPolicy.isOfficialServer(curServerUrl)
  readonly property bool certMatchesServer: {
    if (!config || !config.client_cert_server || !config.client_cert_path) return false
    if (isOfficialServer) return false
    return IconPolicy.isSameOrigin(curServerUrl, config.client_cert_server)
  }

  onCertMatchesServerChanged: {
    authRoot.enableMtlsChecked = Boolean(config && config.client_cert_path && authRoot.certMatchesServer)
    if (authClientCertInput) {
      authClientCertInput.text = authRoot.certMatchesServer ? ((config && config.client_cert_path) || "") : ""
    }
    if (authClientKeyInput) {
      authClientKeyInput.text = authRoot.certMatchesServer ? ((config && config.client_key_path) || "") : ""
    }
  }

  signal unlockRequested(string password)
  signal quickUnlockRequested()
  signal loginPasswordRequested(string email, string password, string code, var provider)
  signal loginApiKeyRequested(string clientId, string clientSecret)
  signal logoutRequested()
  signal settingsRequested()
  signal serverConfigSaved(string serverUrl, string clientCert, string clientKey)
  signal twoFactorProviderSelected(int provider)
  signal sendTwoFactorEmailRequested(string email, string password)
  signal checkFido2StatusRequested()
  signal copyRequested(string text, string label)
  signal installPackageRequested(string pkgName)

  property alias unlockInput: unlockPasswordField
  property alias twoFactorInput: login2FAInput
  property alias resendEmailButton: resendEmailBtn
  property alias submitButtonComponent: submitButton
  property alias fido2AutoDetectTimerComponent: fido2AutoDetectTimer

  Timer {
    id: fido2AutoDetectTimer
    interval: 1500
    repeat: true
    running: authRoot.show2FAField
             && authRoot.twoFactorProvider === 7
             && authRoot.fido2Status !== "tool_not_found"
             && !authRoot.isBusy
    onTriggered: authRoot.checkFido2StatusRequested()
  }

  Timer {
    id: checkAgainTimer
    interval: 800
    repeat: false
  }

  function notifyEmailCodeSent() {
    authRoot.isSendingEmail = false
    authRoot.emailSentCount++
    authRoot.resendCooldown = 60
    resendCooldownTimer.restart()
  }

  function notifyEmailCodeFailed() {
    authRoot.isSendingEmail = false
  }

  Timer {
    id: resendCooldownTimer
    interval: 1000
    repeat: true
    running: false
    onTriggered: {
      if (authRoot.resendCooldown > 1) {
        authRoot.resendCooldown--
      } else {
        authRoot.resendCooldown = 0
        stop()
      }
    }
  }

  function clearInputs() {
    if (unlockPasswordField) unlockPasswordField.text = ""
    if (loginPwdInput) loginPwdInput.text = ""
    if (login2FAInput) login2FAInput.text = ""
    if (apiClientSecInput) apiClientSecInput.text = ""
    authRoot.isNewDeviceVerification = false
    authRoot.twoFactorProvider = 0
    authRoot.availableTwoFactorProviders = []
    authRoot.emailSentCount = 0
    authRoot.resendCooldown = 0
    authRoot.isSendingEmail = false
    resendCooldownTimer.stop()
  }

  onVisibleChanged: {
    if (!visible) {
      clearInputs()
    }
  }

  onLoginMethodChanged: {
    clearInputs()
    authRoot.show2FAField = false
    authRoot.isNewDeviceVerification = false
    authRoot.twoFactorProvider = 0
    authRoot.availableTwoFactorProviders = []
  }

  onShow2FAFieldChanged: {
    if (!show2FAField) {
      authRoot.emailSentCount = 0
      authRoot.resendCooldown = 0
      authRoot.isSendingEmail = false
      resendCooldownTimer.stop()
    }
  }

  onAuthStateChanged: {
    if (authState && (authState.status === "locked" || authState.status === "unlocked" || authState.status === "unauthenticated")) {
      clearInputs()
    }
    if (authState && authState.status === "locked" && Boolean(authState.has_session)) {
      Qt.callLater(function() {
        if (unlockPasswordField) unlockPasswordField.forceActiveFocus()
      })
    }
  }

  onConfigChanged: {
    if (loginEmailInput && authRoot.config && authRoot.config.email && authRoot.rememberEmailChecked) {
      if (!loginEmailInput.text || loginEmailInput.text.trim() === "") {
        loginEmailInput.text = authRoot.config.email
      }
    }
    if (authServerUrlInput && authRoot.config && authRoot.config.server_url) {
      authServerUrlInput.text = authRoot.config.server_url
    }
    if (authRoot.config) {
      authRoot.enableMtlsChecked = Boolean(authRoot.config.client_cert_path && authRoot.certMatchesServer)
    }
    if (authClientCertInput) {
      authClientCertInput.text = authRoot.certMatchesServer ? ((authRoot.config && authRoot.config.client_cert_path) || "") : ""
    }
    if (authClientKeyInput) {
      authClientKeyInput.text = authRoot.certMatchesServer ? ((authRoot.config && authRoot.config.client_key_path) || "") : ""
    }
  }

  Flickable {
    id: authFlickable
    anchors.fill: parent
    contentWidth: width
    contentHeight: Math.max(height, authWrapper.height)
    boundsBehavior: Flickable.StopAtBounds
    clip: true

    Item {
      id: authWrapper
      width: authFlickable.width
      height: Math.max(authFlickable.height, authMainColumn.implicitHeight + 40)

      ColumnLayout {
        id: authMainColumn
        anchors.centerIn: parent
        width: Math.min(parent.width - 48, 360)
        spacing: 14



        // --------------------------------------------------
        // 1. UNLOCK VIEW (When session exists but vault is locked)
        // --------------------------------------------------
        ColumnLayout {
          visible: authRoot.authState.status === "locked" && Boolean(authRoot.authState.has_session)
          Layout.fillWidth: true
          spacing: 14

          ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 4
            Text {
              Layout.alignment: Qt.AlignHCenter
              text: "\uf023"
              font.family: authRoot.fontFamily
              font.pixelSize: Style.font.displayLarge
              color: authRoot.accent
            }
            Text { Layout.alignment: Qt.AlignHCenter; text: "Vault is Locked"; color: authRoot.foreground; font.pixelSize: Style.font.title; font.weight: Font.DemiBold }
            Text {
              Layout.alignment: Qt.AlignHCenter
              text: "Logged in as " + (authRoot.authState.user_email || "user")
              color: authRoot.muted
              font.pixelSize: Style.font.bodySmall
            }
          }

          // Master Password Input
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            Text { text: "Master Password:"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }

            Rectangle {
              Layout.fillWidth: true
              height: 32
              radius: 5
              color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08)
              border.color: unlockPasswordField.activeFocus ? authRoot.accent : authRoot.borderColor
              border.width: 1

              Item {
                anchors.fill: parent
                anchors.leftMargin: 10
                anchors.rightMargin: 10

                TextInput {
                  id: unlockPasswordField
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground
                  font.family: "sans-serif"
                  font.pixelSize: Style.font.body
                  echoMode: TextInput.Password
                  selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  onAccepted: {
                    if (text.trim()) {
                      authRoot.unlockRequested(text)
                    }
                  }
                }

                Text {
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  text: "Enter master password..."
                  color: authRoot.muted
                  font.family: "sans-serif"
                  font.pixelSize: Style.font.body
                  visible: !unlockPasswordField.text
                }
              }
            }
          }

          // Quick Unlock Button (ADR-0025): system authentication instead of
          // the master password after a soft lock.
          Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 32
            radius: 5
            visible: authRoot.quickUnlockAvailable && !authRoot.isBusy
            color: Qt.rgba(1, 1, 1, 0.08)

            Text {
              anchors.centerIn: parent
              text: "Unlock with System Authentication"
              color: authRoot.foreground
              font.pixelSize: Style.font.body
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: authRoot.quickUnlockRequested()
            }
          }

          // Unlock Button
          Rectangle {
            Layout.fillWidth: true
            height: 32
            radius: 5
            color: authRoot.accent

            Text {
              anchors.centerIn: parent
              text: authRoot.isBusy ? "Unlocking..." : "Unlock Vault"
              color: authRoot.textOnAccent
              font.pixelSize: Style.font.body
              font.weight: Font.Medium
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: {
                if (unlockPasswordField.text.trim()) {
                  authRoot.unlockRequested(unlockPasswordField.text)
                }
              }
            }
          }

          // Bottom Links: Logout
          RowLayout {
            Layout.fillWidth: true

            Item { Layout.fillWidth: true }

            // Logout Link
            Text {
              text: "Log out from account"
              color: authRoot.muted
              font.pixelSize: Style.font.bodySmall
              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: authRoot.logoutRequested()
              }
            }
          }
        }

        // --------------------------------------------------
        // 2. FULL LOGIN VIEW (When unauthenticated)
        // --------------------------------------------------
        ColumnLayout {
          visible: authRoot.authState.status !== "locked" || !authRoot.authState.has_session
          Layout.fillWidth: true
          spacing: 12

          ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 4
            Text {
              Layout.alignment: Qt.AlignHCenter
              text: "\uf132"
              font.family: authRoot.fontFamily
              font.pixelSize: Style.font.displayLarge
              color: authRoot.accent
            }
            Text { Layout.alignment: Qt.AlignHCenter; text: "Log In to Bitwarden"; color: authRoot.foreground; font.pixelSize: Style.font.title; font.weight: Font.DemiBold }
            RowLayout {
              Layout.alignment: Qt.AlignHCenter
              spacing: 6
              Text {
                text: (authRoot.config && authRoot.config.server_url) ? authRoot.config.server_url : "https://vault.bitwarden.com"
                color: authRoot.muted
                font.pixelSize: Style.font.caption
              }
              Rectangle {
                implicitWidth: changeServerRow.implicitWidth + 8
                implicitHeight: 18
                radius: 3
                color: changeServerMouse.containsMouse ? Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08) : "transparent"
                border.color: authRoot.borderColor
                border.width: 1

                RowLayout {
                  id: changeServerRow
                  anchors.centerIn: parent
                  spacing: 4
                  Text {
                    text: authRoot.showServerConfig ? "\uf00d Close" : "\uf013 Server"
                    font.family: authRoot.fontFamily
                    color: authRoot.accent
                    font.pixelSize: Style.fontPx(0.7)
                  }
                }
                MouseArea {
                  id: changeServerMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    authRoot.showServerConfig = !authRoot.showServerConfig
                    if (authRoot.showServerConfig) {
                      Qt.callLater(function() {
                        authServerUrlInput.forceActiveFocus()
                      })
                    } else {
                      Qt.callLater(function() {
                        if (authRoot.loginMethod === "password") {
                          loginEmailInput.forceActiveFocus()
                        } else {
                          apiClientIdInput.forceActiveFocus()
                        }
                      })
                    }
                  }
                }
              }
            }
          }

          // Inline Server & mTLS Configuration Box
          Rectangle {
            visible: authRoot.showServerConfig
            Layout.fillWidth: true
            radius: 6
            color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.10)
            border.color: authRoot.borderColor
            border.width: 1
            implicitHeight: serverConfigCol.implicitHeight + 20

            ColumnLayout {
              id: serverConfigCol
              anchors.fill: parent
              anchors.margins: 10
              spacing: 8

              Text {
                text: "SERVER & mTLS CLIENT CERTIFICATE"
                color: authRoot.accent
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.DemiBold
              }

              // Server URL Field
              ColumnLayout {
                Layout.fillWidth: true
                spacing: 3
                Text { text: "Server URL:"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
                Rectangle {
                  Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: authServerUrlInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                  TextInput {
                    id: authServerUrlInput
                    anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                    color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                    clip: true
                    activeFocusOnTab: true
                    KeyNavigation.tab: (!authRoot.isOfficialServer && authRoot.enableMtlsChecked && authClientCertInput) ? authClientCertInput : ((authRoot.loginMethod === "password") ? loginEmailInput : apiClientIdInput)
                    KeyNavigation.backtab: (authRoot.loginMethod === "password") ? (authRoot.show2FAField ? login2FAInput : loginPwdInput) : apiClientSecInput
                    text: (authRoot.config && authRoot.config.server_url) ? authRoot.config.server_url : "https://vault.bitwarden.com"
                  }
                }
              }

              // Info text if official server is selected
              Text {
                visible: authRoot.isOfficialServer
                Layout.fillWidth: true
                text: "Official Bitwarden cloud uses standard HTTPS and does not require client certificates."
                color: authRoot.muted
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              // Optional mTLS Toggle for Self-Hosted Servers
              RowLayout {
                visible: !authRoot.isOfficialServer
                spacing: 6
                Rectangle {
                  width: 14; height: 14; radius: 3
                  color: authRoot.enableMtlsChecked ? authRoot.accent : Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.10)
                  border.color: authRoot.borderColor; border.width: 1
                  Text {
                    anchors.centerIn: parent
                    visible: authRoot.enableMtlsChecked
                    text: "\uf00c"
                    font.family: authRoot.fontFamily
                    color: authRoot.textOnAccent
                    font.pixelSize: Style.fontPx(0.75)
                  }
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: authRoot.enableMtlsChecked = !authRoot.enableMtlsChecked
                  }
                }
                Text {
                  text: "Use mTLS Client Certificate (for edge gateways)"
                  color: authRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: authRoot.enableMtlsChecked = !authRoot.enableMtlsChecked
                  }
                }
              }

              // Certificate Section (Self-Hosted Only when mTLS is enabled)
              ColumnLayout {
                id: authCertFields
                visible: !authRoot.isOfficialServer && authRoot.enableMtlsChecked
                Layout.fillWidth: true
                spacing: 8

                // Client Certificate (.pem / .crt)
                ColumnLayout {
                  Layout.fillWidth: true
                  spacing: 3
                  Text { text: "Client Certificate Path (.pem / .crt):"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
                  Rectangle {
                    Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: authClientCertInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                    TextInput {
                      id: authClientCertInput
                      anchors.left: parent.left; anchors.right: authCertBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                      color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                      clip: true
                      activeFocusOnTab: true
                      KeyNavigation.tab: authClientKeyInput
                      KeyNavigation.backtab: authServerUrlInput
                      text: authRoot.certMatchesServer ? ((authRoot.config && authRoot.config.client_cert_path) || "") : ""
                    }
                    Text {
                      anchors.left: parent.left; anchors.right: authCertBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                      text: "e.g. /home/user/.certs/client.crt"
                      color: authRoot.muted
                      font.family: "sans-serif"; font.pixelSize: Style.font.body
                      elide: Text.ElideRight
                      visible: authClientCertInput.text.length === 0
                    }
                    GhostIconButton {
                      id: authCertBrowseBtn
                      anchors.right: parent.right
                      anchors.rightMargin: 5
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "\uf07b"
                      fontFamily: authRoot.fontFamily
                      tooltip: "Browse certificate file"
                      onClicked: authCertFileDialog.open()
                    }
                  }
                }

                // Client Private Key (.key)
                ColumnLayout {
                  Layout.fillWidth: true
                  spacing: 3
                  Text { text: "Client Private Key Path (optional if merged):"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
                  Rectangle {
                    Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: authClientKeyInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                    TextInput {
                      id: authClientKeyInput
                      anchors.left: parent.left; anchors.right: authKeyBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                      color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                      clip: true
                      activeFocusOnTab: true
                      KeyNavigation.tab: (authRoot.loginMethod === "password") ? loginEmailInput : apiClientIdInput
                      KeyNavigation.backtab: authClientCertInput
                      text: authRoot.certMatchesServer ? ((authRoot.config && authRoot.config.client_key_path) || "") : ""
                    }
                    Text {
                      anchors.left: parent.left; anchors.right: authKeyBrowseBtn.left; anchors.leftMargin: 10; anchors.rightMargin: 6; anchors.verticalCenter: parent.verticalCenter
                      text: "e.g. /home/user/.certs/client.key (0600 mode)"
                      color: authRoot.muted
                      font.family: "sans-serif"; font.pixelSize: Style.font.body
                      elide: Text.ElideRight
                      visible: authClientKeyInput.text.length === 0
                    }
                    GhostIconButton {
                      id: authKeyBrowseBtn
                      anchors.right: parent.right
                      anchors.rightMargin: 5
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "\uf07b"
                      fontFamily: authRoot.fontFamily
                      tooltip: "Browse private key file"
                      onClicked: authKeyFileDialog.open()
                    }
                  }
                }

                FileDialog {
                  id: authCertFileDialog
                  title: "Select Client Certificate (.pem / .crt)"
                  fileMode: FileDialog.OpenFile
                  nameFilters: ["Certificate files (*.crt *.pem)", "All files (*)"]
                  onAccepted: {
                    authClientCertInput.text = IconPolicy.urlToLocalPath(selectedFile)
                  }
                }

                FileDialog {
                  id: authKeyFileDialog
                  title: "Select Client Private Key (.key / .pem)"
                  fileMode: FileDialog.OpenFile
                  nameFilters: ["Private key files (*.key *.pem)", "All files (*)"]
                  onAccepted: {
                    authClientKeyInput.text = IconPolicy.urlToLocalPath(selectedFile)
                  }
                }

                Text {
                  Layout.fillWidth: true
                  text: "Private key files must be restricted to 0600 or 0400 file permissions."
                  color: authRoot.muted
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }
              }

              // Action Buttons Row
              RowLayout {
                Layout.fillWidth: true
                spacing: 8

                Rectangle {
                  implicitHeight: 28
                  implicitWidth: saveServerTxt.implicitWidth + 16
                  radius: 4
                  color: authRoot.accent
                  Text {
                    id: saveServerTxt
                    anchors.centerIn: parent
                    text: "Save & Apply"
                    color: authRoot.textOnAccent
                    font.pixelSize: Style.font.bodySmall
                    font.weight: Font.Medium
                  }
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      var targetServer = authServerUrlInput.text.trim() || "https://vault.bitwarden.com"
                      var isOfficial = IconPolicy.isOfficialServer(targetServer)
                      var useMtls = !isOfficial && authRoot.enableMtlsChecked
                      authRoot.serverConfigSaved(
                        targetServer,
                        useMtls ? (authClientCertInput ? authClientCertInput.text.trim() : "") : "",
                        useMtls ? (authClientKeyInput ? authClientKeyInput.text.trim() : "") : ""
                      )
                      authRoot.showServerConfig = false
                    }
                  }
                }

                Rectangle {
                  implicitHeight: 28
                  implicitWidth: resetServerTxt.implicitWidth + 14
                  radius: 4
                  color: "transparent"
                  border.color: authRoot.borderColor
                  border.width: 1
                  Text {
                    id: resetServerTxt
                    anchors.centerIn: parent
                    text: "Reset to Official"
                    color: authRoot.muted
                    font.pixelSize: Style.font.bodySmall
                  }
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      authServerUrlInput.text = "https://vault.bitwarden.com"
                      authRoot.enableMtlsChecked = false
                      if (authClientCertInput) authClientCertInput.text = ""
                      if (authClientKeyInput) authClientKeyInput.text = ""
                      authRoot.serverConfigSaved(
                        "https://vault.bitwarden.com",
                        "",
                        ""
                      )
                      authRoot.showServerConfig = false
                    }
                  }
                }
              }
            }
          }

          // Login Method Tabs
          RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 6

            Rectangle {
              implicitHeight: 22
              implicitWidth: pwdTabTxt.implicitWidth + 12
              radius: 4
              color: (authRoot.loginMethod === "password") ? Qt.rgba(authRoot.accent.r, authRoot.accent.g, authRoot.accent.b, 0.2) : "transparent"
              border.color: (authRoot.loginMethod === "password") ? authRoot.accent : authRoot.borderColor
              border.width: 1

              Text { id: pwdTabTxt; anchors.centerIn: parent; text: "Master Password"; color: (authRoot.loginMethod === "password") ? authRoot.accent : authRoot.foreground; font.pixelSize: Style.font.bodySmall }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: authRoot.loginMethod = "password" }
            }

            Rectangle {
              implicitHeight: 22
              implicitWidth: apiTabTxt.implicitWidth + 12
              radius: 4
              color: (authRoot.loginMethod === "apikey") ? Qt.rgba(authRoot.accent.r, authRoot.accent.g, authRoot.accent.b, 0.2) : "transparent"
              border.color: (authRoot.loginMethod === "apikey") ? authRoot.accent : authRoot.borderColor
              border.width: 1

              Text { id: apiTabTxt; anchors.centerIn: parent; text: "API Key"; color: (authRoot.loginMethod === "apikey") ? authRoot.accent : authRoot.foreground; font.pixelSize: Style.font.bodySmall }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: authRoot.loginMethod = "apikey" }
            }
          }

          // Master Password Form
          ColumnLayout {
            visible: authRoot.loginMethod === "password"
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Email:"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: loginEmailInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: loginEmailInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: loginPwdInput
                  KeyNavigation.backtab: authRoot.showServerConfig
                    ? (!authRoot.isOfficialServer && authRoot.enableMtlsChecked ? authClientKeyInput : authServerUrlInput)
                    : (authRoot.show2FAField ? login2FAInput : loginPwdInput)
                  text: (authRoot.config && authRoot.config.email) ? authRoot.config.email : ""
                  onAccepted: loginPwdInput.forceActiveFocus()
                }
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Master Password:"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: loginPwdInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: loginPwdInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; echoMode: TextInput.Password; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: (authRoot.show2FAField && authRoot.twoFactorProvider !== 7)
                    ? login2FAInput
                    : (authRoot.showServerConfig ? authServerUrlInput : loginEmailInput)
                  KeyNavigation.backtab: loginEmailInput
                  onAccepted: {
                    if (authRoot.show2FAField && authRoot.twoFactorProvider !== 7 && !login2FAInput.text.trim()) {
                      login2FAInput.forceActiveFocus()
                    } else {
                      authRoot.loginPasswordRequested(
                        loginEmailInput.text.trim(),
                        loginPwdInput.text,
                        authRoot.twoFactorProvider === 7 ? "" : login2FAInput.text.trim(),
                        authRoot.twoFactorProvider
                      )
                    }
                  }
                }
              }
            }

            ColumnLayout {
              visible: authRoot.show2FAField
              Layout.fillWidth: true
              spacing: 6

              // Multi-2FA Provider Switcher (when more than 1 provider is available and not new device verification)
              RowLayout {
                visible: !authRoot.isNewDeviceVerification && authRoot.availableTwoFactorProviders && authRoot.availableTwoFactorProviders.length > 1
                Layout.fillWidth: true
                spacing: 4

                Repeater {
                  model: authRoot.availableTwoFactorProviders
                  delegate: Rectangle {
                    id: providerTab
                    required property int modelData
                    implicitHeight: 22
                    Layout.fillWidth: true
                    radius: 4
                    color: (authRoot.twoFactorProvider === modelData)
                      ? Qt.rgba(authRoot.accent.r, authRoot.accent.g, authRoot.accent.b, 0.2)
                      : "transparent"
                    border.color: (authRoot.twoFactorProvider === modelData)
                      ? authRoot.accent
                      : authRoot.borderColor
                    border.width: 1

                    Text {
                      anchors.centerIn: parent
                      text: modelData === 7
                        ? "Security Key"
                        : (modelData === 1
                            ? "Email"
                            : (modelData === 3 ? "YubiKey OTP" : "Authenticator"))
                      color: (authRoot.twoFactorProvider === modelData)
                        ? authRoot.accent
                        : authRoot.foreground
                      font.pixelSize: Style.font.caption
                      font.weight: (authRoot.twoFactorProvider === modelData) ? Font.DemiBold : Font.Normal
                    }

                    MouseArea {
                      anchors.fill: parent
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        authRoot.twoFactorProvider = providerTab.modelData
                        authRoot.twoFactorProviderSelected(providerTab.modelData)
                        if (providerTab.modelData !== 7) {
                          Qt.callLater(function() {
                            if (login2FAInput) login2FAInput.forceActiveFocus()
                          })
                        }
                      }
                    }
                  }
                }
              }

              // WebAuthn / Security Key View (Provider 7)
              Rectangle {
                visible: authRoot.twoFactorProvider === 7
                Layout.fillWidth: true
                implicitHeight: authRoot.fido2Status === "tool_not_found" ? 88 : 58
                radius: 5
                color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08)
                border.color: authRoot.fido2Status === "tool_not_found" ? StatusPalette.warn : authRoot.accent
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.margins: 10
                  spacing: 10

                  Text {
                    text: authRoot.fido2Status === "available"
                      ? "\uf084"
                      : (authRoot.fido2Status === "tool_not_found" ? "\uf071" : "\uf287")
                    font.family: authRoot.fontFamily
                    font.pixelSize: Style.fontPx(1.667)
                    color: authRoot.fido2Status === "tool_not_found" ? StatusPalette.warn : authRoot.accent
                    Layout.alignment: Qt.AlignTop
                  }

                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: 6

                      Text {
                        text: authRoot.fido2Status === "tool_not_found"
                          ? "libfido2 not installed"
                          : (authRoot.fido2Status === "no_device"
                              ? "No Security Key Detected"
                              : "Security Key Detected")
                        color: authRoot.foreground
                        font.pixelSize: Style.font.bodySmall
                        font.weight: Font.DemiBold
                        Layout.fillWidth: true
                      }

                      // Check Again button
                      Rectangle {
                        visible: authRoot.fido2Status === "no_device" || authRoot.fido2Status === "tool_not_found"
                        implicitWidth: checkAgainBtnText.implicitWidth + 12
                        implicitHeight: 20
                        radius: 3
                        color: checkAgainMouseArea.containsMouse ? Qt.lighter(Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.1), 1.2) : Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08)
                        border.color: authRoot.borderColor
                        border.width: 1

                        Text {
                          id: checkAgainBtnText
                          anchors.centerIn: parent
                          text: checkAgainTimer.running ? "Checking..." : "Check Again"
                          color: authRoot.foreground
                          font.pixelSize: Style.fontPx(0.75)
                          font.weight: Font.Medium
                        }

                        MouseArea {
                          id: checkAgainMouseArea
                          anchors.fill: parent
                          cursorShape: Qt.PointingHandCursor
                          enabled: !checkAgainTimer.running && !authRoot.isBusy
                          onClicked: {
                            checkAgainTimer.restart()
                            authRoot.checkFido2StatusRequested()
                          }
                        }
                      }
                    }

                    Text {
                      text: authRoot.fido2Status === "tool_not_found"
                        ? "Install 'libfido2' package to use security keys, or select another method:"
                        : (authRoot.isBusy
                            ? "Waiting for security key touch..."
                            : (authRoot.fido2Status === "no_device"
                                ? "Insert your USB security key. It will be detected automatically."
                                : "Click 'Verify with Security Key' and touch your key."))
                      color: authRoot.muted
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                      Layout.fillWidth: true
                    }

                    // Install command box with copy button
                    Rectangle {
                      visible: authRoot.fido2Status === "tool_not_found"
                      Layout.fillWidth: true
                      implicitHeight: 24
                      radius: 3
                      color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.12)
                      border.color: authRoot.borderColor
                      border.width: 1

                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 6
                        anchors.rightMargin: 4
                        spacing: 6

                        Text {
                          text: "sudo pacman -S libfido2"
                          color: authRoot.foreground
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption
                          Layout.fillWidth: true
                          elide: Text.ElideRight
                        }

                        // One-Click Install Button
                        Rectangle {
                          implicitWidth: authRoot.isInstalling ? 68 : 46
                          implicitHeight: 18
                          radius: 2
                          color: authRoot.isInstalling ? Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.15) : (installMouse.containsMouse ? Qt.lighter(authRoot.accent, 1.1) : authRoot.accent)

                          Text {
                            anchors.centerIn: parent
                            text: authRoot.isInstalling ? "Installing..." : "Install"
                            color: authRoot.isInstalling ? authRoot.muted : authRoot.textOnAccent
                            font.pixelSize: Style.fontPx(0.75)
                            font.weight: Font.Medium
                          }

                          MouseArea {
                            id: installMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: authRoot.isInstalling ? Qt.ArrowCursor : Qt.PointingHandCursor
                            enabled: !authRoot.isInstalling
                            onClicked: authRoot.installPackageRequested("libfido2")
                          }
                        }

                        // Copy Command Button
                        Rectangle {
                          implicitWidth: copyTimer.running ? 46 : 38
                          implicitHeight: 18
                          radius: 2
                          color: copyTimer.running ? StatusPalette.success : Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.15)

                          Text {
                            anchors.centerIn: parent
                            text: copyTimer.running ? "Copied" : "Copy"
                            color: copyTimer.running ? StatusPalette.textOnTint(StatusPalette.success, 1, Commons.Color.popups.background) : authRoot.foreground
                            font.pixelSize: Style.fontPx(0.75)
                            font.weight: Font.Medium
                          }

                          MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              authRoot.copyRequested("sudo pacman -S libfido2", "Install command")
                              copyTimer.restart()
                            }
                          }
                        }
                      }
                    }
                  }
                }

                Timer {
                  id: copyTimer
                  interval: 1500
                  repeat: false
                }
              }

              // Standard OTP Code View (Providers 0, 1, 3, etc.)
              ColumnLayout {
                visible: authRoot.twoFactorProvider !== 7
                Layout.fillWidth: true
                spacing: 3

                Text {
                  text: authRoot.isNewDeviceVerification
                    ? "New Device Email Verification Code:"
                    : (authRoot.twoFactorProvider === 1
                        ? "Email 2FA Verification Code:"
                        : (authRoot.twoFactorProvider === 3
                            ? "Touch YubiKey or Enter OTP:"
                            : "Two-Factor Authentication (2FA) Code:"))
                  color: authRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.Medium
                }

                Rectangle {
                  Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: login2FAInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1

                  TextInput {
                    id: login2FAInput
                    anchors.left: parent.left
                    anchors.right: resendEmailBtn.visible ? resendEmailBtn.left : parent.right
                    anchors.leftMargin: 10
                    anchors.rightMargin: resendEmailBtn.visible ? 6 : 10
                    anchors.verticalCenter: parent.verticalCenter
                    color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                    clip: true
                    activeFocusOnTab: true
                    KeyNavigation.tab: authRoot.showServerConfig ? authServerUrlInput : loginEmailInput
                    KeyNavigation.backtab: loginPwdInput
                    onAccepted: {
                      authRoot.loginPasswordRequested(
                        loginEmailInput.text.trim(),
                        loginPwdInput.text,
                        login2FAInput.text.trim(),
                        authRoot.twoFactorProvider
                      )
                    }
                  }

                  Rectangle {
                    id: resendEmailBtn
                    visible: authRoot.twoFactorProvider === 1
                    anchors.right: parent.right
                    anchors.rightMargin: 4
                    anchors.verticalCenter: parent.verticalCenter
                    implicitWidth: resendBtnText.implicitWidth + 14
                    height: 24
                    radius: 3
                    color: (resendCooldownTimer.running || authRoot.isSendingEmail)
                      ? Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08)
                      : (resendMouseArea.containsMouse ? Qt.lighter(authRoot.accent, 1.1) : authRoot.accent)
                    opacity: (resendCooldownTimer.running || authRoot.isBusy || authRoot.isSendingEmail) ? 0.7 : 1.0

                    Text {
                      id: resendBtnText
                      anchors.centerIn: parent
                      text: authRoot.isSendingEmail
                        ? "Sending..."
                        : (resendCooldownTimer.running
                            ? ("Resend (" + authRoot.resendCooldown + "s)")
                            : (authRoot.emailSentCount > 0 ? "Resend Email" : "Send Email"))
                      color: (resendCooldownTimer.running || authRoot.isSendingEmail) ? authRoot.foreground : authRoot.textOnAccent
                      font.pixelSize: Style.font.caption
                      font.weight: Font.Medium
                    }

                    MouseArea {
                      id: resendMouseArea
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: (resendCooldownTimer.running || authRoot.isBusy || authRoot.isSendingEmail)
                        ? Qt.ArrowCursor
                        : Qt.PointingHandCursor
                      enabled: !resendCooldownTimer.running && !authRoot.isBusy && !authRoot.isSendingEmail && loginEmailInput.text.trim() !== "" && loginPwdInput.text !== ""
                      onClicked: {
                        authRoot.isSendingEmail = true
                        authRoot.sendTwoFactorEmailRequested(loginEmailInput.text.trim(), loginPwdInput.text)
                      }
                    }
                  }
                }
              }
            }

            // Remember Email Checkbox
            RowLayout {
              spacing: 6
              Rectangle {
                width: 14; height: 14; radius: 3; color: authRoot.rememberEmailChecked ? authRoot.accent : Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.10); border.color: authRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: authRoot.rememberEmailChecked
                  text: "\uf00c"
                  font.family: authRoot.fontFamily
                  color: authRoot.textOnAccent
                  font.pixelSize: Style.fontPx(0.75)
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: authRoot.rememberEmailChecked = !authRoot.rememberEmailChecked }
              }
              Text { text: "Remember Email"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall }
            }

            // Submit Button
            Rectangle {
              id: submitButton
              Layout.fillWidth: true
              height: 32
              radius: 5
              readonly property bool isToolNotFound: authRoot.show2FAField
                && authRoot.twoFactorProvider === 7
                && authRoot.fido2Status === "tool_not_found"
              readonly property bool isFido2NoDevice: authRoot.show2FAField
                && authRoot.twoFactorProvider === 7
                && authRoot.fido2Status === "no_device"
              readonly property bool isSubmitEnabled: !authRoot.isBusy
                && !authRoot.isInstalling
                && !isFido2NoDevice

              color: isSubmitEnabled
                ? (submitMouseArea.containsMouse ? Qt.lighter(authRoot.accent, 1.1) : authRoot.accent)
                : Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08)

              Text {
                anchors.centerIn: parent
                text: {
                  if (authRoot.isBusy) {
                    return (authRoot.twoFactorProvider === 7 ? "Waiting for key touch..." : "Logging in...")
                  }
                  if (authRoot.show2FAField && authRoot.twoFactorProvider === 7) {
                    if (authRoot.fido2Status === "tool_not_found") {
                      return authRoot.isInstalling ? "Installing libfido2 in Terminal..." : "⚡ Install libfido2"
                    }
                    if (authRoot.fido2Status === "no_device") {
                      return "Insert Security Key to Verify"
                    }
                    return "Verify with Security Key"
                  }
                  return "Log In"
                }
                color: submitButton.isSubmitEnabled ? authRoot.textOnAccent : authRoot.muted
                font.pixelSize: Style.font.body
                font.weight: Font.Medium
              }

              MouseArea {
                id: submitMouseArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: submitButton.isSubmitEnabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                enabled: submitButton.isSubmitEnabled
                onClicked: {
                  if (submitButton.isToolNotFound) {
                    authRoot.installPackageRequested("libfido2")
                    return
                  }
                  authRoot.loginPasswordRequested(
                    loginEmailInput.text.trim(),
                    loginPwdInput.text,
                    authRoot.twoFactorProvider === 7 ? "" : login2FAInput.text.trim(),
                    authRoot.twoFactorProvider
                  )
                }
              }
            }
          }

          // API Key Form
          ColumnLayout {
            visible: authRoot.loginMethod === "apikey"
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "API Client ID (`user.xxxxxxxx`):"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: apiClientIdInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: apiClientIdInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: apiClientSecInput
                  KeyNavigation.backtab: authRoot.showServerConfig
                    ? (!authRoot.isOfficialServer && authRoot.enableMtlsChecked ? authClientKeyInput : authServerUrlInput)
                    : apiClientSecInput
                  onAccepted: apiClientSecInput.forceActiveFocus()
                }
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "API Client Secret:"; color: authRoot.foreground; font.pixelSize: Style.font.bodySmall; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(authRoot.foreground.r, authRoot.foreground.g, authRoot.foreground.b, 0.08); border.color: apiClientSecInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: apiClientSecInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: Style.font.body; echoMode: TextInput.Password; selectByMouse: true
                  clip: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: authRoot.showServerConfig ? authServerUrlInput : apiClientIdInput
                  KeyNavigation.backtab: apiClientIdInput
                  onAccepted: {
                    authRoot.loginApiKeyRequested(apiClientIdInput.text.trim(), apiClientSecInput.text.trim())
                  }
                }
              }
            }

            // Submit Button
            Rectangle {
              Layout.fillWidth: true; height: 32; radius: 5; color: authRoot.accent
              Text { anchors.centerIn: parent; text: authRoot.isBusy ? "Logging in..." : "Log In with API Key"; color: authRoot.textOnAccent; font.pixelSize: Style.font.body; font.weight: Font.Medium }
              MouseArea {
                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                onClicked: {
                  authRoot.loginApiKeyRequested(apiClientIdInput.text.trim(), apiClientSecInput.text.trim())
                }
              }
            }
          }


        }
      }
    }
  }
}
