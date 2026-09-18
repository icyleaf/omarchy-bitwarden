import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
  id: authRoot

  property var authState: ({})
  property var config: ({})
  property var cliHealth: ({})
  property bool isDownloadingCli: false
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
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  signal unlockRequested(string password)
  signal loginPasswordRequested(string email, string password, string code, var provider)
  signal loginApiKeyRequested(string clientId, string clientSecret)
  signal logoutRequested()
  signal downloadCliRequested()
  signal settingsRequested()
  signal twoFactorProviderSelected(int provider)
  signal sendTwoFactorEmailRequested(string email, string password)
  signal checkFido2StatusRequested()
  signal copyRequested(string text, string label)

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
             && authRoot.fido2Status === "no_device"
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
              font.pixelSize: 28
              color: authRoot.accent
            }
            Text { Layout.alignment: Qt.AlignHCenter; text: "Vault is Locked"; color: authRoot.foreground; font.pixelSize: 14; font.weight: Font.DemiBold }
            Text {
              Layout.alignment: Qt.AlignHCenter
              text: "Logged in as " + (authRoot.authState.user_email || "user")
              color: Qt.darker(authRoot.foreground, 1.6)
              font.pixelSize: 11
            }
          }

          // Master Password Input
          ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            Text { text: "Master Password:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }

            Rectangle {
              Layout.fillWidth: true
              height: 32
              radius: 5
              color: Qt.rgba(0, 0, 0, 0.25)
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
                  font.pixelSize: 12
                  echoMode: TextInput.Password
                  selectByMouse: true
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
                  color: Qt.darker(authRoot.foreground, 2.0)
                  font.family: "sans-serif"
                  font.pixelSize: 12
                  visible: !unlockPasswordField.text
                }
              }
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
              color: "#ffffff"
              font.pixelSize: 12
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
              color: Qt.darker(authRoot.foreground, 1.6)
              font.pixelSize: 11
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
              font.pixelSize: 28
              color: authRoot.accent
            }
            Text { Layout.alignment: Qt.AlignHCenter; text: "Log In to Bitwarden"; color: authRoot.foreground; font.pixelSize: 14; font.weight: Font.DemiBold }
            Text {
              Layout.alignment: Qt.AlignHCenter
              text: (authRoot.config && authRoot.config.server_url) ? authRoot.config.server_url : "https://vault.bitwarden.com"
              color: Qt.darker(authRoot.foreground, 1.8)
              font.pixelSize: 10
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

              Text { id: pwdTabTxt; anchors.centerIn: parent; text: "Master Password"; color: (authRoot.loginMethod === "password") ? authRoot.accent : authRoot.foreground; font.pixelSize: 11 }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: authRoot.loginMethod = "password" }
            }

            Rectangle {
              implicitHeight: 22
              implicitWidth: apiTabTxt.implicitWidth + 12
              radius: 4
              color: (authRoot.loginMethod === "apikey") ? Qt.rgba(authRoot.accent.r, authRoot.accent.g, authRoot.accent.b, 0.2) : "transparent"
              border.color: (authRoot.loginMethod === "apikey") ? authRoot.accent : authRoot.borderColor
              border.width: 1

              Text { id: apiTabTxt; anchors.centerIn: parent; text: "API Key"; color: (authRoot.loginMethod === "apikey") ? authRoot.accent : authRoot.foreground; font.pixelSize: 11 }
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
              Text { text: "Email:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: loginEmailInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: loginEmailInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: loginPwdInput
                  KeyNavigation.backtab: authRoot.show2FAField ? login2FAInput : loginPwdInput
                  text: (authRoot.config && authRoot.config.email) ? authRoot.config.email : ""
                  onAccepted: loginPwdInput.forceActiveFocus()
                }
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Master Password:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: loginPwdInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: loginPwdInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; echoMode: TextInput.Password; selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: (authRoot.show2FAField && authRoot.twoFactorProvider !== 7) ? login2FAInput : loginEmailInput
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
                      font.pixelSize: 10
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
                color: Qt.rgba(0, 0, 0, 0.25)
                border.color: authRoot.fido2Status === "available"
                  ? "#10b981"
                  : (authRoot.fido2Status === "tool_not_found" ? "#f59e0b" : Qt.rgba(1, 1, 1, 0.15))
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
                    font.pixelSize: 20
                    color: authRoot.fido2Status === "available"
                      ? "#10b981"
                      : (authRoot.fido2Status === "tool_not_found" ? "#f59e0b" : authRoot.accent)
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
                        font.pixelSize: 11
                        font.weight: Font.DemiBold
                        Layout.fillWidth: true
                      }

                      // Check Again button
                      Rectangle {
                        visible: authRoot.fido2Status === "no_device" || authRoot.fido2Status === "tool_not_found"
                        implicitWidth: checkAgainBtnText.implicitWidth + 12
                        implicitHeight: 20
                        radius: 3
                        color: checkAgainMouseArea.containsMouse ? Qt.lighter(Qt.rgba(1, 1, 1, 0.1), 1.2) : Qt.rgba(1, 1, 1, 0.08)
                        border.color: authRoot.borderColor
                        border.width: 1

                        Text {
                          id: checkAgainBtnText
                          anchors.centerIn: parent
                          text: checkAgainTimer.running ? "Checking..." : "Check Again"
                          color: authRoot.foreground
                          font.pixelSize: 9
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
                      color: Qt.darker(authRoot.foreground, 1.4)
                      font.pixelSize: 10
                      wrapMode: Text.WordWrap
                      Layout.fillWidth: true
                    }

                    // Install command box with copy button
                    Rectangle {
                      visible: authRoot.fido2Status === "tool_not_found"
                      Layout.fillWidth: true
                      implicitHeight: 24
                      radius: 3
                      color: Qt.rgba(0, 0, 0, 0.35)
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
                          font.pixelSize: 10
                          Layout.fillWidth: true
                          elide: Text.ElideRight
                        }

                        Rectangle {
                          implicitWidth: copyTimer.running ? 46 : 38
                          implicitHeight: 18
                          radius: 2
                          color: copyTimer.running ? "#10b981" : authRoot.accent

                          Text {
                            anchors.centerIn: parent
                            text: copyTimer.running ? "Copied" : "Copy"
                            color: "#ffffff"
                            font.pixelSize: 9
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
                    ? "New Device Verification Code (check email):"
                    : (authRoot.twoFactorProvider === 1
                        ? "Email 2FA Verification Code (check email):"
                        : (authRoot.twoFactorProvider === 3
                            ? "Touch YubiKey or Enter OTP:"
                            : "Two-Factor Authentication (2FA) Code:"))
                  color: authRoot.foreground
                  font.pixelSize: 11
                  font.weight: Font.Medium
                }

                Rectangle {
                  Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: login2FAInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1

                  TextInput {
                    id: login2FAInput
                    anchors.left: parent.left
                    anchors.right: resendEmailBtn.visible ? resendEmailBtn.left : parent.right
                    anchors.leftMargin: 10
                    anchors.rightMargin: resendEmailBtn.visible ? 6 : 10
                    anchors.verticalCenter: parent.verticalCenter
                    color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
                    activeFocusOnTab: true
                    KeyNavigation.tab: loginEmailInput
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
                      ? Qt.rgba(1, 1, 1, 0.08)
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
                      color: (resendCooldownTimer.running || authRoot.isSendingEmail) ? authRoot.foreground : "#ffffff"
                      font.pixelSize: 10
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
                width: 14; height: 14; radius: 3; color: authRoot.rememberEmailChecked ? authRoot.accent : Qt.rgba(0, 0, 0, 0.2); border.color: authRoot.borderColor; border.width: 1
                Text {
                  anchors.centerIn: parent
                  visible: authRoot.rememberEmailChecked
                  text: "\uf00c"
                  font.family: authRoot.fontFamily
                  color: "#ffffff"
                  font.pixelSize: 9
                }
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: authRoot.rememberEmailChecked = !authRoot.rememberEmailChecked }
              }
              Text { text: "Remember Email"; color: authRoot.foreground; font.pixelSize: 11 }
            }

            // Submit Button
            Rectangle {
              id: submitButton
              Layout.fillWidth: true
              height: 32
              radius: 5
              readonly property bool isFido2Blocked: authRoot.show2FAField
                && authRoot.twoFactorProvider === 7
                && authRoot.fido2Status !== "available"
              readonly property bool isSubmitEnabled: !authRoot.isBusy && !isFido2Blocked

              color: isSubmitEnabled
                ? (submitMouseArea.containsMouse ? Qt.lighter(authRoot.accent, 1.1) : authRoot.accent)
                : Qt.rgba(1, 1, 1, 0.08)

              Text {
                anchors.centerIn: parent
                text: authRoot.isBusy
                  ? (authRoot.twoFactorProvider === 7 ? "Waiting for key touch..." : "Logging in...")
                  : (authRoot.show2FAField && authRoot.twoFactorProvider === 7
                      ? (authRoot.fido2Status === "tool_not_found"
                          ? "Install libfido2 to Proceed"
                          : (authRoot.fido2Status === "no_device"
                              ? "Insert Security Key to Verify"
                              : "Verify with Security Key"))
                      : "Log In")
                color: submitButton.isSubmitEnabled ? "#ffffff" : authRoot.muted
                font.pixelSize: 12
                font.weight: Font.Medium
              }

              MouseArea {
                id: submitMouseArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: submitButton.isSubmitEnabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                enabled: submitButton.isSubmitEnabled
                onClicked: {
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
              Text { text: "API Client ID (`user.xxxxxxxx`):"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: apiClientIdInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: apiClientIdInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: apiClientSecInput
                  KeyNavigation.backtab: apiClientSecInput
                  onAccepted: apiClientSecInput.forceActiveFocus()
                }
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "API Client Secret:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: apiClientSecInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: apiClientSecInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; echoMode: TextInput.Password; selectByMouse: true
                  activeFocusOnTab: true
                  KeyNavigation.tab: apiClientIdInput
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
              Text { anchors.centerIn: parent; text: authRoot.isBusy ? "Logging in..." : "Log In with API Key"; color: "#ffffff"; font.pixelSize: 12; font.weight: Font.Medium }
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
