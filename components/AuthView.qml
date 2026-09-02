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
  property color foreground: "#ffffff"
  property color accent: "#3b82f6"
  property color borderColor: Qt.rgba(1, 1, 1, 0.1)
  property string fontFamily: ""

  signal unlockRequested(string password)
  signal loginPasswordRequested(string email, string password, string code)
  signal loginApiKeyRequested(string clientId, string clientSecret)
  signal logoutRequested()
  signal downloadCliRequested()
  signal settingsRequested()

  property alias unlockInput: unlockPasswordField

  function clearInputs() {
    if (unlockPasswordField) unlockPasswordField.text = ""
    if (loginPwdInput) loginPwdInput.text = ""
    if (login2FAInput) login2FAInput.text = ""
    if (apiClientSecInput) apiClientSecInput.text = ""
  }

  onVisibleChanged: {
    if (!visible) {
      clearInputs()
    }
  }

  onAuthStateChanged: {
    if (authState && (authState.status === "locked" || authState.status === "unlocked" || authState.status === "unauthenticated")) {
      clearInputs()
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
          visible: authRoot.authState.status === "locked"
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
          visible: authRoot.authState.status !== "locked"
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
                  text: (authRoot.config && authRoot.config.email) ? authRoot.config.email : ""
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
                }
              }
            }

            ColumnLayout {
              visible: authRoot.show2FAField
              Layout.fillWidth: true
              spacing: 3
              Text { text: "Two-Factor Authentication (2FA) Code:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: login2FAInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput {
                  id: login2FAInput
                  anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter
                  color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true
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
              Layout.fillWidth: true; height: 32; radius: 5; color: authRoot.accent
              Text { anchors.centerIn: parent; text: authRoot.isBusy ? "Logging in..." : "Log In"; color: "#ffffff"; font.pixelSize: 12; font.weight: Font.Medium }
              MouseArea {
                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                onClicked: {
                  authRoot.loginPasswordRequested(loginEmailInput.text.trim(), loginPwdInput.text, login2FAInput.text.trim())
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
                TextInput { id: apiClientIdInput; anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; selectByMouse: true }
              }
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 3
              Text { text: "API Client Secret:"; color: authRoot.foreground; font.pixelSize: 11; font.weight: Font.Medium }
              Rectangle {
                Layout.fillWidth: true; height: 32; radius: 5; color: Qt.rgba(0, 0, 0, 0.25); border.color: apiClientSecInput.activeFocus ? authRoot.accent : authRoot.borderColor; border.width: 1
                TextInput { id: apiClientSecInput; anchors.left: parent.left; anchors.right: parent.right; anchors.leftMargin: 10; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; color: authRoot.foreground; font.family: "sans-serif"; font.pixelSize: 12; echoMode: TextInput.Password; selectByMouse: true }
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
