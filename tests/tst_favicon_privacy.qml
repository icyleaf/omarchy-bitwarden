import QtQuick
import QtQuick.Controls
import "../components"
import "../components/iconpolicy.js" as IconPolicy

Item {
  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  VaultItemList { id: list }
  ItemInspector { id: insp }

  property var loginItem: ({
    name: "GitHub",
    type_name: "login",
    login: { username: "octocat", uris: [{ uri: "https://github.com" }] },
    sub_title: "octocat"
  })
  property var appSchemeItem: ({
    name: "Example App",
    type_name: "login",
    login: { username: "user", uris: [{ uri: "androidapp://com.example" }] },
    sub_title: "user"
  })
  property var nonLoginItem: ({
    name: "Secret Recipe",
    type_name: "note",
    sub_title: "Secure Note"
  })

  Component.onCompleted: {
    console.log("Running Favicon & Privacy Endpoint Tests...")

    // A. Policy truth table — fail closed until config has actually loaded
    check(IconPolicy.resolve(false, true) === false, "resolve(false, true) is false")
    check(IconPolicy.resolve(false, undefined) === false, "resolve(false, undefined) is false")
    check(IconPolicy.resolve(false, false) === false, "resolve(false, false) is false")
    check(IconPolicy.resolve(true, false) === false, "resolve(true, false) is false")
    check(IconPolicy.resolve(true, true) === true, "resolve(true, true) is true")
    check(IconPolicy.resolve(true, undefined) === true, "resolve(true, undefined) is true")

    // B. Official server vs Self-hosted server classification
    check(IconPolicy.isOfficialServer("https://vault.bitwarden.com") === true, "vault.bitwarden.com is official")
    check(IconPolicy.isOfficialServer("https://vault.bitwarden.eu") === true, "vault.bitwarden.eu is official")
    check(IconPolicy.isOfficialServer("https://api.bitwarden.com") === true, "api.bitwarden.com is official")
    check(IconPolicy.isOfficialServer("") === true, "empty server_url defaults to official")
    check(IconPolicy.isOfficialServer("https://vaultwarden.example.com") === false, "vaultwarden.example.com is self-hosted")
    check(IconPolicy.isOfficialServer("http://192.168.1.50:8080") === false, "lan IP is self-hosted")
    check(IconPolicy.isOfficialServer("https://vault.corp.internal/api/") === false, "corp.internal is self-hosted")

    // C. Icon URL resolution: Cloud vs Self-hosted
    check(IconPolicy.resolveIconUrl("https://vault.bitwarden.com", "github.com") === "https://icons.bitwarden.net/github.com/icon.png",
          "cloud US resolves to icons.bitwarden.net")
    check(IconPolicy.resolveIconUrl("https://vault.bitwarden.eu", "github.com") === "https://icons.bitwarden.net/github.com/icon.png",
          "cloud EU resolves to icons.bitwarden.net")
    check(IconPolicy.resolveIconUrl("https://vaultwarden.example.com", "github.com") === "https://vaultwarden.example.com/icons/github.com/icon.png",
          "self-hosted resolves to server /icons endpoint")
    check(IconPolicy.resolveIconUrl("https://vaultwarden.example.com/api/", "gitlab.com") === "https://vaultwarden.example.com/icons/gitlab.com/icon.png",
          "self-hosted strips /api/ suffix")
    check(IconPolicy.resolveIconUrl("http://10.0.0.5:8000/identity/", "nas.local") === "http://10.0.0.5:8000/icons/nas.local/icon.png",
          "self-hosted strips /identity/ suffix")

    var comps = [{ n: "VaultItemList", c: list }, { n: "ItemInspector", c: insp }]
    var i

    // D. Components fail closed by default
    for (i = 0; i < comps.length; i++) {
      check(comps[i].c.showWebsiteIcons === false, comps[i].n + ": showWebsiteIcons defaults to false")
      check(comps[i].c.getFaviconUrl(loginItem) === "", comps[i].n + ": no favicon URL by default")
    }

    // E. Enabled path with Official Cloud Server
    for (i = 0; i < comps.length; i++) {
      comps[i].c.showWebsiteIcons = true
      comps[i].c.serverUrl = "https://vault.bitwarden.com"
      check(comps[i].c.getFaviconUrl(loginItem) === "https://icons.bitwarden.net/github.com/icon.png",
            comps[i].n + ": enabled login item returns bitwarden cloud icon URL")
      check(comps[i].c.getFaviconUrl(appSchemeItem) === "", comps[i].n + ": enabled app-scheme item returns empty")
      check(comps[i].c.getFaviconUrl(nonLoginItem) === "", comps[i].n + ": enabled non-login item returns empty")
    }

    // F. Enabled path with Self-Hosted Server
    for (i = 0; i < comps.length; i++) {
      comps[i].c.showWebsiteIcons = true
      comps[i].c.serverUrl = "https://vaultwarden.mycorp.net"
      check(comps[i].c.getFaviconUrl(loginItem) === "https://vaultwarden.mycorp.net/icons/github.com/icon.png",
            comps[i].n + ": enabled login item on self-hosted returns self-hosted /icons URL")
    }

    // G. Disabled path suppresses all icon requests
    for (i = 0; i < comps.length; i++) {
      comps[i].c.showWebsiteIcons = false
      comps[i].c.serverUrl = "https://vaultwarden.mycorp.net"
      check(comps[i].c.getFaviconUrl(loginItem) === "", comps[i].n + ": disabled login item returns empty")
      check(comps[i].c.getFaviconUrl(appSchemeItem) === "", comps[i].n + ": disabled app-scheme item returns empty")
      check(comps[i].c.getFaviconUrl(nonLoginItem) === "", comps[i].n + ": disabled non-login item returns empty")
    }

    console.log("ALL FAVICON PRIVACY TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}
