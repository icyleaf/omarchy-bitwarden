import QtQuick
import QtQuick.Controls
import "../components"
import "../components/iconpolicy.js" as IconPolicy

Item {
  property int failures: 0
  function check(cond, msg) { if (!cond) { failures++; console.error("FAIL: " + msg) } }

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
    // A. Policy truth table — fail closed until config has actually loaded
    check(IconPolicy.resolve(false, true) === false, "resolve(false, true) is false")
    check(IconPolicy.resolve(false, undefined) === false, "resolve(false, undefined) is false")
    check(IconPolicy.resolve(false, false) === false, "resolve(false, false) is false")
    check(IconPolicy.resolve(true, false) === false, "resolve(true, false) is false")
    check(IconPolicy.resolve(true, true) === true, "resolve(true, true) is true")
    check(IconPolicy.resolve(true, undefined) === true, "resolve(true, undefined) is true")

    var comps = [{ n: "VaultItemList", c: list }, { n: "ItemInspector", c: insp }]
    var i

    // B. Components fail closed by default
    for (i = 0; i < comps.length; i++) {
      check(comps[i].c.showWebsiteIcons === false, comps[i].n + ": showWebsiteIcons defaults to false")
      check(comps[i].c.getFaviconUrl(loginItem) === "", comps[i].n + ": no favicon URL by default")
    }

    // C. Enabled path
    for (i = 0; i < comps.length; i++) {
      comps[i].c.showWebsiteIcons = true
      check(comps[i].c.getFaviconUrl(loginItem) === "https://icons.bitwarden.net/github.com/icon.png",
            comps[i].n + ": enabled login item returns bitwarden icon URL")
      check(comps[i].c.getFaviconUrl(appSchemeItem) === "", comps[i].n + ": enabled app-scheme item returns empty")
      check(comps[i].c.getFaviconUrl(nonLoginItem) === "", comps[i].n + ": enabled non-login item returns empty")
    }

    // D. Disabled path
    for (i = 0; i < comps.length; i++) {
      comps[i].c.showWebsiteIcons = false
      check(comps[i].c.getFaviconUrl(loginItem) === "", comps[i].n + ": disabled login item returns empty")
      check(comps[i].c.getFaviconUrl(appSchemeItem) === "", comps[i].n + ": disabled app-scheme item returns empty")
      check(comps[i].c.getFaviconUrl(nonLoginItem) === "", comps[i].n + ": disabled non-login item returns empty")
    }

    Qt.exit(failures === 0 ? 0 : 1)
  }
}
