.pragma library

function resolve(configLoaded, configValue) {
  if (!configLoaded) return false
  return configValue !== false
}

function extractHost(serverUrl) {
  if (!serverUrl) return ""
  var str = String(serverUrl).trim()
  var match = str.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?([^:\/\n?#]+)/i)
  return match ? match[1].toLowerCase() : ""
}

function isOfficialServer(serverUrl) {
  var host = extractHost(serverUrl)
  if (!host) return true
  return host === "bitwarden.com" || host.endsWith(".bitwarden.com") ||
         host === "bitwarden.eu" || host.endsWith(".bitwarden.eu")
}

function getIconBaseUrl(serverUrl) {
  if (isOfficialServer(serverUrl)) {
    return "https://icons.bitwarden.net"
  }
  var trimmed = String(serverUrl || "").trim()
  if (!trimmed) {
    return "https://icons.bitwarden.net"
  }
  var normalized = trimmed
  if (!normalized.match(/^https?:\/\//i)) {
    normalized = "https://" + normalized
  }
  normalized = normalized.replace(/\/+$/, "")
  normalized = normalized.replace(/\/api$/i, "").replace(/\/identity$/i, "").replace(/\/+$/, "")
  return normalized + "/icons"
}

function resolveIconUrl(serverUrl, domain) {
  if (!domain) return ""
  var base = getIconBaseUrl(serverUrl)
  return base + "/" + domain + "/icon.png"
}
