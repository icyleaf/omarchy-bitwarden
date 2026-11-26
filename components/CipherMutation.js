.pragma library

// Pure helpers for Overlay cipher mutations (favorite toggle and delete).
// Keeping the optimistic list update here lets the headless QML suite exercise
// it directly instead of mirroring the logic.

// All five personal cipher types support favorite and delete mutations from the Overlay.
function isMutableType(item) {
  if (!item) return false
  return item.type_name === "login"
    || item.type_name === "note"
    || item.type_name === "card"
    || item.type_name === "identity"
    || item.type_name === "ssh_key"
}

// Cipher types currently supported by Inspector Form (CipherEditor) editing.
function isEditableType(item) {
  if (!item) return false
  return item.type_name === "login"
    || item.type_name === "note"
    || item.type_name === "card"
    || item.type_name === "identity"
    || item.type_name === "ssh_key"
}

function isOrganizationOwned(item) {
  return Boolean(item && item.organization_id)
}

function canMutate(item) {
  return isMutableType(item) && !isOrganizationOwned(item)
}

// Per-user Favorite & Folder assignment work on all readable personal and
// Organization Ciphers via `PUT /ciphers/{id}/partial`.
function canFavorite(item) {
  return isMutableType(item)
}

function canAssignFolder(item) {
  return isMutableType(item)
}

// Organization Cipher editing is gated by `edit && view_password` and deletion
// is gated by `can_delete` (`permissions.delete`), both fail-closed false when absent.
function canEdit(item) {
  if (!isEditableType(item)) return false
  if (!isOrganizationOwned(item)) return true
  return Boolean(item.edit) && Boolean(item.view_password)
}

function editGuardError(item) {
  if (!isEditableType(item)) return ""
  if (!isOrganizationOwned(item)) return ""
  if (!item.edit) return "You do not have permission to edit this Organization cipher."
  if (!item.view_password) return "Cannot edit this Organization cipher because passwords are hidden."
  return ""
}

function canDelete(item) {
  if (!isMutableType(item)) return false
  if (!isOrganizationOwned(item)) return true
  return Boolean(item.can_delete)
}

function deleteGuardError(item) {
  if (!isMutableType(item)) return ""
  if (!isOrganizationOwned(item)) return ""
  if (!item.can_delete) return "You do not have permission to delete this Organization cipher."
  return ""
}

function withFolder(items, itemId, folderId, folderName) {
  var out = []
  var src = items || []
  for (var i = 0; i < src.length; i++) {
    var row = src[i]
    if (row && row.id === itemId) {
      var copy = Object.assign({}, row)
      copy.folder_id = folderId || null
      copy.folder_name = folderId ? (folderName || null) : null
      out.push(copy)
    } else {
      out.push(row)
    }
  }
  return out
}

function nextFavorite(item) {
  return !Boolean(item && item.favorite)
}

// Returns a new list with the target row's favorite flag replaced. The input
// list and its row objects are left untouched so callers can roll back by
// re-applying the previous value.
function withFavorite(items, itemId, favorite) {
  var out = []
  var src = items || []
  for (var i = 0; i < src.length; i++) {
    var row = src[i]
    if (row && row.id === itemId) {
      var copy = Object.assign({}, row)
      copy.favorite = Boolean(favorite)
      out.push(copy)
    } else {
      out.push(row)
    }
  }
  return out
}

// Per-URI match detection rules aligned with Bitwarden wire values (null or 0..=5).
// ListModel uses -1 as a typed integer sentinel for Default (null).
var URI_MATCH_OPTIONS = [
  { value: -1, wire: null, label: "Default" },
  { value: 0, wire: 0, label: "Base Domain" },
  { value: 1, wire: 1, label: "Host" },
  { value: 2, wire: 2, label: "Starts With" },
  { value: 3, wire: 3, label: "Exact" },
  { value: 4, wire: 4, label: "Regex" },
  { value: 5, wire: 5, label: "Never" }
]

function normalizeUriMatchRule(value) {
  if (value === null || value === undefined || value === "") return -1
  var n = Number(value)
  if (!isNaN(n) && Math.floor(n) === n && n >= 0 && n <= 5) return n
  return -1
}

function uriMatchRuleToWire(rule) {
  var n = normalizeUriMatchRule(rule)
  return n >= 0 ? n : null
}

function uriMatchRuleIndex(rule) {
  var n = normalizeUriMatchRule(rule)
  for (var i = 0; i < URI_MATCH_OPTIONS.length; i++) {
    if (URI_MATCH_OPTIONS[i].value === n) return i
  }
  return 0
}

// Pre-submit Login TOTP seed validation matching omawarden::totp::validate_totp_seed.
// Returns "" when empty (optional/clearing) or valid, or an error message string.
function validateTotpSeed(rawInput) {
  var raw = String(rawInput || "").trim()
  if (raw.length === 0) return ""

  var secret = ""
  var algorithm = "SHA1"
  var digits = 6
  var period = 30

  function parseQuery(queryStr) {
    var pairs = queryStr.split("&")
    for (var i = 0; i < pairs.length; i++) {
      var part = pairs[i]
      if (!part) continue
      var eq = part.indexOf("=")
      if (eq < 0) continue
      var k = ""
      var v = ""
      try {
        k = decodeURIComponent(part.slice(0, eq))
        v = decodeURIComponent(part.slice(eq + 1))
      } catch (e) {
        return "Invalid TOTP URI: malformed percent-encoding in query parameters."
      }
      if (k === "secret") {
        secret = v.replace(/\s+/g, "")
      } else if (k === "algorithm") {
        algorithm = v.toUpperCase()
      } else if (k === "digits") {
        if (!/^\d+$/.test(v)) return "Invalid TOTP digits parameter '" + v + "'."
        digits = parseInt(v, 10)
      } else if (k === "period") {
        if (!/^\d+$/.test(v)) return "Invalid TOTP period parameter '" + v + "'."
        period = parseInt(v, 10)
      }
    }
    return ""
  }

  if (raw.indexOf("otpauth://") === 0 || raw.indexOf("otpauth-migration://") === 0) {
    var qIdx = raw.indexOf("?")
    if (qIdx < 0) return "Invalid TOTP URI: missing secret parameter."
    var uriErr = parseQuery(raw.slice(qIdx + 1))
    if (uriErr) return uriErr
  } else if (raw.indexOf("?") >= 0) {
    var sep = raw.indexOf("?")
    secret = raw.slice(0, sep).replace(/\s+/g, "")
    var qErr = parseQuery(raw.slice(sep + 1))
    if (qErr) return qErr
  } else {
    secret = raw.replace(/\s+/g, "")
  }

  if (!secret) return "Invalid TOTP seed: missing secret parameter."
  if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") {
    return "Unsupported TOTP algorithm '" + algorithm + "'. Supported algorithms are SHA1, SHA256, and SHA512."
  }
  if (digits < 1 || digits > 9) {
    return "Invalid TOTP digits '" + digits + "'. Expected a value between 1 and 9 (typically 6 or 8)."
  }
  if (period <= 0) {
    return "Invalid TOTP period '0'. Period must be at least 1 second."
  }
  if (!/^[A-Za-z2-7]+=*$/.test(secret)) {
    return "Invalid TOTP secret: expected valid Base32 characters (A-Z, 2-7)."
  }
  var unpadded = secret.replace(/=+$/, "")
  var padLen = secret.length - unpadded.length
  var rem = unpadded.length % 8
  if (unpadded.length === 0 || rem === 1 || rem === 3 || rem === 6) {
    return "Invalid TOTP secret: expected valid Base32 characters (A-Z, 2-7)."
  }
  if (padLen > 0 && (secret.length % 8 !== 0 || padLen !== (8 - rem) % 8)) {
    return "Invalid TOTP secret: invalid Base32 padding."
  }
  return ""
}
