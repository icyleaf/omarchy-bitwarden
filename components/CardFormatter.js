.pragma library

/**
 * Clean all non-digit characters from a card number string.
 * Used for pure-digit clipboard copying and internal segment calculation.
 */
function cleanCardNumber(num) {
  if (num === null || num === undefined) return ""
  return String(num).replace(/\D/g, "")
}

/**
 * Sanitize card number for clipboard delivery.
 * Guarantees a clean, unsegmented pure-digit string without spaces or formatting delimiters.
 */
function sanitizeCardNumberForCopy(num) {
  return cleanCardNumber(num)
}

/**
 * Determine segment partition lengths for a card number based on length,
 * BIN prefixes, and card brand heuristics.
 */
function getCardSegments(cleanDigits, brand) {
  var len = cleanDigits ? cleanDigits.length : 0
  if (len <= 4) {
    return [len]
  }

  var b = (brand || "").toLowerCase().trim()
  var isAmexBrand = b === "amex" || b.indexOf("american express") !== -1 || b.replace(/\s+/g, "").indexOf("americanexpress") !== -1
  var isAmexBin = cleanDigits.startsWith("34") || cleanDigits.startsWith("37")

  // American Express: 15 digits -> 4-6-5
  if (len === 15 && (isAmexBin || isAmexBrand)) {
    return [4, 6, 5]
  }

  var isDinersBrand = b.indexOf("diners") !== -1
  var isDinersBin = cleanDigits.startsWith("36") || cleanDigits.startsWith("38") ||
                    cleanDigits.startsWith("300") || cleanDigits.startsWith("301") ||
                    cleanDigits.startsWith("302") || cleanDigits.startsWith("303") ||
                    cleanDigits.startsWith("304") || cleanDigits.startsWith("305")

  // Diners Club: 14 digits -> 4-6-4
  if (len === 14 && (isDinersBin || isDinersBrand)) {
    return [4, 6, 4]
  }

  // Standard cards (Visa, Mastercard, Discover, UnionPay, JCB, etc.): 4-4-4-4
  // For irregular lengths (> 4), chunk into groups of 4
  var segments = []
  var remaining = len
  while (remaining > 0) {
    var chunk = Math.min(4, remaining)
    segments.push(chunk)
    remaining -= chunk
  }
  return segments
}

/**
 * Format revealed card number with spaces between segments.
 * e.g. "4111 1111 1111 1111", "3782 822463 10005", "3612 345678 9012"
 */
function formatRevealedCardNumber(num, brand) {
  var clean = cleanCardNumber(num)
  if (!clean) return String(num || "")
  if (clean.length <= 4) return clean

  var segs = getCardSegments(clean, brand)
  var parts = []
  var idx = 0
  for (var i = 0; i < segs.length; i++) {
    var segLen = segs[i]
    if (idx >= clean.length) break
    parts.push(clean.slice(idx, idx + segLen))
    idx += segLen
  }
  if (idx < clean.length) {
    parts.push(clean.slice(idx))
  }
  return parts.join(" ")
}

/**
 * Format masked card number with bullet glyphs (•) matching the revealed
 * card segments and length, revealing only the last 4 digits.
 * e.g. "•••• •••• •••• 1111", "•••• •••••• •0005", "•••• •••••• 9012"
 */
function formatMaskedCardNumber(num, brand) {
  var clean = cleanCardNumber(num)
  if (!clean) return "•••• •••• •••• ••••"
  if (clean.length <= 4) {
    var dots = ""
    for (var d = 0; d < clean.length; d++) dots += "•"
    return dots
  }

  var segs = getCardSegments(clean, brand)
  var maskCount = clean.length - 4
  var last4 = clean.slice(-4)

  // Build raw masked string of length `clean.length`
  var maskedRaw = ""
  for (var m = 0; m < maskCount; m++) {
    maskedRaw += "•"
  }
  maskedRaw += last4

  // Partition raw masked string according to segments
  var parts = []
  var idx = 0
  for (var i = 0; i < segs.length; i++) {
    var segLen = segs[i]
    if (idx >= maskedRaw.length) break
    parts.push(maskedRaw.slice(idx, idx + segLen))
    idx += segLen
  }
  if (idx < maskedRaw.length) {
    parts.push(maskedRaw.slice(idx))
  }
  return parts.join(" ")
}
