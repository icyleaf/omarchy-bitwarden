.pragma library

// Pure helpers for Overlay cipher mutations (favorite toggle and delete).
// Keeping the optimistic list update here lets the headless QML suite exercise
// it directly instead of mirroring the logic.

// Only personal Login and Secure Note ciphers are mutable from the Overlay.
function isMutableType(item) {
  if (!item) return false
  return item.type_name === "login" || item.type_name === "note"
}

function isOrganizationOwned(item) {
  return Boolean(item && item.organization_id)
}

function canMutate(item) {
  return isMutableType(item) && !isOrganizationOwned(item)
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
