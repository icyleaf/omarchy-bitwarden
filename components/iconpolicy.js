.pragma library
function resolve(configLoaded, configValue) {
  if (!configLoaded) return false
  return configValue !== false
}
