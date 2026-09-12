#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL=false
for arg in "$@"; do
  case "$arg" in
    -i|--install)
      INSTALL=true
      ;;
  esac
done

if ! command -v makepkg >/dev/null 2>&1; then
  echo "Error: 'makepkg' command not found. Please install pacman / base-devel tools."
  exit 1
fi

echo "==> Building omawarden in release mode..."
(cd "${ROOT_DIR}/omawarden" && cargo build --release)

CARGO_VER=$(grep '^version = ' "${ROOT_DIR}/omawarden/Cargo.toml" | head -n 1 | cut -d'"' -f2)
# Pacman forbids '-' in pkgver, replace '-' with '.' (e.g., 0.8.0-dev -> 0.8.0.dev)
PKGVER="${CARGO_VER//-/.}"

BUILD_DIR="${ROOT_DIR}/dist/pkg-dev"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

cp "${ROOT_DIR}/omawarden/target/release/omawarden" "${BUILD_DIR}/"
cp "${ROOT_DIR}/LICENSE" "${BUILD_DIR}/"

cat << PKG_EOF > "${BUILD_DIR}/PKGBUILD"
# Maintainer: icyleaf <icyleaf.cn at gmail dot com>

pkgname=omawarden-bin
pkgver=${PKGVER}
pkgrel=1
pkgdesc="High-performance Bitwarden CLI and resident daemon (Local Development Build)"
arch=('x86_64' 'aarch64')
url="https://github.com/icyleaf/omarchy-bitwarden"
license=('MIT')
depends=('libsecret' 'wl-clipboard')
provides=('omawarden')
conflicts=('omawarden')
source=("omawarden" "LICENSE")
sha256sums=('SKIP' 'SKIP')

package() {
    install -Dm755 "\${srcdir}/omawarden" "\${pkgdir}/usr/bin/omawarden"
    install -Dm644 "\${srcdir}/LICENSE" "\${pkgdir}/usr/share/licenses/\${pkgname}/LICENSE"
}
PKG_EOF

echo "==> Packaging omawarden-bin ${PKGVER} via makepkg..."
(cd "${BUILD_DIR}" && makepkg -f --nodeps)

PKG_FILE=$(find "${BUILD_DIR}" -name "*.pkg.tar.zst" | head -n 1)
if [ -z "${PKG_FILE}" ]; then
  echo "Error: Failed to create Arch Linux package (.pkg.tar.zst)"
  exit 1
fi

mkdir -p "${ROOT_DIR}/dist"
cp -f "${PKG_FILE}" "${ROOT_DIR}/dist/"
FINAL_PKG="${ROOT_DIR}/dist/$(basename "${PKG_FILE}")"

echo "==> Successfully generated package: ${FINAL_PKG}"

if [ "${INSTALL}" = true ]; then
  echo "==> Installing ${FINAL_PKG} with pacman..."
  sudo pacman -U --noconfirm "${FINAL_PKG}"
  echo "==> Installed omawarden to /usr/bin/omawarden:"
  /usr/bin/omawarden -V || true
else
  echo ""
  echo "To install this local development package into your system, run:"
  echo "  sudo pacman -U ${FINAL_PKG}"
  echo "Or run with --install flag: mise run pkg-dev --install"
fi
