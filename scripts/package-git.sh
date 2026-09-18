#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL=false
USE_LOCAL=false

for arg in "$@"; do
  case "$arg" in
    -i|--install)
      INSTALL=true
      ;;
    -l|--local)
      USE_LOCAL=true
      ;;
    -h|--help)
      echo "Usage: $0 [-i|--install] [-l|--local]"
      echo "  -i, --install   Install the built package using sudo pacman -U"
      echo "  -l, --local     Use local git repository instead of remote GitHub URL for packaging test"
      exit 0
      ;;
  esac
done

if ! command -v makepkg >/dev/null 2>&1; then
  echo "Error: 'makepkg' command not found. Please install pacman / base-devel tools."
  exit 1
fi

BUILD_DIR="${ROOT_DIR}/dist/pkg-git"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

GIT_REPO_URL="https://github.com/icyleaf/omarchy-bitwarden.git"
if [ "${USE_LOCAL}" = true ]; then
  echo "==> Using local repository for git source..."
  GIT_REPO_URL="file://${ROOT_DIR}"
fi

cat << PKG_EOF > "${BUILD_DIR}/PKGBUILD"
# Maintainer: icyleaf <icyleaf.cn at gmail dot com>

pkgname=omawarden-git
pkgver=0.8.0.r0.g0000000
pkgrel=1
pkgdesc="High-performance Bitwarden CLI and resident daemon (VCS build from develop branch)"
arch=('x86_64' 'aarch64')
url="https://github.com/icyleaf/omarchy-bitwarden"
license=('MIT')
depends=('libsecret' 'wl-clipboard')
makedepends=('cargo' 'git')
optdepends=('libfido2: WebAuthn / Passkey / FIDO2 security key support')
provides=('omawarden' 'omawarden-bin')
conflicts=('omawarden' 'omawarden-bin')
options=('!lto')
source=("omarchy-bitwarden::git+${GIT_REPO_URL}#branch=develop")
sha256sums=('SKIP')

pkgver() {
    cd "\${srcdir}/omarchy-bitwarden"
    _ver=\$(grep '^version = ' omawarden/Cargo.toml | head -n 1 | cut -d'"' -f2 | cut -d'-' -f1)
    _rev=\$(git rev-list --count HEAD)
    _hash=\$(git rev-parse --short=7 HEAD)
    printf "%s.r%s.g%s" "\$_ver" "\$_rev" "\$_hash"
}

build() {
    cd "\${srcdir}/omarchy-bitwarden/omawarden"
    cargo build --frozen --release --bin omawarden
}

package() {
    cd "\${srcdir}/omarchy-bitwarden"
    install -Dm755 omawarden/target/release/omawarden "\${pkgdir}/usr/bin/omawarden"
    install -Dm644 LICENSE "\${pkgdir}/usr/share/licenses/\${pkgname}/LICENSE"
}
PKG_EOF

echo "==> Packaging omawarden-git via makepkg..."
(cd "${BUILD_DIR}" && makepkg -f --nodeps)

PKG_FILE=$(find "${BUILD_DIR}" -name "omawarden-git-*.pkg.tar.zst" | head -n 1)
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
  echo "To install this development package into your system, run:"
  echo "  sudo pacman -U ${FINAL_PKG}"
  echo "Or run with --install flag: mise run pkg-git --install"
fi
