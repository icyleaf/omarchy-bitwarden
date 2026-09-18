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

cp "${ROOT_DIR}/dist/aur-git/PKGBUILD" "${BUILD_DIR}/"

if [ "${USE_LOCAL}" = true ]; then
  echo "==> Using local repository for git source..."
  sed -i "s|https://github.com/icyleaf/omarchy-bitwarden.git|file://${ROOT_DIR}|" "${BUILD_DIR}/PKGBUILD"
fi

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
