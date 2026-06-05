#!/bin/sh
# Install the latest mail release binary.
#
# Usage: ./install.sh [version]
#   version: tag like v0.1.0; defaults to the latest release.
set -eu

REPO="Glyndor/mail"
ARCH="x86_64-linux"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

version="${1:-}"
if [ -z "$version" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -n 1 | cut -d '"' -f 4)
fi
if [ -z "$version" ]; then
	echo "error: cannot determine the latest release" >&2
	exit 1
fi

base="https://github.com/${REPO}/releases/download/${version}"
binary="mail-${version}-${ARCH}"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

echo "Downloading ${binary} ..."
curl -fsSL -o "${workdir}/${binary}" "${base}/${binary}"
curl -fsSL -o "${workdir}/SHA256SUMS" "${base}/SHA256SUMS"

echo "Verifying checksum ..."
(cd "$workdir" && grep " ${binary}\$" SHA256SUMS | sha256sum -c -)

echo "Installing to ${INSTALL_DIR}/mail ..."
install -m 0755 "${workdir}/${binary}" "${INSTALL_DIR}/mail"

echo "Installed: $("${INSTALL_DIR}/mail" --version)"
