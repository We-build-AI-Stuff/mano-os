#!/usr/bin/env bash
set -euo pipefail

# Both callers run on Ubuntu 24.04 GitHub-hosted runners.
source /etc/os-release
if [[ ${GITHUB_ACTIONS:-} != true || $ID != ubuntu || $VERSION_CODENAME != noble ]]; then
    echo "Ubuntu Noble GitHub Actions runner required" >&2
    exit 1
fi

options=(-o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15)
install_packages() {
    sudo apt-get "${options[@]}" -o APT::Update::Error-Mode=any update &&
        sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
}

if install_packages "$@"; then
    exit 0
fi

echo "Runner package sources failed. Retrying with a signed Ubuntu archive mirror." >&2
source_dir=$(mktemp -d)
trap 'rm -rf -- "$source_dir"' EXIT
cat > "$source_dir/ubuntu.sources" <<'SOURCES'
Types: deb
URIs: https://mirrors.edge.kernel.org/ubuntu
Suites: noble noble-updates noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
options+=(-o "Dir::Etc::SourceList=$source_dir/ubuntu.sources" -o Dir::Etc::SourceParts=-)
install_packages "$@"
