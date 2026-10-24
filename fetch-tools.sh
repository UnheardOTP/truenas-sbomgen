#!/bin/sh
# Build-time: download Syft and Grype (pinned via build args, or the latest release)
# and verify each against the release's published SHA-256 checksums.
set -eu
mkdir -p /out
for tool in syft grype; do
  ver=$(eval echo "\${$(echo "$tool" | tr a-z A-Z)_VERSION:-}")
  if [ -z "$ver" ]; then
    ver=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/anchore/$tool/releases/latest" \
          | sed -n 's#.*/tag/v\([0-9][0-9.]*\)$#\1#p')
  fi
  [ -n "$ver" ] || { echo "could not resolve $tool version" >&2; exit 1; }
  tgz="${tool}_${ver}_linux_amd64.tar.gz"
  base="https://github.com/anchore/$tool/releases/download/v$ver"
  cd /tmp
  curl -fsSLO "$base/$tgz"
  curl -fsSLO "$base/${tool}_${ver}_checksums.txt"
  grep " ${tgz}\$" "${tool}_${ver}_checksums.txt" | sha256sum -c -
  tar -xzf "$tgz" -C /out "$tool"
  echo "$tool=$ver" >> /out/VERSIONS
done
cat /out/VERSIONS
