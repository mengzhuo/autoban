#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' "$ROOT/internal/engine/engine.go" 2>/dev/null || true)}"
VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-$(dpkg --print-architecture)}"
STAGE="$ROOT/dist/deb/autoban_${VERSION}_${ARCH}"
OUT="$ROOT/dist/autoban_${VERSION}_${ARCH}.deb"

cd "$ROOT"
rm -rf "$STAGE" "$OUT"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/systemd/system" "$STAGE/usr/lib/sysusers.d" "$STAGE/etc/autoban"

CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/autoban" ./cmd/autoban
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/autoban-ctl" ./cmd/autoban-ctl
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/autoban-regex" ./cmd/autoban-regex

install -m 0644 packaging/common/autoban.conf "$STAGE/etc/autoban/autoban.conf"
install -m 0644 packaging/common/jail.deb.local "$STAGE/etc/autoban/jail.local"
cp -r config/filter.d "$STAGE/etc/autoban/"
cp -r config/action.d "$STAGE/etc/autoban/"
install -m 0644 packaging/common/autoban.service "$STAGE/usr/lib/systemd/system/autoban.service"
install -m 0644 contrib/autoban.sysusers "$STAGE/usr/lib/sysusers.d/autoban.conf"

sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" packaging/deb/control.in > "$STAGE/DEBIAN/control"
install -m 0755 packaging/deb/postinst "$STAGE/DEBIAN/postinst"
install -m 0755 packaging/deb/prerm "$STAGE/DEBIAN/prerm"
install -m 0755 packaging/deb/postrm "$STAGE/DEBIAN/postrm"
(cd "$STAGE" && find etc/autoban -type f | sort | sed 's#^#/#' > DEBIAN/conffiles)

dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built $OUT"
dpkg-deb -I "$OUT"
