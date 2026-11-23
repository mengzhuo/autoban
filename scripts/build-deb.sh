#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' "$ROOT/internal/engine/engine.go" 2>/dev/null || true)}"
VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-$(dpkg --print-architecture)}"
STAGE="$ROOT/dist/deb/gojail_${VERSION}_${ARCH}"
OUT="$ROOT/dist/gojail_${VERSION}_${ARCH}.deb"

cd "$ROOT"
rm -rf "$STAGE" "$OUT"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/systemd/system" "$STAGE/usr/lib/sysusers.d" "$STAGE/etc/gojail"

CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/gojail" ./cmd/gojail
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/gj" ./cmd/gj
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$STAGE/usr/bin/gj-regex" ./cmd/gj-regex

install -m 0644 packaging/common/gojail.conf "$STAGE/etc/gojail/gojail.conf"
install -m 0644 packaging/common/jail.deb.local "$STAGE/etc/gojail/jail.local"
cp -r config/filter.d "$STAGE/etc/gojail/"
cp -r config/action.d "$STAGE/etc/gojail/"
install -m 0644 packaging/common/gojail.service "$STAGE/usr/lib/systemd/system/gojail.service"
install -m 0644 contrib/gojail.sysusers "$STAGE/usr/lib/sysusers.d/gojail.conf"

sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" packaging/deb/control.in > "$STAGE/DEBIAN/control"
install -m 0755 packaging/deb/postinst "$STAGE/DEBIAN/postinst"
install -m 0755 packaging/deb/prerm "$STAGE/DEBIAN/prerm"
install -m 0755 packaging/deb/postrm "$STAGE/DEBIAN/postrm"
(cd "$STAGE" && find etc/gojail -type f | sort | sed 's#^#/#' > DEBIAN/conffiles)

dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built $OUT"
dpkg-deb -I "$OUT"
