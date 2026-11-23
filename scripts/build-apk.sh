#!/usr/bin/env bash
#
# Build a real Alpine .apk with abuild.
#
# abuild is not available on most Debian/Ubuntu hosts, so the default path
# builds inside a Go-enabled Alpine container. Set BUILDER_IMAGE to an image
# that already contains abuild (and Go) to avoid installing abuild at runtime.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' "$ROOT/internal/engine/engine.go" 2>/dev/null || true)}"
VERSION="${VERSION:-0.1.0}"
PKGREL="${PKGREL:-0}"
OUTDIR="${OUTDIR:-$ROOT/dist}"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.26-alpine}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/gojail-apk.XXXXXX")"
BUILD="$WORKDIR/build"
OUT="$WORKDIR/out"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

die() {
    echo "error: $*" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || die "git is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v docker >/dev/null 2>&1 || die "docker is required (or run abuild manually from packaging/apk)"

mkdir -p "$BUILD" "$OUT" "$OUTDIR"
rm -f "$OUTDIR/gojail-${VERSION}-r${PKGREL}.apk"
rm -rf "$OUTDIR/apk-keys"

# Build the source archive from tracked and untracked-but-not-ignored files.
# This keeps uncommitted packaging changes available to abuild while excluding
# .git, bin/ and dist/.
echo "==> creating source archive"
(
    cd "$ROOT"
    git ls-files -z --cached --others --exclude-standard \
        | tar --null -T - --transform "s#^#gojail-$VERSION/#" \
              -czf "$BUILD/gojail-$VERSION.tar.gz"
)

[ -s "$BUILD/gojail-$VERSION.tar.gz" ] || die "source archive is empty"

cp "$ROOT/packaging/apk/APKBUILD" "$BUILD/APKBUILD"
cp "$ROOT"/packaging/apk/gojail.pre-install \
   "$ROOT"/packaging/apk/gojail.post-install \
   "$ROOT"/packaging/apk/gojail.pre-deinstall \
   "$BUILD/"

# Keep the package version in sync with the requested build version.
sed -i \
    -e "s/^pkgver=.*/pkgver=$VERSION/" \
    -e "s/^pkgrel=.*/pkgrel=$PKGREL/" \
    "$BUILD/APKBUILD"
sed -i '/^sha512sums=/d' "$BUILD/APKBUILD"

if command -v sha512sum >/dev/null 2>&1; then
    SHA512="$(sha512sum "$BUILD/gojail-$VERSION.tar.gz" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    SHA512="$(shasum -a 512 "$BUILD/gojail-$VERSION.tar.gz" | awk '{print $1}')"
else
    die "sha512sum or shasum is required"
fi
printf '\nsha512sums="%s  gojail-%s.tar.gz"\n' "$SHA512" "$VERSION" >> "$BUILD/APKBUILD"

cat > "$WORKDIR/run-abuild.sh" <<'EOF'
#!/bin/sh
set -eu

if ! command -v abuild >/dev/null 2>&1; then
    apk add --no-cache abuild >/dev/null
fi

if ! id builder >/dev/null 2>&1; then
    adduser -D builder
fi
addgroup builder abuild 2>/dev/null || true

# mktemp creates the host work directory as 0700 root; let builder traverse it.
chmod 755 /work
chown -R builder /work/build

# Generate a signing key and trust it inside the container. Without this,
# `abuild -r` fails while updating the package index with an untrusted key.
su builder -c 'cd /work/build && abuild-keygen -a -n >/dev/null'
cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/

# -d skips dependency checks: the Go toolchain is already in the builder image
# and nftables is a runtime dependency, not a build dependency.
su builder -c 'cd /work/build && PACKAGER="Meng Zhuo <mengzhuo@iscas.ac.cn>" abuild -d -r -P /work/build/packages'

mkdir -p /work/out/keys
find /work/build/packages -type f -name '*.apk' -exec cp {} /work/out/ \;
cp /home/builder/.abuild/*.rsa.pub /work/out/keys/ 2>/dev/null || true
EOF
chmod +x "$WORKDIR/run-abuild.sh"

echo "==> building APK with $BUILDER_IMAGE"
docker run --rm \
    -v "$WORKDIR:/work" \
    "$BUILDER_IMAGE" \
    /bin/sh /work/run-abuild.sh

APK="$(find "$OUT" -maxdepth 1 -type f -name '*.apk' | head -n 1)"
[ -n "$APK" ] || die "abuild did not produce an APK"

# Verify the two package requirements that matter for this project.
# GNU tar warns about APK's extended checksum headers; those are expected.
PKGINFO="$(tar -xOzf "$APK" .PKGINFO 2>/dev/null)"
printf '%s\n' "$PKGINFO" | grep -qx 'depend = nftables' \
    || die "APK is missing 'depend = nftables'"
printf '%s\n' "$PKGINFO" | grep -qx 'depend = !fail2ban' \
    || die "APK is missing 'depend = !fail2ban'"

mkdir -p "$OUTDIR/apk-keys"
cp "$OUT"/keys/*.rsa.pub "$OUTDIR/apk-keys/" 2>/dev/null || true
cp "$APK" "$OUTDIR/"

echo "==> built $OUTDIR/$(basename "$APK")"
echo "==> signing key:"
ls -1 "$OUTDIR"/apk-keys/*.rsa.pub 2>/dev/null || echo "    (no public key copied)"
