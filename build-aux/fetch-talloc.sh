#!/bin/sh
# Fetch the talloc source tarball, samba.org-outage-proof.
#
# Every CI run re-downloads talloc; www.samba.org has already served
# truncated bodies ("gzip: stdin: not in gzip format") and 504s, which
# fails the android and musl builds without any nproot change.  Try
# the known-good locations in order and hand the tarball over only
# when its sha256 matches the published one.
#
# usage: sh build-aux/fetch-talloc.sh [output.tar.gz]
set -eu

OUT=${1:-talloc-2.4.2.tar.gz}
SHA256=85ecf9e465e20f98f9950a52e9a411e14320bc555fa257d87697b7e7a9b1d8a6

fetch() {	# fetch <url> <out>  (curl when present, busybox wget otherwise)
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 2 --max-time 120 -o "$2" "$1"
	else
		wget -q -T 120 -O "$2" "$1"
	fi
}

for url in \
	https://download.samba.org/pub/talloc/talloc-2.4.2.tar.gz \
	https://ftp.samba.org/pub/talloc/talloc-2.4.2.tar.gz \
	http://archive.ubuntu.com/ubuntu/pool/main/t/talloc/talloc_2.4.2.orig.tar.gz \
	https://www.samba.org/ftp/talloc/talloc-2.4.2.tar.gz
do
	echo "fetch-talloc: trying $url"
	if fetch "$url" "$OUT" &&
	   echo "$SHA256  $OUT" | sha256sum -c - >/dev/null 2>&1; then
		echo "fetch-talloc: $(wc -c < "$OUT") bytes, sha256 ok"
		exit 0
	fi
	echo "fetch-talloc: $url unusable, trying the next mirror"
	rm -f "$OUT"
done

echo "fetch-talloc: all mirrors failed" >&2
exit 1
