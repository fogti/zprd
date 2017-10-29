#!/bin/bash

errmsg() {
  echo "pack.sh failed at: " $@
  exit 1
}

PN="zprd"
COMMIT="$(git rev-list --tags --max-count=1)"
TAG="$(git describe --tags "$COMMIT")"

echo "using tag $TAG -> commit $COMMIT"

CURVER="$1"
[ -z "$CURVER" ] && CURVER="$(echo "$TAG" | cut -c2-)"
[ -z "$CURVER" ] && errmsg version
echo "using version $CURVER"

echo -n "sleep ..."
for n in `seq 5`; do
  echo -n " $n"
  sleep 1
done
echo

echo "------------"
echo "mktemp ..."
TMPD="$(mktemp -d)" || errmsg mktemp

P="$PN-$CURVER"
mkdir -p "$TMPD/$P" || errmsg mkdir

echo "copy files ..."
for i in *; do
  case "$i" in
    (pack.sh) continue ;;
  esac
  echo " - $i"
  cp -rt "$TMPD/$P" "$i" || errmsg cp
done

echo "create tar ..."
tar czf "$(realpath "../$P.tar.gz")" -C "$TMPD" "$P" || errmsg tar
rm -r "$TMPD"
