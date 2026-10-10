#!/usr/bin/env bash
# Fetch the MIB corpus into corpus/ (not committed) and build its index.
#
#   interop/mibs/fetch.sh [--update-pins] [--no-index] [--no-swap] [SOURCE...]
#
# SOURCE is any of: netsnmp ietf-iana librenms cisco pysnmp juniper nokia (default: all).
# Every source is pinned: git sources by commit (partial + sparse clone, only
# the MIB directories are checked out), the IETF/IANA set (extracted from the
# interop lab image, Ubuntu package snmp-mibs-downloader 1.6) by the sha256
# manifest pins/ietf-iana.sha256 (--update-pins rewrites that manifest), the
# official Juniper bundles (public downloads) by URL + sha256 in
# pins/juniper.tsv, and the Nokia SR OS bundles by path + sha256 in
# pins/nokia.tsv. The Nokia bundles are proprietary and optional: they are
# copied from $MIBLAB_NOKIA_DIR and skipped with a notice when it is unset or
# an archive is missing.
# index.py then scans the corpus and builds corpus/flat/ (one file per unique
# module name, see README.md). The new flat/, split/, index/, duplicates.tsv
# and vendors.tsv are built next to the published ones and swapped in
# atomically; --no-swap leaves them staged as *.new for swap.py, e.g. to run
# the oracles on them first.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# --- pins -------------------------------------------------------------------
NETSNMP_URL=https://github.com/net-snmp/net-snmp
NETSNMP_REF=v5.9.4
NETSNMP_COMMIT=7d38b8299e26708ee92c9fe1628e5a000bc23e17
NETSNMP_PATHS=(/mibs/)

LIBRENMS_URL=https://github.com/librenms/librenms
LIBRENMS_REF=26.9.1
LIBRENMS_COMMIT=4ce3be87e0edb5d82a041f8319fc9fa30e207c89
LIBRENMS_PATHS=(/mibs/)

CISCO_URL=https://github.com/cisco/cisco-mibs
CISCO_REF=main@2026-09-29
CISCO_COMMIT=c9ab98c03ee051de74edda72f6d5c43ee65cad91
CISCO_PATHS=(/v2/ /v1/)

# Scrape of mibs.snmplabs.com (2020-01-31), pysmi's default MIB source
# (https://mibs.pysnmp.com/asn1/); repo is Apache-2.0, the MIBs keep their own terms.
PYSNMP_URL=https://github.com/lextudio/mibs.pysnmp.com
PYSNMP_REF=master@2025-10-05
PYSNMP_COMMIT=32ab65b4316cbff85f26eef47dd80299521f2630
PYSNMP_PATHS=(/asn1/)

IETF_IANA_PINS="$MIBS_DIR/pins/ietf-iana.sha256"

# Official vendor bundles: pins/juniper.tsv (URL + sha256), pins/nokia.tsv (local path + sha256).
JUNIPER_PINS="$MIBS_DIR/pins/juniper.tsv"
NOKIA_PINS="$MIBS_DIR/pins/nokia.tsv"
NOKIA_DIR="${MIBLAB_NOKIA_DIR:-}"
# ----------------------------------------------------------------------------

update_pins=0
do_index=1
swap_arg=()
sources=()
for a in "$@"; do
    case "$a" in
        --update-pins) update_pins=1 ;;
        --no-index) do_index=0 ;;
        --no-swap) swap_arg=(--no-swap) ;;
        netsnmp|ietf-iana|librenms|cisco|pysnmp|juniper|nokia) sources+=("$a") ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done
[ ${#sources[@]} -gt 0 ] || sources=(netsnmp ietf-iana librenms cisco pysnmp juniper nokia)

mkdir -p "$CORPUS_DIR/src"

# git_sparse NAME URL COMMIT PATH...: partial clone of one commit, sparse
# checkout of PATHs only. Idempotent: does nothing if already at COMMIT.
git_sparse() {
    local name=$1 url=$2 commit=$3; shift 3
    local dir="$CORPUS_DIR/src/$name"
    if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null)" = "$commit" ]; then
        log "$name: already at $commit"
    else
        log "$name: fetching $url @ $commit (paths: $*)"
        rm -rf "$dir"
        git init -q "$dir"
        git -C "$dir" config gc.auto 0
        git -C "$dir" remote add origin "$url"
        git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$commit"
        git -C "$dir" sparse-checkout set --no-cone "$@"
        git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
    fi
    [ "$(git -C "$dir" rev-parse HEAD)" = "$commit" ] || die "$name: HEAD is not $commit"
    [ -z "$(git -C "$dir" status --porcelain)" ] || die "$name: working tree modified (rm -rf $dir to refetch)"
}

fetch_ietf_iana() {
    local dir="$CORPUS_DIR/src/ietf-iana" tmp
    if ! docker image inspect "$INTEROP_IMAGE" >/dev/null 2>&1; then
        log "ietf-iana: image $INTEROP_IMAGE missing, building it (../build.sh)"
        locked "$MIBS_DIR/../build.sh"
    fi
    tmp="$dir.tmp"
    rm -rf "$tmp"; mkdir -p "$tmp"
    log "ietf-iana: extracting /var/lib/mibs/{ietf,iana} from $INTEROP_IMAGE"
    docker run --rm --entrypoint tar "$INTEROP_IMAGE" -C /var/lib/mibs -cf - ietf iana | tar -x -C "$tmp"
    (cd "$tmp" && find . -type f -printf '%P\n' | LC_ALL=C sort | xargs sha256sum) > "$tmp.sha256"
    if [ "$update_pins" = 1 ] || [ ! -f "$IETF_IANA_PINS" ]; then
        mkdir -p "$(dirname "$IETF_IANA_PINS")"
        { echo "# sha256 of /var/lib/mibs/{ietf,iana} in $INTEROP_IMAGE (snmp-mibs-downloader 1.6, Ubuntu 24.04)"
          cat "$tmp.sha256"; } > "$IETF_IANA_PINS"
        log "ietf-iana: wrote $IETF_IANA_PINS ($(grep -vc '^#' "$IETF_IANA_PINS") files)"
    elif ! diff -q <(grep -v '^#' "$IETF_IANA_PINS") "$tmp.sha256" >/dev/null; then
        diff <(grep -v '^#' "$IETF_IANA_PINS") "$tmp.sha256" | head -20 >&2 || true
        die "ietf-iana: content differs from $IETF_IANA_PINS (rebuilt image? use --update-pins to accept)"
    fi
    rm -rf "$dir" "$tmp.sha256"
    mv "$tmp" "$dir"
    log "ietf-iana: $(find "$dir" -type f | wc -l) files, verified against pins"
}

# pin_rows FILE: the data rows of a pins/*.tsv file (no comments, no header)
pin_rows() { grep -v '^#' "$1" | tail -n +2; }

# extract_archive ARCHIVE DEST [MEMBER_DIR]: unpack into DEST (replaced atomically);
# with MEMBER_DIR only that top-level directory of the archive, flattened into DEST.
extract_archive() {
    local archive=$1 dest=$2 member=${3:-} tmp="$2.tmp"
    rm -rf "$tmp"; mkdir -p "$tmp"
    case "$archive" in
        *.zip) unzip -q "$archive" ${member:+"$member/*"} -d "$tmp" ;;
        *.tar.gz|*.tgz) tar -xzf "$archive" -C "$tmp" ${member:+"$member"} ;;
        *) die "unknown archive type: $archive" ;;
    esac
    if [ -n "$member" ]; then
        mv "$tmp/$member" "$tmp.m"; rm -rf "$tmp"; mv "$tmp.m" "$tmp"
    fi
    chmod -R u+rwX,go+rX "$tmp"
    rm -rf "$dest"; mv "$tmp" "$dest"
}

# Official Juniper MIB bundles (Junos OS + Junos OS Evolved), public downloads.
fetch_juniper() {
    local base="$CORPUS_DIR/src/juniper-official" dl="$CORPUS_DIR/dl" keep=() src rel dir url sha size fn
    mkdir -p "$base" "$dl"
    while IFS=$'\t' read -r src rel dir url sha size; do
        keep+=("$dir")
        if [ -d "$base/$dir" ] && [ "$(cat "$base/$dir.sha256" 2>/dev/null)" = "$sha" ]; then
            log "$src: $rel already extracted"; continue
        fi
        if [ -z "$NOKIA_DIR" ]; then
            log "NOTICE $src: MIBLAB_NOKIA_DIR is not set: skipping SR OS $rel (optional local source, see pins/nokia.tsv)"
            continue
        fi
        fn="$dl/${url##*filename=}"
        if ! { [ -f "$fn" ] && echo "$sha  $fn" | sha256sum -c --status; }; then
            log "$src: downloading $url"
            curl -fsSL --retry 3 -A "Mozilla/5.0 (actsnmp MIB lab)" -o "$fn.part" "$url"
            mv "$fn.part" "$fn"
        fi
        echo "$sha  $fn" | sha256sum -c --status || die "$src: sha256 of $fn is not $sha (pins/juniper.tsv)"
        extract_archive "$fn" "$base/$dir"
        echo "$sha" > "$base/$dir.sha256"
        log "$src: $rel: $(find "$base/$dir" -type f | wc -l) files, archive verified against pins"
    done < <(pin_rows "$JUNIPER_PINS")
    # releases that are no longer pinned
    for d in "$base"/*/; do
        [ -d "$d" ] || continue
        d=$(basename "$d")
        [[ " ${keep[*]} " == *" $d "* ]] || { log "juniper: removing unpinned $d"; rm -rf "${base:?}/$d" "$base/$d.sha256"; }
    done
}

# Nokia SR OS MIB bundles: optional local source (proprietary, support portal only).
fetch_nokia() {
    local base="$CORPUS_DIR/src/nokia-sros" keep=() src rel role path sha size z
    mkdir -p "$base"
    while IFS=$'\t' read -r src rel role path sha size; do
        keep+=("$rel")
        z="$NOKIA_DIR/$path"
        if [ -d "$base/$rel" ] && [ "$(cat "$base/$rel.sha256" 2>/dev/null)" = "$sha" ]; then
            log "$src: $rel already extracted"; continue
        fi
        if [ -z "$NOKIA_DIR" ]; then
            log "NOTICE $src: MIBLAB_NOKIA_DIR is not set: skipping SR OS $rel (optional local source, see pins/nokia.tsv)"
            continue
        fi
        if [ ! -f "$z" ]; then
            log "NOTICE $src: $z not found: skipping SR OS $rel (optional local source, see pins/nokia.tsv)"
            continue
        fi
        echo "$sha  $z" | sha256sum -c --status || die "$src: sha256 of $z is not $sha (pins/nokia.tsv)"
        extract_archive "$z" "$base/$rel" MIBs
        echo "$sha" > "$base/$rel.sha256"
        log "$src: SR OS $rel ($role): $(find "$base/$rel" -type f | wc -l) files, archive verified against pins"
    done < <(pin_rows "$NOKIA_PINS")
    for d in "$base"/*/; do
        [ -d "$d" ] || continue
        d=$(basename "$d")
        [[ " ${keep[*]} " == *" $d "* ]] || { log "nokia: removing unpinned $d"; rm -rf "${base:?}/$d" "$base/$d.sha256"; }
    done
}

for s in "${sources[@]}"; do
    case "$s" in
        netsnmp) git_sparse netsnmp "$NETSNMP_URL" "$NETSNMP_COMMIT" "${NETSNMP_PATHS[@]}" ;;
        librenms) git_sparse librenms "$LIBRENMS_URL" "$LIBRENMS_COMMIT" "${LIBRENMS_PATHS[@]}" ;;
        cisco) git_sparse cisco "$CISCO_URL" "$CISCO_COMMIT" "${CISCO_PATHS[@]}" ;;
        pysnmp) git_sparse pysnmp "$PYSNMP_URL" "$PYSNMP_COMMIT" "${PYSNMP_PATHS[@]}" ;;
        ietf-iana) fetch_ietf_iana ;;
        juniper) fetch_juniper ;;
        nokia) fetch_nokia ;;
    esac
done

# Machine-readable record of what was fetched (read by index.py / report.py).
{
    printf 'source\turl\tref\tcommit\tpaths\n'
    printf 'netsnmp\t%s\t%s\t%s\t%s\n' "$NETSNMP_URL" "$NETSNMP_REF" "$NETSNMP_COMMIT" "${NETSNMP_PATHS[*]}"
    printf 'ietf-iana\tdocker:%s:/var/lib/mibs\tsnmp-mibs-downloader 1.6\tsha256:%s\tietf/ iana/\n' \
        "$INTEROP_IMAGE" "$(grep -v '^#' "$IETF_IANA_PINS" | sha256sum | cut -c1-16)"
    printf 'librenms\t%s\t%s\t%s\t%s\n' "$LIBRENMS_URL" "$LIBRENMS_REF" "$LIBRENMS_COMMIT" "${LIBRENMS_PATHS[*]}"
    printf 'cisco\t%s\t%s\t%s\t%s\n' "$CISCO_URL" "$CISCO_REF" "$CISCO_COMMIT" "${CISCO_PATHS[*]}"
    printf 'pysnmp\t%s\t%s\t%s\t%s\n' "$PYSNMP_URL" "$PYSNMP_REF" "$PYSNMP_COMMIT" "${PYSNMP_PATHS[*]}"
    # vendor bundles: one row per extracted release (source label as in index.py)
    pin_rows "$JUNIPER_PINS" | while IFS=$'\t' read -r src rel dir url sha size; do
        [ -d "$CORPUS_DIR/src/juniper-official/$dir" ] &&
            printf '%s\t%s\t%s\tsha256:%s\t%s\n' "$src" "$url" "$rel" "$sha" "juniper-official/$dir/"
    done
    pin_rows "$NOKIA_PINS" | while IFS=$'\t' read -r src rel role path sha size; do
        [ -d "$CORPUS_DIR/src/nokia-sros/$rel" ] &&
            printf '%s\t%s\t%s\tsha256:%s\t%s\n' "$src" "local:$path" "$rel" "$sha" "nokia-sros/$rel/ ($role)"
    done
    true
} > "$CORPUS_DIR/sources.tsv"

if [ "$do_index" = 1 ]; then
    log "indexing corpus"
    locked python3 "$MIBS_DIR/index.py" --corpus "$CORPUS_DIR" --out "$MIBS_DIR" "${swap_arg[@]}"
fi
log "done"
