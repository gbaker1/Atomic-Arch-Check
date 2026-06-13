#!/usr/bin/env bash
# Atomic Arch AUR supply-chain incident checker/remover
# Campaign: June 2026 — orphaned AUR packages hijacked to run malicious npm/bun
# payloads (atomic-lockfile, js-digest, lockfile-js) delivering infostealer + eBPF rootkit.
#
# Authoritative live list (Arch team HedgeDoc):
#   https://md.archlinux.org/s/SxbqukK6IA
#
# Community references:
#   https://github.com/lenucksi/aur-malware-check
#   https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
#   https://ioctl.fail/preliminary-analysis-of-aur-malware/

set -euo pipefail

resolve_script_dir() {
    local src="${BASH_SOURCE[0]}"
    while [[ -L "$src" ]]; do
        local link
        link="$(readlink "$src")"
        if [[ "$link" == /* ]]; then
            src="$link"
        else
            src="$(cd "$(dirname "$src")" && pwd)/$link"
        fi
    done
    cd "$(dirname "$src")" && pwd
}
SCRIPT_DIR="$(resolve_script_dir)"
BUNDLED_LIST="${SCRIPT_DIR}/packages-bundled.txt"

# Live list sources (tried in order)
LIST_URLS=(
    "https://md.archlinux.org/s/SxbqukK6IA/download"
    "https://md.archlinux.org/s/SxbqukK6IA"
    "https://gr.ht/aur_pkg_list.txt"
    "https://cscs.pastes.sh/raw/aurvulnlist20260611.txt"
)

MALICIOUS_NPM=(atomic-lockfile js-digest lockfile-js)

# Campaign install window (override with ATOMIC_ARCH_DATE_START / ATOMIC_ARCH_DATE_END)
DATE_START="${ATOMIC_ARCH_DATE_START:-2026-06-09}"
DATE_END="${ATOMIC_ARCH_DATE_END:-2026-06-13}"

DO_REFRESH=0
DO_REMOVE=0
DO_REPLACE=0
DO_YES=0
DO_IOC=1
DO_LOG=1
PACKAGE_LIST=""
QUIET=0

usage() {
    cat <<'EOF'
Usage: atomic-arch-check.sh [OPTIONS]

Detect (and optionally remove) AUR packages compromised in the June 2026
"Atomic Arch" supply-chain campaign.

Options:
  --refresh              Fetch the latest package list from Arch HedgeDoc (recommended)
  --package-list=PATH    Use a local package list (one name per line)
  --remove               Remove detected compromised packages (requires confirmation)
  --replace              After removal, suggest/install official-repo alternatives
  --yes                  Skip interactive confirmation for --remove / --replace
  --no-ioc               Skip npm/bun cache and persistence IOC checks
  --no-log               Skip pacman.log historical scan
  --quiet                Less output (still prints findings)
  -h, --help             Show this help

Environment:
  ATOMIC_ARCH_DATE_START   First day of campaign window (default: 2026-06-09)
  ATOMIC_ARCH_DATE_END     Last day of campaign window (default: 2026-06-13)

Examples:
  atomic-arch-check.sh --refresh
  atomic-arch-check.sh --refresh --remove
  atomic-arch-check.sh --package-list=./my-list.txt --remove --replace --yes

If anything was installed/upgraded during the campaign window, treat the host as
potentially fully compromised (credential rotation + clean reinstall advised).
EOF
}

log() { [[ "$QUIET" -eq 1 ]] || echo "$@"; }
warn() { echo "WARNING: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

require_root_for_remove() {
    if [[ "$DO_REMOVE" -eq 1 && "$(id -u)" -ne 0 ]]; then
        die "--remove requires root (run with sudo)"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --refresh) DO_REFRESH=1 ;;
            --remove) DO_REMOVE=1 ;;
            --replace) DO_REPLACE=1 ;;
            --yes) DO_YES=1 ;;
            --no-ioc) DO_IOC=0 ;;
            --no-log) DO_LOG=0 ;;
            --quiet) QUIET=1 ;;
            --package-list=*) PACKAGE_LIST="${1#*=}" ;;
            --package-list)
                shift
                PACKAGE_LIST="${1:-}"
                ;;
            -h|--help) usage; exit 0 ;;
            *) die "Unknown option: $1 (try --help)" ;;
        esac
        shift
    done
}

parse_package_names() {
    # Accept plain text, markdown, or HTML-ish HedgeDoc output.
    sed 's/<[^>]*>//g' \
        | grep -E '^[a-z0-9][a-z0-9_.+-]*[a-z0-9]$' \
        | sort -u
}

load_package_list() {
    local tmp raw url count
    tmp="$(mktemp)"

    if [[ -n "$PACKAGE_LIST" ]]; then
        [[ -r "$PACKAGE_LIST" ]] || die "Cannot read package list: $PACKAGE_LIST"
        cp "$PACKAGE_LIST" "$tmp"
        log "Using package list: $PACKAGE_LIST"
    elif [[ "$DO_REFRESH" -eq 1 ]]; then
        for url in "${LIST_URLS[@]}"; do
            log "Fetching compromised package list from $url ..."
            if raw="$(curl -fsSL --max-time 20 "$url" 2>/dev/null)"; then
                printf '%s\n' "$raw" | parse_package_names > "$tmp"
                count="$(wc -l < "$tmp" | tr -d ' ')"
                if [[ "$count" -gt 100 ]]; then
                    log "Loaded $count packages from live source."
                    cp "$tmp" "$SCRIPT_DIR/packages-last-refresh.txt"
                    cat "$tmp"
                    rm -f "$tmp"
                    return 0
                fi
                warn "Parsed only $count names from $url; trying next source."
            else
                warn "Failed to fetch $url"
            fi
        done
        rm -f "$tmp"
        die "Could not fetch a live list. Use bundled list with no --refresh, or pass --package-list=PATH."
    elif [[ -r "$SCRIPT_DIR/packages-last-refresh.txt" ]]; then
        log "Using cached refresh: $SCRIPT_DIR/packages-last-refresh.txt"
        cp "$SCRIPT_DIR/packages-last-refresh.txt" "$tmp"
    elif [[ -r "$BUNDLED_LIST" ]]; then
        warn "Using bundled wave-1 list ($(wc -l < "$BUNDLED_LIST" | tr -d ' ') packages)."
        warn "Run with --refresh for the full ~1600-package Arch HedgeDoc list."
        cp "$BUNDLED_LIST" "$tmp"
    else
        rm -f "$tmp"
        die "No package list found. Place packages-bundled.txt next to this script or use --refresh."
    fi

    cat "$tmp"
    rm -f "$tmp"
}

find_installed_compromised() {
    local list_file="$1"
    local tmp_installed tmp_list
    tmp_installed="$(mktemp)"
    tmp_list="$(mktemp)"

    sort -u "$list_file" > "$tmp_list"

    if ! pacman -Qmq 2>/dev/null | sort > "$tmp_installed"; then
        rm -f "$tmp_installed" "$tmp_list"
        die "Failed to query foreign packages (is pacman DB locked?)"
    fi

    comm -12 "$tmp_installed" "$tmp_list"
    rm -f "$tmp_installed" "$tmp_list"
}

find_historical_compromised() {
    local list_file="$1"
    local logfile="/var/log/pacman.log"
    local pkg

    [[ "$DO_LOG" -eq 1 ]] || return 0
    [[ -r "$logfile" ]] || { warn "Cannot read $logfile; skipping historical scan."; return 0; }

    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] || continue
        # Exact match avoids false positives (e.g. yy vs yyjson).
        if grep -F "installed ${pkg} (" "$logfile" >/dev/null 2>&1; then
            while IFS= read -r line; do
                if [[ "$line" > "[${DATE_START}" && "$line" < "[${DATE_END}" ]]; then
                    echo "$pkg|$line"
                fi
            done < <(grep -F "installed ${pkg} (" "$logfile")
        fi
    done < "$list_file"
}

check_malicious_npm_cache() {
    [[ "$DO_IOC" -eq 1 ]] || return 1

    local pkg hit=0
    for pkg in "${MALICIOUS_NPM[@]}"; do
        if [[ -d "$HOME/.npm/_cacache" ]]; then
            if find "$HOME/.npm/_cacache" -type d -name "$pkg" -print -quit 2>/dev/null | grep -q .; then
                warn "npm cacache contains directory for malicious package: $pkg"
                hit=1
            fi
        fi
        if [[ -d "$HOME/.bun/install/cache" ]]; then
            if find "$HOME/.bun/install/cache" -type d -name "$pkg" -print -quit 2>/dev/null | grep -q .; then
                warn "bun cache contains directory for malicious package: $pkg"
                hit=1
            fi
        fi
    done
    [[ "$hit" -eq 1 ]]
}

check_persistence_iocs() {
    [[ "$DO_IOC" -eq 1 ]] || return 1
    local hit=0 unit

    while IFS= read -r unit; do
        case "$unit" in
            *atomic-lockfile*|*js-digest*|*lockfile-js*)
                warn "Suspicious systemd unit: $unit"
                hit=1
                ;;
        esac
    done < <(systemctl list-unit-files --no-pager --no-legend 2>/dev/null | awk '{print $1}')

    if [[ -f /sys/fs/bpf/scales ]]; then
        warn "Found /sys/fs/bpf/scales (reported Atomic Arch eBPF artifact)."
        hit=1
    fi

    [[ "$hit" -eq 1 ]]
}

suggest_replacement() {
    local pkg="$1"
    local candidate

    # Prefer exact name matches in official repos (not AUR).
    candidate="$(pacman -Ss "^${pkg}$" 2>/dev/null | awk '
        /^[a-z]+\// { repo=$1; sub(/\/$/,"",repo); next }
        /^[[:space:]]/ && repo !~ /^(aur|cachyos|cachyos-v3|cachyos-v4)$/ { print repo "/" $1; exit }
    ' || true)"

    if [[ -n "$candidate" ]]; then
        echo "$candidate"
        return 0
    fi

    # Strip common AUR suffixes and retry.
    local base="${pkg%-bin}"
    base="${base%-git}"
    base="${base%-appimage}"
    if [[ "$base" != "$pkg" ]]; then
        candidate="$(pacman -Ss "^${base}$" 2>/dev/null | awk '
            /^[a-z]+\// { repo=$1; sub(/\/$/,"",repo); next }
            /^[[:space:]]/ && repo !~ /^(aur|cachyos|cachyos-v3|cachyos-v4)$/ { print repo "/" $1; exit }
        ' || true)"
        [[ -n "$candidate" ]] && echo "$candidate"
    fi
}

remove_packages() {
    local -a pkgs=("$@")
    [[ ${#pkgs[@]} -gt 0 ]] || return 0

    if [[ "$DO_YES" -ne 1 ]]; then
        echo
        echo "The following packages will be REMOVED with pacman -Rns:"
        printf '  - %s\n' "${pkgs[@]}"
        read -r -p "Proceed? [y/N] " ans
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || { echo "Aborted."; return 1; }
    fi

    pacman -Rns --noconfirm "${pkgs[@]}"
}

replace_packages() {
    local -a pkgs=("$@")
    local pkg repo_pkg replacements=()

    for pkg in "${pkgs[@]}"; do
        repo_pkg="$(suggest_replacement "$pkg" || true)"
        if [[ -n "$repo_pkg" ]]; then
            log "  $pkg -> possible official replacement: $repo_pkg"
            replacements+=("$repo_pkg")
        else
            log "  $pkg -> no official-repo replacement found (reinstall manually from trusted source later)"
        fi
    done

    [[ ${#replacements[@]} -gt 0 ]] || return 0

    if [[ "$DO_YES" -ne 1 ]]; then
        echo
        read -r -p "Install suggested official replacements now? [y/N] " ans
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || return 0
    fi

    pacman -S --needed --noconfirm "${replacements[@]}"
}

main() {
    parse_args "$@"
    require_root_for_remove

    local list_file tmp_installed tmp_historical
    list_file="$(mktemp)"
    tmp_installed="$(mktemp)"
    tmp_historical="$(mktemp)"
    trap 'rm -f "$list_file" "$tmp_installed" "$tmp_historical"' EXIT

    load_package_list > "$list_file"
    local total
    total="$(wc -l < "$list_file" | tr -d ' ')"
    [[ "$total" -gt 0 ]] || die "Package list is empty."

    log "Atomic Arch checker"
    log "Known compromised AUR packages in list: $total"
    log "Campaign window for log scan: ${DATE_START} .. ${DATE_END}"
    log

    mapfile -t installed < <(find_installed_compromised "$list_file" || true)
    local -a historical=()

    if [[ ${#installed[@]} -eq 0 ]]; then
        log "Clean: none of the known compromised packages are currently installed (foreign/AUR set)."
    else
        warn "${#installed[@]} compromised package(s) currently installed:"
        printf '  - %s\n' "${installed[@]}"
    fi

    if [[ "$DO_LOG" -eq 1 ]]; then
        mapfile -t historical < <(find_historical_compromised "$list_file" || true)
        if [[ ${#historical[@]} -gt 0 ]]; then
            echo
            warn "Historical pacman.log matches inside campaign window:"
            local entry pkg line
            for entry in "${historical[@]}"; do
                pkg="${entry%%|*}"
                line="${entry#*|}"
                echo "  - $pkg :: $line"
            done
            echo
            warn "If these packages were installed/upgraded during the window, assume host compromise."
        elif [[ "$QUIET" -eq 0 ]]; then
            log "No pacman.log installs of listed packages during ${DATE_START}..${DATE_END}."
        fi
    fi

    local ioc_hits=0
    if check_malicious_npm_cache; then ioc_hits=1; fi
    if check_persistence_iocs; then ioc_hits=1; fi

    if [[ "$ioc_hits" -eq 1 ]]; then
        echo
        warn "Additional IOC indicators detected — review npm/bun caches and consider full reinstall."
    fi

    if [[ ${#installed[@]} -gt 0 && "$DO_REMOVE" -eq 1 ]]; then
        echo
        remove_packages "${installed[@]}"
        if [[ "$DO_REPLACE" -eq 1 ]]; then
            echo
            log "Searching for official-repo replacements..."
            replace_packages "${installed[@]}"
        fi
    elif [[ ${#installed[@]} -gt 0 ]]; then
        echo
        log "To remove detected packages: sudo $0 --refresh --remove"
        log "To remove and attempt official replacements: sudo $0 --refresh --remove --replace"
    fi

    if [[ ${#installed[@]} -gt 0 || ${#historical[@]} -gt 0 ]]; then
        echo
        cat <<'EOF'
Next steps if you may have been affected:
  1. Rotate ALL credentials (SSH keys, API tokens, browser passwords, GitHub/GitLab, npm).
  2. Do not rely on removal alone — malware included infostealer + eBPF rootkit components.
  3. Prefer a clean OS reinstall from trusted media if packages were installed Jun 9–12 2026.
  4. Refresh the list before acting: atomic-arch-check.sh --refresh
  5. Official list: https://md.archlinux.org/s/SxbqukK6IA
EOF
        exit 1
    fi

    if [[ "$ioc_hits" -eq 1 ]]; then
        exit 2
    fi

    exit 0
}

main "$@"
