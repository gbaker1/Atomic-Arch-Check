# Atomic-Arch-Check
The script:

Compares installed foreign/AUR packages against the compromised list
Scans /var/log/pacman.log for installs during 2026-06-09 .. 2026-06-13
Checks npm/bun caches for atomic-lockfile, js-digest, lockfile-js
With --remove: runs pacman -Rns on matches
With --replace: searches official repos for alternatives (many AUR-only packages won’t have one)

Usage
# Scan with live list (~1600 packages) — recommended
atomic-arch-check.sh --refresh
# Remove compromised packages (interactive)
sudo atomic-arch-check.sh --refresh --remove
# Remove and try official-repo replacements
sudo atomic-arch-check.sh --refresh --remove --replace
# Non-interactive
sudo atomic-arch-check.sh --refresh --remove --replace --yes
