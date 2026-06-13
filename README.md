# Atomic-Arch-Check
The script:  Compares installed foreign/AUR packages against the compromised list Scans /var/log/pacman.log for installs during 2026-06-09 .. 2026-06-13, Checks npm/bun caches for atomic-lockfile, js-digest, lockfile-js, With --remove: runs pacman -Rns on matches, With --replace: searches official repos for alternatives
