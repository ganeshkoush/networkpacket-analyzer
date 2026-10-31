#!/bin/sh
# Gives members of the macOS "admin" group read/write access to /dev/bpf* so PacketMind can capture
# packets without running the backend as root. Uses only built-in tools (no Wireshark).
#
#   sudo scripts/macos-bpf-access.sh install     one-time; also re-applied at every boot (LaunchDaemon)
#   sudo scripts/macos-bpf-access.sh now         temporary; lasts until reboot
#   sudo scripts/macos-bpf-access.sh uninstall   remove the LaunchDaemon and restore root-only access
#   scripts/macos-bpf-access.sh status
#
# Security: any admin user on this Mac can then sniff traffic on its interfaces. Uninstall when not needed.
set -eu
LABEL=com.packetmind.bpf-access
PLIST=/Library/LaunchDaemons/$LABEL.plist
GRANT='/usr/bin/chgrp admin /dev/bpf* && /bin/chmod g+rw /dev/bpf*'
REVOKE='/usr/bin/chgrp wheel /dev/bpf* && /bin/chmod g-rw /dev/bpf*'

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0 $1" >&2; exit 1; }; }

case "${1:-}" in
  now) need_root now; sh -c "$GRANT"; echo "Granted until reboot." ;;
  install)
    need_root install
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>$GRANT</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF
    chown root:wheel "$PLIST"; chmod 644 "$PLIST"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
    sh -c "$GRANT"   # apply immediately as well
    echo "Installed. /dev/bpf* is now readable/writable by the admin group, and this persists across reboots." ;;
  uninstall)
    need_root uninstall
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"; sh -c "$REVOKE"; echo "Removed; /dev/bpf* is root-only again." ;;
  status)
    ls -l /dev/bpf0; id -Gn | tr ' ' '\n' | grep -qx admin && echo "You are in the admin group." || echo "You are NOT in the admin group."
    [ -f "$PLIST" ] && echo "LaunchDaemon installed." || echo "LaunchDaemon not installed." ;;
  *) echo "Usage: sudo $0 {install|now|uninstall} | $0 status" >&2; exit 2 ;;
esac
