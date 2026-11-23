#!/usr/bin/env bash
# Stand up a local Samba share for smbgui e2e tests (port 1445).
set -euo pipefail

SHARE_DIR="${SMBGUI_SHARE_DIR:-/tmp/smbgui-share}"
SMB_USER="${SMBGUI_TEST_USER:-smbtest}"
SMB_PASS="${SMBGUI_TEST_PASS:-TestPass123!}"
SMB_PORT="${SMBGUI_TEST_PORT:-1445}"
CONF="${SMBGUI_SMB_CONF:-/tmp/smbgui-smb.conf}"
PIDDIR="${SMBGUI_SMB_PIDDIR:-/tmp/smbgui-samba}"
LOGDIR="${SMBGUI_SMB_LOGDIR:-/tmp/smbgui-samba-logs}"

mkdir -p "$PIDDIR/state" "$PIDDIR/cache" "$PIDDIR/ncalrpc" "$LOGDIR"
sudo mkdir -p "$SHARE_DIR/subdir" "${SHARE_DIR}-admin"
sudo chmod -R 777 "$SHARE_DIR" || true
echo "hello from smbgui fixture" | sudo tee "$SHARE_DIR/readme.txt" >/dev/null
echo "nested" | sudo tee "$SHARE_DIR/subdir/note.txt" >/dev/null
echo "admin share root" | sudo tee "${SHARE_DIR}-admin/secret.txt" >/dev/null
sudo chmod -R 777 "${SHARE_DIR}-admin" || true

if ! id "$SMB_USER" >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$SMB_USER" || true
fi
printf '%s\n%s\n' "$SMB_PASS" "$SMB_PASS" | sudo smbpasswd -a -s "$SMB_USER"
sudo smbpasswd -e "$SMB_USER" || true

cat > "$CONF" <<CFGEOF
[global]
   workgroup = WORKGROUP
   netbios name = SMBGUI
   server string = smbgui test
   security = user
   passdb backend = tdbsam
   map to guest = Never
   smb ports = ${SMB_PORT}
   interfaces = 127.0.0.1
   bind interfaces only = yes
   log file = ${LOGDIR}/log.%m
   max log size = 100
   server min protocol = SMB2
   server max protocol = SMB3
   disable spoolss = yes
   load printers = no
   printing = bsd
   printcap name = /dev/null
   pid directory = ${PIDDIR}
   lock directory = ${PIDDIR}
   state directory = ${PIDDIR}/state
   cache directory = ${PIDDIR}/cache
   ncalrpc dir = ${PIDDIR}/ncalrpc
   private dir = /var/lib/samba/private

[testdata]
   path = ${SHARE_DIR}
   browseable = yes
   read only = no
   valid users = ${SMB_USER}
   force user = ${SMB_USER}
   create mask = 0666
   directory mask = 0777

[admin$]
   path = ${SHARE_DIR}-admin
   browseable = yes
   read only = no
   valid users = ${SMB_USER}
   force user = ${SMB_USER}
   create mask = 0666
   directory mask = 0777
CFGEOF

if [[ -f "${PIDDIR}/smbd.pid" ]]; then
  sudo kill "$(cat "${PIDDIR}/smbd.pid")" 2>/dev/null || true
  sleep 0.5
fi
pkill -f "smbd -s ${CONF}" 2>/dev/null || true
sleep 0.3
rm -f "${PIDDIR}/smbd.pid"

sudo /usr/sbin/smbd -s "$CONF" -D
sleep 0.8

if ss -lnt | grep -q ":${SMB_PORT}"; then
  echo "Samba listening on 127.0.0.1:${SMB_PORT}, share=testdata, user=${SMB_USER}"
else
  echo "ERROR: Samba did not bind :${SMB_PORT}" >&2
  sudo tail -n 50 "${LOGDIR}"/* 2>/dev/null || true
  exit 1
fi
