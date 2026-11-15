#!/bin/bash
# The last step of an AWS image build, after every download over the Session Manager connection: arrange for the build
# instance's own state (the SSM agent's registration and logs, Packer's temporary login key) to be removed when the instance
# STOPS, which Packer does before it takes the snapshot. Removing them now would cut the very session that carries Packer.
#
# Everything lives in /run (memory): the unit, the script and the marker. Nothing persists into the image, so a box made from
# it never runs this (no marker, so the unit is skipped, and the unit file does not exist), and the image's disk generation
# is untouched. The unit is ordered BEFORE the SSM agent, so at shutdown it is stopped AFTER the agent has stopped.
set -euo pipefail
install -m 0700 -o root -g root /tmp/ozbox-image-wipe.sh /run/ozbox-image-wipe.sh
rm -f /tmp/ozbox-image-wipe.sh
: >/run/ozbox-image-wipe.marker
mkdir -p /run/systemd/system
cat >/run/systemd/system/ozbox-image-wipe.service <<'UNIT'
[Unit]
Description=Oz Box image build: clear the build instance's own state when it stops
ConditionPathExists=/run/ozbox-image-wipe.marker
Before=snap.amazon-ssm-agent.amazon-ssm-agent.service amazon-ssm-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=/bin/sh /run/ozbox-image-wipe.sh
TimeoutStopSec=60
UNIT
systemctl daemon-reload
systemctl start ozbox-image-wipe.service
systemctl is-active --quiet ozbox-image-wipe.service
