#!/usr/bin/env bash
# Setup / shutdown a tap device on linux for the rv908 sim.
# use `start` / `stop` as first argument.
#
# Likely must be called by root
user="$USER"
if [[ -n "$SUDO_USER" ]]; then
    user="$SUDO_USER"
fi

link_name="rv908simtun0"

if [[ "$1" == "up" ]]; then
  echo "Starting $link_name"

  # using tap here as we also wanna emulate the ethernet headers
  ip tuntap add name "$link_name" mode tap user $user
  ip link set "$link_name" up
elif [[ "$1" == "down" ]]; then
  echo "Stopping $link_name"

  ip link set "$link_name" down
  ip tuntap del name "$link_name" mode tap
else
  echo "Error. Unknown command '$1' (must be up or down)"
fi
