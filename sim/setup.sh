#!/usr/bin/env bash
# Setup / shutdown a tap device on linux for the rv908 sim.
# use `start` / `stop` as first argument.
#
# Likely must be called by root
user="$USER"
if [[ -n "$SUDO_USER" ]]; then
    user="$SUDO_USER"
fi

br_name="br-led"
link_name="rv908simtun0"

if [[ "$1" == "up" ]]; then
  echo "Creating bridge $br_name"
  ip link add name "$br_name" type bridge
  ip link set dev "$br_name" up

  echo "Starting tap $link_name"

  # using tap here as we also wanna emulate the ethernet headers
  ip tuntap add name "$link_name" mode tap user $user
  ip link set dev "$link_name" master "$br_name"
  ip link set dev "$link_name" qlen 10000
  ip link set "$link_name" up

elif [[ "$1" == "down" ]]; then
  echo "Stopping $link_name"

  ip link set "$link_name" down
  ip tuntap del name "$link_name" mode tap

  echo "Removing bridge $br_name"
  ip link set "$br_name" down
  ip link del name "$br_name"
elif [[ "$1" == "add-if" ]]; then
  if_name="$2"
  echo "Adding '$if_name' to '$br_name'"
  ip link set dev "$if_name" master "$br_name"
else
  echo "Error. Unknown command '$1' (must be up or down)"
fi
