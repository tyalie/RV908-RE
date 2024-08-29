#!/usr/bin/env python3
from argparse import ArgumentParser
import asyncio

from network import NetworkSocket
from sim import Simulator

def get_args():
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", help="TAP interface name to be used", required=True)
    parser.add_argument("-l", "--lua-param", default=None, help="Lua path for tshark (argument -X)")

    return parser.parse_args()

def main():
    args = get_args()
    print(args)

    socket = NetworkSocket(args.interface)

    sim = Simulator(socket)
    sim.start_ui()

    asyncio.run(sim.run())

if __name__ == "__main__":
    main()
