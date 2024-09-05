#!/usr/bin/env python3
from argparse import ArgumentParser
import asyncio
from scapy.config import conf

from network import NetworkSocket
from simulator import Simulator

def get_args():
    parser = ArgumentParser()
    parser.add_argument("--headless", help="Start without gui", action="store_true")
    parser.add_argument("-i", "--interface", help="TAP interface name to be used", required=True)
    parser.add_argument("-t", "--transparent", help="Transparent mode: No data will be send", action="store_true")
    parser.add_argument("--adapt-memory", help="Turn on memory pattern adaptation aka only unknown changes to memory in comparision to previous will raise error", action="store_true")

    return parser.parse_args()

def main():
    args = get_args()

    socket = NetworkSocket(args.interface, args.transparent)
    conf.debug_dissector = True

    sim = Simulator(socket, with_gui=not args.headless, adapt_memory=args.adapt_memory)
    sim.start_ui()

    asyncio.run(sim.run())

if __name__ == "__main__":
    main()
