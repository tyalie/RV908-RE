#!/usr/bin/env python3
"""
Given a pcap file extracts the video frames from it and stores them 
enumerated in a folder.
"""

from argparse import ArgumentParser, ArgumentTypeError, Namespace
from pathlib import Path
from dataclasses import dataclass
from pcapkit import extract
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(encoding='utf-8', level=logging.INFO)

@dataclass()
class ParsedProtocol:
    frames: list


def get_args() -> Namespace:
    parser = ArgumentParser(description="A small tool to extract images from Linsn RV908 lan protocol")
    
    def check_file(v: str):
        if (p := Path(v)).exists() and p.is_file():
            return p
        raise ArgumentTypeError(f"'{v}' is not a file")

    def check_dir(v: str):
        if (p := Path(v)).exists() and p.is_dir():
            return p
        raise ArgumentTypeError(f"'{v}' is not a directory")

    parser.add_argument("-i", "--input", help="Input pcap file with traffic recording", type=check_file, required=True)
    parser.add_argument("-o", "--output", help="Output folder for frames", type=check_dir, required=True)

    return parser.parse_args()


def parse_pcap(file: Path) -> ParsedProtocol:
    logger.info(f"Start parsing `file`")
    extractor = extract(fin=str(file), nofile=True, engine="dpkt")
    logger.info(f"Finished parsing `file`")

    __import__('ipdb').set_trace()


if __name__ == "__main__":
    args = get_args()
    protocol = parse_pcap(args.input)
    print(f"found {len(protocol.frames)} images")
