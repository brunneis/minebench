#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha256
import random
import time
import codecs
import struct
import os
import csv
from sys import argv
import logging
from concurrent.futures import ThreadPoolExecutor
import pyprind
# from tqdm import tqdm


THREADS_NO = 1

class Utils:

    def swap_hex(string):
        swapped_string = ''
        for i in range(0, len(string), 2):
            swapped_string += string[i+1] + string[i]
        return swapped_string

    def sha256_to_hex_little_endian(string):
        return Utils.swap_hex(string[::-1])

    def uint32_to_hex_little_endian(integer):
        return codecs.encode(struct.pack('<I', integer), 'hex').decode('utf-8')

    def uint32_to_hex_big_endian(integer):
        return codecs.encode(struct.pack('>I', integer), 'hex').decode('utf-8')

    def uint256_to_hex_big_endian(integer):
        string = str(hex(integer))[2:]
        padding = int(64 - len(string)) * '0'
        return padding + string

    def hex_to_bin(string):
        return bytes(bytearray.fromhex(string))

    def hex_to_int(string):
        return int(string, 16)

    def current_timestamp_in_seconds():
        return int(round(time.time()))

    def current_timestamp_in_millis():
        return int(round(time.time()*1000))

    def hex_to_sha256_sha256(string):
        header_bin = Utils.hex_to_bin(string)
        first_hash_bin = sha256(header_bin).digest()
        second_hash_bin = sha256(first_hash_bin).digest() # big-endian

        big_endian_hash = codecs.encode(second_hash_bin, 'hex').decode('utf-8')
        block_header_hash = Utils.sha256_to_hex_little_endian(big_endian_hash)
        return block_header_hash


class BlockHeader:
    def __init__(self,
                 ver,
                 prev_block,
                 mrkl_root,
                 time,
                 bits,
                 nonce=None,
                 sequential_nonce=False):
        self.ver = int(ver) # Block version number (4 bytes)
        self.prev_block = prev_block # Hash of the previous block header (32 bytes)
        self.mrkl_root = mrkl_root # Hash based on all of the transactions in the block (32 bytes)
        self.time = int(time) # Timestamp in seconds (4 bytes)
        self.bits = int(bits) # Current target in compact format (4 bytes)
        self.sequential_nonce = sequential_nonce
        self.nonce = 0 # 32-bit number (starts at 0, 4 bytes)
        if not nonce:
            self._new_nonce()
            return
        self.nonce = int(nonce)

    def mine(self):
        network_target = self.get_target()
        logging.info(f'Target: {network_target}')

        start_time = Utils.current_timestamp_in_millis()
        block_seconds = 0
        attempts = 1

        current_hash = self.get_hash()
        while (current_hash > network_target):
            self._new_nonce()
            current_hash = self.get_hash()
            block_seconds = Utils.current_timestamp_in_millis() - start_time
            attempts += 1

        logging.info(f'Block found: {current_hash}')
        logging.info(f'Nonce: {self.nonce}')
        logging.info(f'Attempts: {attempts}')
        logging.info('Block elapsed seconds: %.2f\n' % (block_seconds / 1000))

        return current_hash

    def get_target(self):
        bits_big_endian_hex = Utils.uint32_to_hex_big_endian(self.bits)
        exp = Utils.hex_to_int(bits_big_endian_hex[:2]) # 8 bits
        coeff = Utils.hex_to_int(bits_big_endian_hex[2:]) # 24 bits
        target = coeff * 2 ** (8 * (exp - 3))
        return Utils.uint256_to_hex_big_endian(target)

    def get_hex(self):
        return Utils.uint32_to_hex_little_endian(self.ver) \
            + Utils.sha256_to_hex_little_endian(self.prev_block) \
            + Utils.sha256_to_hex_little_endian(self.mrkl_root) \
            + Utils.uint32_to_hex_little_endian(self.time) \
            + Utils.uint32_to_hex_little_endian(self.bits) \
            + Utils.uint32_to_hex_little_endian(self.nonce)

    def get_hash(self):
        header_hex = self.get_hex()
        block_header_hash = Utils.hex_to_sha256_sha256(header_hex)
        return block_header_hash

    def _new_nonce(self):
        if self.sequential_nonce:
            self.nonce += 1
            return
        self.nonce = random.randint(0, 0x7FFFFFFF)


def thread_work(row):
    txs_hex = ''.join(row['tx'].split(':'))
    mrkl_root = Utils.hex_to_sha256_sha256(txs_hex)
    BlockHeader(ver=int(row['ver']),
                     prev_block=row['prev_block'],
                     mrkl_root=mrkl_root,
                     time=int(row['time']),
                     bits=522000000, # 2 zeros (difficulty)
                     sequential_nonce=True).mine()

if __name__ == "__main__":
    random.seed("minebench")
    logging.getLogger().setLevel(logging.WARN)

    if len(argv) != 2:
        logging.error("You must indicate an input csv file.")
        raise SystemExit
    filename = argv[1]

    with open(filename) as csvfile:
        with ThreadPoolExecutor(max_workers=THREADS_NO) as executor:
            reader = csv.DictReader(csvfile)

            start_time = Utils.current_timestamp_in_millis()

            futures = []
            for row in reader:
                futures.append(executor.submit(thread_work, row))

            bar = pyprind.ProgBar(len(futures), bar_char='█', title='Minebench v0.1.0')
            # for future in tqdm(futures):
            for future in futures:
                future.result()
                bar.update()
            print(bar)

            total_seconds = Utils.current_timestamp_in_millis() - start_time
            logging.info('Total elapsed seconds: %.2f\n' % (total_seconds / 1000))