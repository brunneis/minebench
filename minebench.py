#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha256
import random
import time
import codecs
import struct
import os
import csv
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count


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
        self.used_nonces = set()
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

        while(True):
            nonce = random.randint(0, 0x7FFFFFFF)
            if not nonce in self.used_nonces:
                self.used_nonces.add(nonce)
                self.nonce = nonce
                break


def mine_block(row, bits=0x1D00FFFF, sequential_nonce=False):
    # Merkle root hash generation from raw transactions
    txs_hex = ''.join(row['tx'].split(':'))
    mrkl_root = Utils.hex_to_sha256_sha256(txs_hex)
    return BlockHeader(ver=int(row['ver']),
                     prev_block=row['prev_block'],
                     mrkl_root=mrkl_root,
                     time=int(row['time']),
                     bits=bits,
                     sequential_nonce=sequential_nonce).mine()

def get_points(blocks_no, millis):
    return int(len(futures)*10e6/total_millis)


if __name__ == "__main__":
    from tqdm import tqdm
    logging.getLogger().setLevel(logging.WARN)

    THREADS_NO = cpu_count()
    logging.info(f'THREADS_NO={THREADS_NO}')

    random.seed(1984)

    if len(sys.argv) != 2:
        logging.error("You must indicate an input csv file.")
        raise SystemExit
    filename = sys.argv[1]

    print('\nMinebench v0.1.1 (Python 3.6)\n')

    with open(filename) as csvfile:
        with ThreadPoolExecutor(max_workers=THREADS_NO) as executor:
            csv.field_size_limit(sys.maxsize)
            reader = csv.DictReader(csvfile)

            futures = []
            start_time = Utils.current_timestamp_in_millis()
            for row in reader:
                futures.append(executor.submit(mine_block,
                                               row,
                                               bits=0x1F888888)) # Higher target than maximum
                     
            for future in tqdm(futures, unit=' blocks'):
                future.result()

            total_millis = Utils.current_timestamp_in_millis() - start_time
            print('\n - Elapsed time: %.2f seconds' % (total_millis / 1000))
            print(' - Points: %d' % get_points(len(futures), total_millis))