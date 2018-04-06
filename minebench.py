#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha256
import random
import time
import codecs
import struct
import os
import sys
import logging
from multiprocessing import Process, cpu_count


class Minebench:
    @staticmethod
    def mine_block(row, bits=0x1D00FFFF, sequential_nonce=False):
        # Merkle root from the block's raw transactions
        txs = row['tx'].split(':')
        merkle_root = Minebench.get_merkle_root(txs)
        return BlockHeader(ver=int(row['ver']),
                           prev_block=row['prev_block'],
                           merkle_root=merkle_root,
                           time=int(row['time']),
                           bits=bits,
                           sequential_nonce=sequential_nonce).mine()

    @staticmethod
    def get_merkle_root(txs):
        txs_hashes = []
        for tx in txs:
            txs_hashes.append(FormatUtils.hex_to_sha256_sha256(tx))

        merkle_hashes = txs_hashes
        while len(merkle_hashes) > 1:
            merkle_hashes_len = len(merkle_hashes)
            new_merkle_hashes = []
            for i in range(0, merkle_hashes_len, 2):
                if merkle_hashes_len > i+1:
                    new_merkle_hashes.append(FormatUtils.hex_to_sha256_sha256(merkle_hashes[i] + merkle_hashes[i+1]))
                    continue
                new_merkle_hashes.append(FormatUtils.hex_to_sha256_sha256(merkle_hashes[i] + merkle_hashes[i]))
            merkle_hashes = new_merkle_hashes

        return merkle_hashes[0]

    @staticmethod
    def get_points(blocks_no, millis):
        return int(blocks_no * 10e6 / total_millis)

    @staticmethod
    def get_dict_from_file_line(line):
        if type(line) == str:
            line = line.strip().split(',')
        return {'ver': line[0],
                'prev_block': line[1],
                'time': line[2],
                'tx': line[3]}

    @staticmethod
    def process_job(filename,
                    start_row=0,
                    rows_no=0,
                    bits=0x1D00FFFF,
                    sequential_nonce=False,
                    process_id=None):
        logging.info(f'process {process_id} started')
        with open(filename, 'r') as file:
            InputUtils.forward_file_lines(file, start_row)
            for i in range(0, rows_no):
                try:
                    row = next(file)
                except StopIteration:
                    break

                if i % 100 == 99:
                    logging.info(
                        f'process {process_id}: {i + 1} mined blocks')

                Minebench.mine_block(Minebench.get_dict_from_file_line(row),
                                     bits,
                                     sequential_nonce)


class InputUtils:
    @staticmethod
    def get_file_lines(filename):
        with open(filename, 'r') as file:
            no_lines = 0
            try:
                while(next(file)):
                    no_lines += 1
            except StopIteration:
                pass
            return no_lines

    @staticmethod
    def forward_file_lines(file_handler, lines_no):
        for i in range(lines_no):
            try:
                next(file_handler)
            except StopIteration:
                return


class FormatUtils:
    @staticmethod
    def swap_hex(string):
        swapped_string = ''
        for i in range(0, len(string), 2):
            swapped_string += string[i + 1] + string[i]
        return swapped_string

    @staticmethod
    def sha256_to_hex_little_endian(string):
        return FormatUtils.swap_hex(string[::-1])

    @staticmethod
    def uint32_to_hex_little_endian(integer):
        return codecs.encode(struct.pack('<I', integer), 'hex').decode('utf-8')

    @staticmethod
    def uint32_to_hex_big_endian(integer):
        return codecs.encode(struct.pack('>I', integer), 'hex').decode('utf-8')

    @staticmethod
    def uint256_to_hex_big_endian(integer):
        string = str(hex(integer))[2:]
        padding = int(64 - len(string)) * '0'
        return padding + string

    @staticmethod
    def hex_to_bin(string):
        return bytes(bytearray.fromhex(string))

    @staticmethod
    def hex_to_int(string):
        return int(string, 16)

    @staticmethod
    def current_timestamp_in_seconds():
        return int(round(time.time()))

    @staticmethod
    def current_timestamp_in_millis():
        return int(round(time.time() * 1000))

    @staticmethod
    def hex_to_sha256_sha256(string):
        header_bin = FormatUtils.hex_to_bin(string)
        first_hash_bin = sha256(header_bin).digest()
        second_hash_bin = sha256(first_hash_bin).digest()  # big-endian

        big_endian_hash = codecs.encode(second_hash_bin, 'hex').decode('utf-8')
        block_header_hash = FormatUtils.sha256_to_hex_little_endian(
            big_endian_hash)
        return block_header_hash


class BlockHeader:
    def __init__(self,
                 ver,
                 prev_block,
                 merkle_root,
                 time,
                 bits,
                 nonce=None,
                 sequential_nonce=False):
        self.ver = int(ver)  # Block version number (4 bytes)
        # Hash of the previous block header (32 bytes)
        self.prev_block = prev_block
        # Hash based on all of the transactions in the block (32 bytes)
        self.merkle_root = merkle_root
        self.time = int(time)  # Timestamp in seconds (4 bytes)
        self.bits = int(bits)  # Current target in compact format (4 bytes)
        self.sequential_nonce = sequential_nonce
        self.nonce = 0  # 32-bit number (starts at 0, 4 bytes)
        self.used_nonces = set()
        if not nonce:
            self._set_new_nonce()
            return
        self.nonce = int(nonce)

    def mine(self):
        network_target = self._get_target()
        logging.debug(f'Target: {network_target}')

        start_time = FormatUtils.current_timestamp_in_millis()
        block_seconds = 0
        attempts = 1

        current_hash = self._get_hash()
        while (current_hash > network_target):
            self._set_new_nonce()
            current_hash = self._get_hash()
            block_seconds = FormatUtils.current_timestamp_in_millis() - start_time
            attempts += 1

        logging.debug(f'Block found: {current_hash}')
        logging.debug(f'Nonce: {self.nonce}')
        logging.debug(f'Attempts: {attempts}')
        logging.debug('Block elapsed seconds: %.2f\n' % (block_seconds / 1000))

        return current_hash

    def _get_target(self):
        bits_big_endian_hex = FormatUtils.uint32_to_hex_big_endian(self.bits)
        exp = FormatUtils.hex_to_int(bits_big_endian_hex[:2])  # 8 bits
        coeff = FormatUtils.hex_to_int(bits_big_endian_hex[2:])  # 24 bits
        target = coeff * 2 ** (8 * (exp - 3))
        return FormatUtils.uint256_to_hex_big_endian(target)

    def _get_hex(self):
        return FormatUtils.uint32_to_hex_little_endian(self.ver) \
            + FormatUtils.sha256_to_hex_little_endian(self.prev_block) \
            + FormatUtils.sha256_to_hex_little_endian(self.merkle_root) \
            + FormatUtils.uint32_to_hex_little_endian(self.time) \
            + FormatUtils.uint32_to_hex_little_endian(self.bits) \
            + FormatUtils.uint32_to_hex_little_endian(self.nonce)

    def _get_hash(self):
        header_hex = self._get_hex()
        block_header_hash = FormatUtils.hex_to_sha256_sha256(header_hex)
        return block_header_hash

    def _set_new_nonce(self):
        if self.sequential_nonce:
            self.nonce += 1
            return

        while(True):
            nonce = random.randint(0, 0x7FFFFFFF)
            if not nonce in self.used_nonces:
                self.used_nonces.add(nonce)
                self.nonce = nonce
                break


if __name__ == "__main__":
    print('\nMinebench v0.1.3 (Python 3.6+)\n')
    random.seed(1984)
    logging.getLogger().setLevel(logging.INFO)
    processes_no = cpu_count()
    process_ids = range(0, processes_no)

    if len(sys.argv) != 2:
        logging.error("You must indicate an input csv file.")
        raise SystemExit
    filename = sys.argv[1]

    no_lines = InputUtils.get_file_lines(filename)
    split_size = int(no_lines / processes_no)

    bits = 0x1F888888
    processes = []
    start_time = FormatUtils.current_timestamp_in_millis()
    for i in process_ids:
        if no_lines - (i + 1) * split_size < 0:
            split_size = no_lines - i * split_size
        process = Process(name=i,
                          target=Minebench.process_job,
                          kwargs={'filename': filename,
                                  'start_row': split_size * i,
                                  'rows_no': split_size,
                                  'bits': bits,
                                  'process_id': i})
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    total_millis = FormatUtils.current_timestamp_in_millis() - start_time
    print('\n- Elapsed time: %.2f seconds' % (total_millis / 1000))
    print('- Points: %d' % Minebench.get_points(no_lines, total_millis))
    print(f'- Bits: {bits}\n')
