#!/usr/bin/env python3
"""Request a PDR record and follow GetPDR transfers until the record is complete.

Uses helpers from `run_pldm_tests.py` to build/send MCTP/PLDM frames and parse responses.
"""
import sys
import struct
import time
import os

sys.path.insert(0, os.path.dirname(__file__))
import run_pldm_tests as rt


def le_u32(bs):
    return bs[0] | (bs[1] << 8) | (bs[2] << 16) | (bs[3] << 24)


def follow_getpdr(device, baud, record_handle=5, request_cnt=0x12, verbose=True):
    # initial request: data_transfer_handle = 0
    data_transfer_handle = 0
    assembled = bytearray()
    attempt = 0
    while True:
        attempt += 1
        # build PLDM GetPDR request payload: record_handle(4), data_transfer_handle(4), transfer_op_flag(1), request_cnt(2), record_chg_num(2)
        transfer_op_flag = 0
        record_chg_num = 0
        payload = struct.pack('<I I B H H', record_handle, data_transfer_handle, transfer_op_flag, request_cnt, record_chg_num)
        pldm_msg = rt.build_pldm_msg(0x51, rt.PLDM_PLATFORM, 0, payload)
        frame = rt.build_mctp_pldm_request(pldm_msg, dest=0)
        resp = rt.send_and_capture(device, frame, baud)
        if not resp:
            print('No response for attempt', attempt)
            return 1
        info = rt.parse_frame(resp)
        if not info:
            print('Could not parse response frame')
            return 2

        # reconstruct resp_bytes as in run_pldm_tests
        resp_bytes = bytes([info['instance'] & 0xFF, info['type'] & 0xFF, info['cmd_code'] & 0xFF]) + info['extra']
        if len(resp_bytes) < 15:
            print('Response too short:', resp_bytes.hex())
            return 3
        completion = resp_bytes[3]
        next_record_handle = le_u32(resp_bytes[4:8])
        returned_transfer_handle = le_u32(resp_bytes[8:12])
        transfer_flag = resp_bytes[12]
        resp_cnt = resp_bytes[13] | (resp_bytes[14] << 8)
        data_start = 15
        data_end = data_start + resp_cnt
        record_chunk = resp_bytes[data_start:data_end]
        if verbose:
            print(f'Attempt {attempt}: completion=0x{completion:02x} transfer_flag=0x{transfer_flag:02x} resp_cnt={resp_cnt} returned_xfer=0x{returned_transfer_handle:08x}')
        if completion != 0:
            print('PLDM reported error completion code', completion)
            return 4

        assembled.extend(record_chunk)

        # If the returned transfer handle is zero the transfer is complete
        if returned_transfer_handle == 0:
            crc = None
            if len(resp_bytes) > data_end:
                crc = resp_bytes[data_end]
            if verbose:
                print('Transfer complete. total_bytes=', len(assembled), 'crc=', crc)
            break

        # otherwise continue using returned_transfer_handle
        if returned_transfer_handle == 0:
            print('Server indicated more data but returned zero transfer handle')
            return 5
        data_transfer_handle = returned_transfer_handle
        # small delay
        time.sleep(0.05)

    # basic validation: ensure we received some data
    if len(assembled) == 0:
        print('No record data received')
        return 6
    print('Successfully retrieved record bytes:', len(assembled))
    print('Sample (first 32 bytes):', assembled[:32].hex())
    return 0


if __name__ == '__main__':
    dev = '/dev/ttyUSB0'
    baud = 115200
    if len(sys.argv) > 1:
        dev = sys.argv[1]
    if len(sys.argv) > 2:
        baud = int(sys.argv[2])
    # allow overriding record_handle
    rh = 5
    if len(sys.argv) > 3:
        rh = int(sys.argv[3], 0)
    rc = follow_getpdr(dev, baud, record_handle=rh)
    sys.exit(rc)
