#!/usr/bin/env python
import struct
import sys
import re
import os
from os.path import isfile
import traceback
from collections import defaultdict

__author__ = 'Yanick Fratantonio / @reyammer / Shellphish'


# This is the list of the known keys. If you want to attempt to bruteforce
# them, just replace the numbers with 'None'! See commented line after this
# list.
known_keys = [
    20543,
    44829,
    21138,
    23618,
    15062,
    59478,
    13198,
    54610,
    4633,
    46710,
    41810,
    38097,
    56123,
    58392,
    52387,
    12251,
    26106,
    43868,
    15618,
    57633,
    1053,
    53731,
    53447,
    30269,
    24329,
    17183,
    6131,
    19564
]

#known_keys = [20543] + [None] * 26 + [19564]


def main():
    # the received.bin file contains just that
    received_bytes_fp = sys.argv[1]
    try:
        # useful for debugging
        start_key = int(sys.argv[2])
    except IndexError:
        start_key = 0

    content = open(received_bytes_fp, 'rb').read()

    first_session_payload, second_session_payload = split_pcap_into_sessions(content)

    first_session_chunks = split_payload_into_chunks(first_session_payload, 68, '\x07\x32\x00\x01')
    second_session_chunks = split_payload_into_chunks(second_session_payload, 212, '\x07\x32\x00\x1c')

    print 'Listing files'
    for fc in first_session_chunks:
        elem = str(struct.unpack('>I', fc[0xc:0x10])[0]) +  ' -- ' + decrypt_chunk(fc[0x10:-2], 59897).rstrip('\x00')
        print elem
    print 'Done\n'

    # get all encrypted chunks of the PNG
    png_enc_chunks = []
    for chunk in second_session_chunks:
        png_enc_chunks.append(chunk[0xc:])

    keys = known_keys
    assert len(keys) == len(png_enc_chunks)

    # bruteforce the key for each chunk, or use a known one
    png_dec_payload = ''
    for idx in range(len(png_enc_chunks)):
        png_enc_chunk = png_enc_chunks[idx]
        key = keys[idx]

        if key is None:
            # the key is not known, let's bruteforce it
            print 'Key for chunk #%d is not known, bruteforcing..' % idx
            key = find_key_for_png_chunk(png_enc_chunk, png_dec_payload, start_key)
            print 'Best key for chunk #%d is %d' % (idx, key)

        print 'Using key %d for chunk #%d' % (key, idx)
        png_dec_chunk = decrypt_chunk(png_enc_chunk, key)
        png_dec_payload += png_dec_chunk

    # remove trailing \x00
    png_dec_payload = png_dec_payload.rstrip('\x00')

    with open('flag.png', 'wb') as f:
        f.write(png_dec_payload)

    print 'Done.'


def split_pcap_into_sessions(c):
    ss = c.split('END')
    first = ss[0]
    second = ss[1]
    return first, second


def split_payload_into_chunks(session, size, pattern4to7=None):
    chunks = []
    for idx in range(0, len(session), size):
        chunk = session[idx:idx+size]
        chunks.append(chunk)
    assert len(chunks) * size == len(session)
    if pattern4to7:
        for c in chunks:
            assert c[4:8] == pattern4to7
    return chunks


def find_key_for_png_chunk(png_enc_chunk, png_dec_payload_prefix, start_key=0):
    candidate_keys = defaultdict(list) # score ~> [key]
    for key in range(start_key, 65535):
        if key % 30000 == 0:
            print 'Trying with key: %d' % (key)
        png_dec_chunk = decrypt_chunk(png_enc_chunk, key)
        png_dec_payload = png_dec_payload_prefix + png_dec_chunk

        score = eval_payload(png_dec_payload)
        if score >= 0:
            candidate_keys[score].append(key)

    if len(candidate_keys) == 0:
        raise Exception('fuck. key not found')

    # select the best one
    min_score = min(candidate_keys.keys())
    keys = candidate_keys[min_score]

    if len(keys) > 1:
        raise Exception('fuck. two keys have the same score')

    return keys[0]


def eval_payload(png_dec_payload):
    # skip the non-IDAT part of the PNG
    idat_payload = png_dec_payload[59:]

    try:
        rgba = uncompress_zlib(idat_payload)
    except Exception as e:
        # if gzip fails, it can't be right..
        return -1

    # compute a score for this payload
    score = compute_score(rgba)

    return score


def uncompress_zlib(zlib_payload):
    # FIXME: this is not thread safe!
    zlib_payload_fp = '/tmp/zlibpayload.bin'
    uncompressed_fp = '/tmp/uncompressed.bin'
    err_fp = '/tmp/error.txt'

    if isfile(zlib_payload_fp):
        os.unlink(zlib_payload_fp)
    if isfile(uncompressed_fp):
        os.unlink(uncompressed_fp)
    if isfile(err_fp):
        os.unlink(err_fp)

    # trick found here: http://unix.stackexchange.com/a/49066/13985
    f = open(zlib_payload_fp, 'wb')
    f.write('\x1f\x8b\x08\x00\x00\x00\x00\x00' + zlib_payload)
    f.close()

    cmd = './uncompress.sh %s %s %s' % (zlib_payload_fp, uncompressed_fp, err_fp)
    os.system(cmd)

    if isfile(err_fp):
        f = open(err_fp)
        c = f.read()
        f.close()
        if c.find('data--format') >= 0:
            raise Exception('data format exception')
        if c.find('data--crc') >= 0:
            raise Exception('data--crc exception')
        if c.find('data--length') >= 0:
            raise Exception('data--length exception')

    if not isfile(uncompressed_fp):
        raise Exception('uncompressed file not existing')

    f = open(uncompressed_fp, 'rb')
    uncompressed = f.read()
    f.close()

    if len(uncompressed) < 3:
        raise Exception('uncompressed file super small')

    return uncompressed


def compute_score(payload):
    payload = payload[10:]
    processed_payload = ''

    for c in payload:
        if c == '\x00':
            processed_payload += '\x00'
        else:
            processed_payload += '\xff'

    # the score is the number of four consecutive non-zero bytes. The idea
    # behind this is that there should be few of them like this, as the alpha
    # value is zero.
    starters = [m.start() for m in re.finditer('\xff\xff\xff\xff', processed_payload)]
    score = len(starters)

    starters = [m.start() for m in re.finditer('\xff\xff\xff\x00', processed_payload)]

    if len(starters) < 3:
        return -1

    # count how many of the RGBA bytes are 4bytes-aligned
    success = 0
    failure = 0
    for idx in range(len(starters)-1):
        if (starters[idx+1] - starters[idx]) % 4 == 0:
            success += 1
        else:
            failure += 1

    success_ratio = float(success) / (len(starters)-1)

    if success_ratio > 0.8:
        return score
    else:
        return -1


def decrypt_chunk(enc_chunk, key):
    dec = xor(enc_chunk, struct.pack('>H', key))
    return dec


def xor(a, b):
    c = ''
    for idx in range(len(a)):
        c += chr(ord(a[idx]) ^ ord(b[idx%2]))
    return c


if __name__ == '__main__':
    main()
