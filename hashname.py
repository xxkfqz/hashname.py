#!/usr/bin/env python3
# Copyleft by xxkfqz <xxkfqz@gmail.com> 2021

import os
import sys
import hashlib
import argparse
import re

BUF_SIZE = 8192


def check_args():
    parser = argparse.ArgumentParser(
        description='Rename files to their hash',
        add_help=True
    )

    parser.add_argument(
        '-f',
        '--force',
        action='store_true',
        help='Process the file even if it looks like it has already been processed '
    )
    
    parser.add_argument(
        '-F',
        '--force-rename',
        action='store_true',
        help='Rename file even there is file with the same hash'
    )
    
    parser.add_argument(
        '-a',
        '--algorithm',
        default='sha256',
        dest='algorithm',
        help='Hash algorithm: "md5", "sha256" (default), "sha512"'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action='store_true',
        help='Print more information during processing'
    )

    parser.add_argument(
        'files',
        metavar='FILE',
        nargs='+',
        type=str,
        help='Path to file to rename'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(-1)

    return parser.parse_args()


def get_algorithm(args):
    fa = args.algorithm
    if fa == 'md5':
        a = hashlib.md5
    elif fa == 'sha256':
        a = hashlib.sha256
    elif fa == 'sha512':
        a = hashlib.sha512
    else:
        print(f'Unknown algorithm "{fa}"', file=sys.stderr)
        sys.exit(-1)
    return a


def is_already_hash(file_name: str, digest_size: int):
    file_name = os.path.splitext(file_name)[0]

    return bool(re.match('^[a-f0-9]{64}$', file_name))


def process(args, algo):
    for input_file in args.files:
        hasher = algo()

        try:
            if os.path.isdir(input_file):
                if args.verbose:
                    print(f'"{input_file}" is a directory')
                continue

            path = os.path.split(input_file)
            ext = os.path.splitext(input_file)[-1]
            if not args.force and is_already_hash(path[-1], len(hasher.hexdigest())):
                if args.verbose:
                    print(f'Skipping "{input_file}"')
                continue

            with open(input_file, 'rb') as f:
                while True:
                    chunk = f.read(BUF_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)

            out_file = ''.join(path[:-1]) + '/' + hasher.hexdigest() + ext
            if os.path.isfile(out_file) and not args.force_rename:
                print(f'"{out_file}" already exists, skipping "{input_file}"')
            else:
                os.rename(input_file, out_file)
                print(f'"{input_file}" -> "{out_file}"')
        except OSError:
            sys.stderr.write(f'Cannot access to {input_file}\n')


if __name__ == '__main__':
    arguments = check_args()
    algorithm = get_algorithm(arguments)
    process(arguments, algorithm)
