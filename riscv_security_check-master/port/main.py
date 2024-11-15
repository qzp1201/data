#!/usr/bin/env python3
import os
import argparse

import chk_dir
import chk_file
import chk_fortify
import chk_proc
import filecheck
import kernelcheck
import libcheck


if __name__ == "__main__":

    '''
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('integers', metavar='N', type=int, nargs='+',
                    help='an integer for the accumulator')
    parser.add_argument('--sum', dest='accumulate', action='store_const',
                    const=sum, default=max,
                    help='sum the integers (default: find the max)')

    args = parser.parse_args()
    print(args.accumulate(args.integers))
    kernelcheck()
    '''

    kernelcheck.chk_kernel()
    chk_proc.chk_proc_all()
    chk_file.chk_file('/usr/bin/python3')
    # libcheck.libcheck(os.getpid())
    # chk_fortify.chk_fortify_file('/usr/bin/python3')
    # chk_dir.chk_dir('/usr/bin')
