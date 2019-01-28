#!/usr/bin/python
#
# Basic fuzzing handler
#
# @author Chris Bisnett

import sys

import framework

BASEDIR = "/home/cr0c0/Desktop/myfuzz/"

CONFIG = {
    # Location of outcome files
    "outcome_dir" : BASEDIR + "vlc_outcomes",

    # Path to the fuzzer
    "fuzzer" : BASEDIR + "./dumbfuzz.py",

    # Arguments for fuzzer
    "fuzzer_args" : '%(seed)s "%(input)s" %(output)s',

    # Path to target
    "target_bin" : BASEDIR + "./vlc-static",

    # Arguments for target
    "target_args" : "--play-and-exit --quiet \"%(input)s\"",

    # Timeout for running target
    "target_timeout" : 7,

    # Directory of input files
    "inputs" : BASEDIR + "vlc_inputs",
}

def main():
    try:
        framework.doFuzz(CONFIG)
    except KeyboardInterrupt as e:
        return 0

    return -1

if __name__ == '__main__':
    sys.exit(main())

