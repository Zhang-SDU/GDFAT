#!/usr/bin/env python3

import sys
import sm4Fault
import sm4DA
import os


def processinput(input, blocksize):
    return (None, None)


def processoutput(output, blocksize):
    return int(output[output.find(b'Enc_out:') + 11:].rstrip().replace(b' ', b''), 16)


engine = sm4Fault.Acquisition(targetbin='./sm4_enc', targetdata='./sm4_enc', goldendata='./sm4_enc.gold',
                              dfa=sm4DA, processinput=processinput, processoutput=processoutput, verbose=2,
                              faults_number=128)
tracefiles_sets = engine.run()
for tracefile in tracefiles_sets[0]:
    roundkey = sm4DA.crack_file(tracefile)
    if roundkey:
        print("\nAll_round_key And The Seed_Key Are Recovered!\n")
        os.system('./sm4_keyschedule ' + str(hex(roundkey[3])[2:].rjust(8, '0')) + ' ' + str(
            hex(roundkey[2])[2:].rjust(8, '0')) + ' ' + str(hex(roundkey[1])[2:].rjust(8, '0')) + ' ' + str(
            hex(roundkey[0])[2:].rjust(8, '0')) + ' 32')
        break
