# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@File : sm4Fault.py
@Author : A lover
@Email : 1146918446@qq.com
@Time : 2023/4/13 16:29
@Software: PyCharm
@Purpose:Perform fault injection on white-box programs and collect fault cipher
"""


import os
import sys
import random
import subprocess
import struct
import datetime
from collections import deque
import signal
import time


# helper function
def processinput(iblock, blocksize):
    """
    :param iblock: int representation of one input block
    :param blocksize: int (16 for SM4)
    :return: bytes to be used as target stdin, a list of strings to be used as args for the target
    """
    return (None, ['%0*x' % (2 * blocksize, iblock)])


# helper function
def processoutput(output, blocksize):
    """
    :param output: string, textual output of the target
    :param blocksize: int (16 for SM4)
    :return: a int, supposed to be the data block outputted by the target
    """
    return int(output, 16)


# Exception handling:output exceptions
def try_processoutput(processoutput):
    def foo(output, blocksize):
        try:
            return processoutput(output, blocksize)
        except:
            return None

    return foo


class Acquisition:
    # Initialization:Customized parameters on a case-by-case basis
    def __init__(self, targetbin, targetdata, goldendata, dfa,
                 iblock=0x7364755f6373745f7364755f6373745f,
                 processinput=processinput,
                 processoutput=processoutput,
                 verbose=1,
                 maxleaf=256 * 256,
                 minleaf=64,
                 minleafnail=8,
                 addresses=None,
                 start_from_left=False,
                 depth_first_traversal=False,
                 faults=1,
                 faults_number=128,
                 timeoutfactor=2,
                 savetraces_format='default',
                 logfile=None,
                 outputbeforelastrounds=False):
        # Information level:Determine what information is output on the command line by setting this value
        self.verbose = verbose
        # Determine whether to recover the last round of keys at this point
        self.outputbeforelastrounds = outputbeforelastrounds
        if self.verbose > 1:
            print("Initializing...")
        # Target White Box Program
        self.targetbin = targetbin
        # Target Inject Faults Program
        self.targetdata = targetdata
        # Copy of targetdata:Realistic fault injection Program
        self.goldendata = open(goldendata, 'rb').read()
        # Differential Analysis and Recover Keys Tool
        self.dfa = dfa
        # Block size in bytes SM4:16
        self.blocksize = dfa.blocksize
        # A list of execution status after injecting a fault
        self.FaultStatus = dfa.FaultStatus
        # Plaintext input
        self.iblock = iblock
        # prepares iblock as list of strings based on its int representation
        self.processinput = processinput
        # from output bytes returns oblock as int
        self.processoutput = processoutput
        # Exception handling:If program may crash, make sure try_processoutput() returns None in such cases
        self.try_processoutput = try_processoutput(processoutput)
        # Largest block to fault
        self.maxleaf = maxleaf
        # Smallest block to fault in discovery phase
        self.minleaf = minleaf
        # Smallest block to fault in nail-down phase
        self.minleafnail = minleafnail
        # Tables addresses range:
        # None               = full range
        # (0x1000,0x5000)    = target only specified address range
        # '/path/to/logfile' = replays address ranges according to this log file
        self.addresses = addresses
        # Start faults from the left part or the right part of the range?
        self.start_from_left = start_from_left
        # Depth-first traversal or breadth-first traversal?
        self.depth_first_traversal = depth_first_traversal
        # After finding the good fault output, how many times the fault injection is performed at the same location?
        # list of values to XOR: [0x01, 0xff, ...], or number of random faults
        self.faults = faults
        # How many fault outputs need to be found?
        self.faults_number = faults_number
        # Timestamp:Detection of infinite loops
        self.inittimestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        # Timeout factor (if target execution is N times slower than usual it gets killed)
        self.timeoutfactor = timeoutfactor
        # Traces format:'default'
        self.savetraces_format = savetraces_format
        # Logfile
        self.logfilename = logfile
        self.logfile = None
        self.lastroundkeys = []

        def sigint_handler(signal, frame):
            print('\nGot interrupted!')
            self.savetraces()
            os.remove(self.targetdata)
            if self.logfile is not None:
                self.logfile.close()
            sys.exit(0)

        def sigusr1_handler(signal, frame):
            self.savetraces()

        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGUSR1, sigusr1_handler)
        self.timeout = 10
        if self.verbose > 1:
            print("Initialized!")
        if self.verbose > 0:
            print('Press Ctrl+C to interrupt')
            print('Send SIGUSR1 to dump intermediate results file: $ kill -SIGUSR1 %i' % os.getpid())


    def savetraces(self):
        if len(self.pairs) <= 1:
            print('No trace to save, sorry!')
            return ([], [])
        if self.savetraces_format == 'default':
            return self.savedefault()
        else:
            print('Error: unknown format: ' + self.savetraces_format)


    def savedefault(self):
        tracefiles = ([], [])
        for goodpairs, mode in [(self.pairs, "enc")]:
            if len(goodpairs) > 1:
                tracefile = 'dfa_%s_%s-%s_%i.txt' % (
                    mode, self.inittimestamp, datetime.datetime.now().strftime('%H%M%S'), len(goodpairs))
                print('Saving %i traces in %s' % (len(goodpairs), tracefile))
                with open(tracefile, 'wb') as f:
                    for (iblock, oblock) in goodpairs:
                        f.write(
                            ('%0*X %0*X\n' % (2 * self.blocksize, iblock, 2 * self.blocksize, oblock)).encode('utf8'))
                tracefiles[mode == "dec"].append(tracefile)
        return tracefiles


    # Use program execution encryption after fault injection
    def doit(self, table, processed_input, protect=True, init=False, lastroundkeys=None):
        input_stdin, input_args = processed_input
        if input_args is None:
            input_args = ""
        if lastroundkeys is None:
            lastroundkeys = self.lastroundkeys
        # To avoid seldom busy file errors:
        if os.path.isfile(self.targetdata):
            os.remove(self.targetdata)
        open(self.targetdata, 'wb').write(table)
        # Modify file permissions
        if os.path.normpath(self.targetbin) == os.path.normpath(self.targetdata):
            os.chmod(self.targetbin, 0o755)
        # Create a child process Execute the program
        try:
            proc = subprocess.Popen(self.targetbin + " " + input_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
            # Putting output into memory
            output, errs = proc.communicate(input=input_stdin, timeout=self.timeout)
        except OSError:
            return (None, self.FaultStatus.Crash, None)
        except subprocess.TimeoutExpired:
            # If it times out, killing the child process, indicating a problem with the program.
            proc.terminate()
            try:
                proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
            except:
                pass
            return (None, self.FaultStatus.Loop, None)
        if protect:
            oblock = self.try_processoutput(output, self.blocksize)
        else:
            oblock = self.processoutput(output, self.blocksize)
        # Incorrect output format
        if oblock is not None and oblock.bit_length() > self.blocksize * 8:
            oblock = None
        if oblock is None:
            return (None, self.FaultStatus.Crash, None)
        else:
            oblock = self.dfa.int2bytes(oblock, self.blocksize)
            # Obtain fault ciphertext
            oblocktmp = self.dfa.rewind(oblock, lastroundkeys)
            # Compare the faulty cipher with the correct cipher and Retaining a valid fault cipher
            status, index = self.dfa.check(oblocktmp, self.verbose, init)
            oblock = oblocktmp if self.outputbeforelastrounds else oblock
            oblock = self.dfa.bytes2int(oblock)
        return (oblock, status, index)


    # split the injection area
    def splitrange(self, r, mincut=1):
        x, y = r
        if y - x <= self.maxleaf and mincut == 0:
            return deque([r])
        # split range into power of two and remaining
        left = 1 << (((y - x - 1) // 2)).bit_length()
        if mincut > 0:
            mincut = mincut - 1
        dq = self.splitrange((x, x + left), mincut)
        dq.extend(self.splitrange((x + left, y), mincut))
        return dq


    # Perform fault injection
    def inject(self, r, faultfct):
        return self.goldendata[:r[0]] + bytes([faultfct(x) for x in self.goldendata[r[0]:r[1]]]) + self.goldendata[
                                                                                                   r[1]:]

    # Traverse the region, inject faults, and get valid fault ciphers
    def dig(self, tree=None, faults=None, level=0, candidates=[]):
        if tree is None:
            tree = self.tabletree
        if faults is None:
            faults = self.faults
        if not self.depth_first_traversal:
            breadth_first_level_address = None
        while len(tree) > 0:
            if type(faults) is list:
                fault = faults[0]
            else:
                fault = ('xor', lambda x: x ^ random.randint(1, 255))
            if self.start_from_left:
                r = tree.popleft()
                if not self.depth_first_traversal:
                    if breadth_first_level_address is not None and r[0] < breadth_first_level_address:
                        level += 1
                    breadth_first_level_address = r[0]
            else:
                r = tree.pop()
                if not self.depth_first_traversal:
                    if breadth_first_level_address is not None and r[1] > breadth_first_level_address:
                        level += 1
                    breadth_first_level_address = r[1]
            # the program after the fault injection
            table = self.inject(r, fault[1])
            oblock, status, index = self.doit(table, self.processed_input)
            # save to logfile
            log = 'Lvl %03i [0x%08X-0x%08X[ %s 0x%02X %0*X ->' % (
                level, r[0], r[1], fault[0], fault[1](0), 2 * self.blocksize, self.iblock)
            if oblock is not None:
                log += ' %0*X' % (2 * self.blocksize, oblock)
            log += ' ' + status.name
            if status in [self.FaultStatus.GoodFault]:
                log += ' Index:' + str(index)
            if self.verbose > 1:
                print(log)
            # Fault cipher is the same as normal cipher or only one byte is affected -----> Skip the whole area
            if status in [self.FaultStatus.NoFault, self.FaultStatus.MinorFault]:
                continue
            # Valid failure modes -----> Narrow area
            elif status in [self.FaultStatus.GoodFault]:
                if r[1] > r[0] + self.minleafnail:
                    # Nailing phase: always depth-first
                    if self.verbose > 2:
                        print('Nailing [0x%08X-0x%08X[' % (r[0], r[1]))
                    del (table)
                    if self.dig(self.splitrange(r), faults, level + 1):
                        return True
                    continue
                # Get a good fault output when within minleafnail range before
                else:
                    # Save a current fault message
                    mycandidates = candidates + [(log, (self.iblock, oblock))]
                    if type(faults) is list and len(faults) > 1:
                        del (table)
                        # Fault injection again for the current area ------> Feedback mechanism
                        if self.dig(deque([r]), faults[1:], level, mycandidates):
                            return True
                        continue
                    elif type(faults) is int and faults > 1:
                        del (table)
                        if self.dig(deque([r]), faults - 1, level, mycandidates):
                            return True
                        continue
                    else:
                        while len(mycandidates) > 0:
                            txt, pair = mycandidates.pop(0)
                            if self.verbose > 0:
                                print(txt + ' Logged')
                            if status is self.FaultStatus.GoodFault:
                                if pair not in self.pairs:
                                    self.pairs.append(pair)
                                if len(self.pairs) >= self.faults_number:
                                    return True
                            self.logfile.write(txt + '\n')
                        # write to file right now
                        self.logfile.flush()
                        continue
            # Program crashes/execution takes significantly longer/output format changes
            # Split the area in two, divide it into two small areas, and try again
            elif status in [self.FaultStatus.MajorFault, self.FaultStatus.Loop, self.FaultStatus.Crash]:
                if r[1] > r[0] + self.minleaf:
                    if self.depth_first_traversal:
                        del (table)
                        if self.dig(self.splitrange(r), faults, level + 1):
                            return True
                        continue
                    # breadth-first traversal
                    else:
                        if self.start_from_left:
                            tree.extend(self.splitrange(r))
                            continue
                        else:
                            tree.extendleft(reversed(self.splitrange(r)))
                            continue
                else:
                    continue
        return False


    # Collect fault ciphers
    def run(self, lastroundkeys=[]):
        self.lastroundkeys = lastroundkeys
        # Create a log file to record some information about the fault message that has been obtained.
        if self.logfilename is None:
            self.logfile = open('%s_%s.log' % (self.targetbin, self.inittimestamp), 'w')
        else:
            self.logfile = open(self.logfilename, 'w')
        # split the area
        if self.addresses is None:
            self.tabletree = deque(self.splitrange((0, len(self.goldendata))))
        # '/path/to/logfile'
        elif type(self.addresses) is str:
            self.tabletree = deque()
            with open(self.addresses, 'r') as reflog:
                for line in reflog:
                    self.tabletree.extend([(int(line[9:19], 16), int(line[20:30], 16))])
        # Divide the specified area according to maxleaf
        else:
            self.tabletree = deque(self.splitrange(self.addresses))
        # Plaintext input
        self.processed_input = self.processinput(self.iblock, self.blocksize)
        # Prepare golden output
        starttime = time.time()
        # Get the correct ciphertext
        oblock, status, index = self.doit(self.goldendata, self.processed_input, protect=False, init=True)
        # Set timeout = N times normal execution time
        # Set a time factor to detect infinite loops, beyond which the infinite loop is judged to exist.
        self.timeout = (time.time() - starttime) * self.timeoutfactor
        if oblock is None or status is not self.FaultStatus.NoFault:
            raise AssertionError('Error, could not obtain golden output, check your setup!')
        # Save correct and faulty pairs
        self.pairs = [(self.iblock, oblock)]
        # Collect fault ciphers
        self.dig()
        # save trace file
        tracefiles = self.savetraces()
        os.remove(self.targetdata)
        self.logfile.close()
        return tracefiles
