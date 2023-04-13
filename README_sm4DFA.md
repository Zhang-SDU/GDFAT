# Differential Fault Analysis

The DFA attacks are leveraged by two components:

 * ```sm4Fault.py``` to inject fault and collect faulty outputs.
 * ```sm4DA.py``` to perform DFA attacks against faulty outputs.


## ```sm4Fault.py```

```sm4Fault.py``` is a Python 3 library to help acquiring faulty outputs.  
The current ```sm4Fault.py``` injects faults statically into a data file or an executable file before execution.   
The script will take care of abnormal situations due to fault injection such as crashes or (presumably) infinite loops.  

### Inputs and outputs

To interface with the white-box implementation under attack, you must define two helper functions.    

```processinput()``` will take the input block defined as ```int iblock``` and the blocksize as ```int blocksize``` and will return a tuple (```bytes```, ```list of str```) that will be used in a [Popen](https://docs.python.org/2/library/subprocess.html) interface respectively for the command stdin and command arguments.

The most elementary one is the one defined by default, providing the input as a hex string argument, stdin being unused:
```python
def processinput(iblock, blocksize):
    return (None, ['%0*x' % (2*blocksize, iblock)])
```

An example to provide input as raw chars on stdin is:
```python
def processinput(iblock, blocksize):
    return (bytes.fromhex('%0*x' % (2*blocksize, iblock)), None)
```

If there is no input to provide for the Popen call, e.g. because processinput will write the input in a file or because the white-box implementation generates its own random input, processinput must return ```(None, None)```.(We recommend this approach!)    


```processoutput()``` will take the output of the white-box implementation defined as a multiline ```str output``` and the blocksize as ```int blocksize``` and will return the output block as an ```int```.

The most elementary one is the one defined by default, expecting the white-box output to be a hex string:
```python
def processoutput(output, blocksize):
    return int(output, 16)
```

For a successful DFA we need to get the output under normal conditions, otherwise there is nothing to attack!
So under normal conditions processoutput is always expected to return an output.

Now as we're faulting the white-box implementation it might be that for some faults, the program does not output anything, or even crashes or even is in an infinite loop.  
Therefore internally processoutput is wrapped in a try-catch that will output ```None``` in case of failure.



### Acquisition

```Acquisition``` ```__init__``` arguments are:
  * ```targetbin```: (str) the executable, required. Must be in the PATH so prepend './' if needed.
  * ```targetdata```: (str) the file to be faulted, can be the tables file loaded by the white-box executable or the executable itself. It's not supposed to be provided, it'll be copied from ```goldendata```, therefore any existing ```targetdata``` will be destroyed!
  * ```goldendata```: (str) the original copy of the file to be faulted, ```targetdata``` faulty copies will be made during the attack. Must be different from ```targetdata```!
  * ```dfa```: DFA module, sm4DA
  * ```iblock```: (int) reference input block to provide to the executable
  Default: 0x7364755f6373745f7364755f6373745f
  * ```processinput```: the helper function to prepare the input from ```iblock```, cf above.  
  Default: a helper writing the input in hex
  * ```processoutput```: the helper function to extract the output data, cf above.  
  Default: a helper expecting the output in hex
  * ```verbose```: (int) verbosity level  
  Default: 1
  * ```maxleaf```: (int) max size of faulty blocks, can be large when attacking raw tables, smaller when attacking serialized tables or executables as a large fault has very little chance to succeed  
  Default: 256*256
  * ```minleaf```: (int) min size of faulty blocks in the search phase. Same as above. The smaller, the longer the scan may take.  
  Default: 64
  * ```minleafnail```: (int) once an exploitable output is found in the scan phase, reduce the fault up to this size, in order to avoid multiple faults at once. Reduce if DFA tool fails on the recorded traces.  
  Default: 8
  * ```addresses```: (tuple) address range within ```goldendata``` where to inject faults; or (str) '/path/to/logfile' to replay address ranges specified in this log file, see below  
  Default: None => the entire address range of ```goldendata```
  * ```start_from_left```: (bool) scan should start from left? Else from right. Note that DFA attacks one of the last rounds so it may be faster starting from the right.
  Default: True
  * ```depth_first_traversal```: (bool) scan should dig from ```maxleaf``` to ```minleaf``` elements before getting to the next ```maxleaf``` segment? Else try all ```maxxleaf``` segments before going one level down
  Default: False
  * ```faults```: (int) once a ```minleafnail``` segment gives a good fault output, how many times the fault injection is performed at the same location?(with other random values)?   
  Default: 4 
  * ```faults_number```: (int) How many fault outputs need to be found?    
  Default: 128
  * ```timeoutfactor```: (int or float) to detect potentially infinite loops, the script measures the process time under normal conditions and interrupts the faulted process after ```timeoutfactor``` times the normal processing time.     
  Default: 2
  * ```savetraces_format```: (str) ```'default'``` will save inputs and faulty outputs in a very basic format, suitable for sm4DA.     
  Default: ```'default'```
  * ```logfile```: (str)Default: None

  * ```outputbeforelastrounds``` (bool) when attacking previous rounds, indicate what kind of output to record: the real output or the virtual output once the known last rounds are removed.
  Default: False
  

When an attack is running, a logfile records the faults leading to potentially exploitable outputs. This logfile can be provided for a new set of attacks via the ```addresses``` argument to replay an attack at the same addresses.

Default saved traces format is very basic: ```dfa_<<enc/dec>>>_<<begin_timestamp>>-<<end_timestamp>>>_<<number of records>>.txt``` containing on each line the reference input and the output as hex string.
First record is the one with the correct output, to be used as reference by the DFA tool.

If the attack is running for long and you want to try a DFA attack on intermediate results, send a SIGUSR1 and it will dump an intermediate tracefile.
You can interrupt the script with a SIGINT (ctrl-C), it will save the current tracefile as well before quitting.


Typical usage:
```python
import sys
import sm4Fault
import sm4DA
import os

engine = sm4Fault.Acquisition(targetbin='./sm4_enc', targetdata='./sm4_enc', goldendata='./sm4_enc.gold', dfa=sm4DA,verbose=2, faults_number=128)
                             
tracefiles_sets = engine.run()
for tracefile in tracefiles_sets[0]:
    roundkey = sm4DA.crack_file(tracefile)
    if roundkey:
        print("\nAll_round_key And The Seed_Key Are Recovered!\n")
        os.system('./sm4_keyschedule ' + str(hex(roundkey[3])[2:].rjust(8, '0')) + ' ' + str(
            hex(roundkey[2])[2:].rjust(8, '0')) + ' ' + str(hex(roundkey[1])[2:].rjust(8, '0')) + ' ' + str(
            hex(roundkey[0])[2:].rjust(8, '0')) + ' 32')
        break
```
