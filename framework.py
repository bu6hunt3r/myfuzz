#
# Framework for fuzzing things
#
# author: Chris Bisnett
#

import sys
import os
import random
import subprocess
import time
import shutil
import shlex

from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.debugger.process_event import ProcessExit
from ptrace.debugger.ptrace_signal import ProcessSignal
from signal import SIGCHLD, SIGTRAP, SIGSEGV
import logging

def _setupEnvironment(config):
    """
    Performs one-time setup tasks before starting the fuzzer
    """
    # Silence warnings from the ptrace library
    logging.getLogger().setLevel(logging.ERROR)

    # AddressSanitizer will report memory leaks by default on exit. We don't
    # care about those since they aren't vulnerabilities, so disable it
    os.environ["ASAN_OPTIONS"] = "detect_leaks=false:abort_on_error=true"

    # Tell Glibc to abort on heap corruption but not dump a bunch of output
    os.environ["MALLOC_CHECK_"] = "2"

# Global cache of inputs
_inputs = []

def _chooseInput(config):
    """
    Chooses an input from the inputs directory specified in the configuration
    """
    global _inputs
    if len(_inputs) == 0:
        _inputs = os.listdir(config["inputs"])

    return os.path.join(config["inputs"], random.choice(_inputs))

def _generateSeed(config):
    """
    Generate a random seed to pass to the fuzzer
    """
    return random.randint(0, 2**64 - 1)

def _runFuzzer(config, inputFile, seed, outputFile, count):
    """
    Run the fuzzer specified in the configuration
    """
    args = config["fuzzer_args"] % ({"seed" : seed, "input" : inputFile,
        "output" : outputFile, "count" : count})
    subprocess.call(config["fuzzer"] + " " + args, shell=True)

def _runTarget(config, outputFile):
    """
    Run the target application specified in the configuration and pass it the
    file output from the fuzzer
    """
    args = config["target_args"] % ({"input" : outputFile})
    cmd = shlex.split(config["target_bin"] + " " + args)
    pid = createChild(cmd, True, None)

    return pid

def _checkForCrash(config, event):
    """
    Check if the target application has crashed
    """
    # Normal exits have no signal associated with them
    if event.signum is not None or event.exitcode != 0:
        return event

    return None

def _handleOutcome(config, event, inputFile, seed, outputFile, count):
    """
    Save the output from the fuzzer for replay and make a note of the outcome
    """
    # Save a log
    with open(os.path.join(config["outcome_dir"], str(seed)+".txt"), "w") as f:
        f.write("Input: %s\n" % inputFile)
        f.write("Seed: %s\n" % seed)
        f.write("Count: %d\n" % count)
        if hasattr(event, "signum") and event.signum:
            f.write("Signal: %d\n" % event.signum)

        if hasattr(event, "exitcode") and event.exitcode:
            f.write("Exit code: %d\n" % event.exitcode)

    # Save the output
    try:
        shutil.copy(outputFile, os.path.join(config["outcome_dir"],
            os.path.basename(outputFile)))
    except Exception as e:
        print "Failed to copy output file:", outputFile

def doFuzz(config, setupEnvironment=_setupEnvironment, chooseInput=_chooseInput,
    generateSeed=_generateSeed, runFuzzer=_runFuzzer, runTarget=_runTarget,
    checkForCrash=_checkForCrash, handleOutcome=_handleOutcome):
    seed = 0
    count = 0
    haveOutcome = False
    outcome = None
    done = False

    # Step 1: Setup environment
    setupEnvironment(config)

    print "Running fuzzer:", config["fuzzer"]

    sys.stdout.write("%8d: " % (0))
    sys.stdout.flush()

    while not done:
        # Step 2: Choose an input
        inFile = chooseInput(config)

        # We're done if no input is returned
        if inFile is None:
            print "\nNo more inputs, exiting."
            break

        # Step 3: Generate a seed
        seed = generateSeed(config)

        # Generate a name for the output file
        outExt = os.path.splitext(inFile)[1]
        outFile = os.path.join(os.getcwd(), str(seed) + outExt)

        # Step 4: Run fuzzer
        runFuzzer(config, inFile, seed, outFile, count)

        # Step 5: Run the target
        pid = runTarget(config, outFile)

        #######################################################################
        # This is where the magic happens. We monitor the process to determine
        # if it has crashed
        # Attach to the process with ptrace
        dbg = PtraceDebugger()
        proc = dbg.addProcess(pid, True)
        proc.cont()

        # Calculate the maximum time the target will be allowed to run
        endTime = time.time() + config["target_timeout"]

        outcome = None
        while True:
            try:
                # Check if there is an event pending for the target applicaiton
                # This will return immediately with either an event or None if
                # there is no event. We do this so we can kill the target after
                # it reaches the timeout
                event = dbg.waitProcessEvent(blocking=False)

                # Check if the process exited
                if type(event) == ProcessExit:
                    # Step 6: Check for crash
                    outcome = checkForCrash(config, event)

                    # The target application exited so we're done here
                    break

                elif type(event) == ProcessSignal:
                    # SIGCHLD simply notifies the parent that one of it's
                    # children processes has exited or changed (exec another
                    # process). It's not a bug so we tell the process to
                    # continue and we loop again to get the next event
                    if event.signum == SIGCHLD:
                        event.process.cont()
                        continue

                    outcome = checkForCrash(config, event)
                    break

            except KeyboardInterrupt:
                done = True
                break

            # Check if the process has reached the timeout
            if time.time() >= endTime:
                break
            else:
                # Give the CPU some timeslices to run other things
                time.sleep(0.1)

        # Step 7: Handle any crashes
        if outcome is not None:
            handleOutcome(config, outcome, inFile, seed, outFile, count)

            haveOutcome = True

        # Done with the process
        proc.terminate()

        # Delete the output
        try:
            os.remove(outFile)
        except:
            print "Failed to remove file %s!" % outFile

        # Update the counter and display the visual feedback
        count += 1
        if count % 2 == 0:
            if haveOutcome:
                sys.stdout.write("!")
                haveOutcome = False
            else:
                sys.stdout.write(".")

            sys.stdout.flush()

        if count % 100 == 0:
            sys.stdout.write("\n%8d: " % count)
            sys.stdout.flush()
