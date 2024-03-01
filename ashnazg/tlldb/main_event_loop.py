import lldb

def run_commands(command_interpreter, commands, stop_on_error=False):
    return_obj = lldb.SBCommandReturnObject()
    for command in commands:
        command_interpreter.HandleCommand(command, return_obj)
        if return_obj.Succeeded():
            print(return_obj.GetOutput())
        else:
            print(return_obj)
            if stop_on_error:
                break

def print_threads(process, options):
    for thread in process:
        print("%s %s" % (thread, thread.GetFrameAtIndex(0)))

def handle_events(exe, pid, options):
    debugger : lldb.SBDebugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    command_interpreter : lldb.SBCommandInterpreter = debugger.GetCommandInterpreter()

    error = lldb.SBError()
    target = debugger.CreateTarget(
                exe, options.arch, options.platform, True, error)
    
    launch_info = None

    attach_info = lldb.SBAttachInfo(pid)

    if target:
        for run_idx in range(options.run_count):
            # Launch the process. Since we specified synchronous mode, we won't return
            # from this function until we hit the breakpoint at main
            error = lldb.SBError()

            process : lldb.SBProcess = target.Attach(attach_info, error)

            # Make sure the launch went ok
            if process and process.GetProcessID() != lldb.LLDB_INVALID_PROCESS_ID:

                pid = process.GetProcessID()
                print('Process is %i' % (pid))
                if attach_info:
                    # continue process if we attached as we won't get an
                    # initial event
                    print_threads(process,options)
                    result = lldb.SBCommandReturnObject()
                    print(command_interpreter.HandleCommand("register read", result))
                    print(result.GetOutput())
                    print(command_interpreter.HandleCommand("thread backtrace", result))
                    print(result.GetOutput())
                    currThread : lldb.SBThread = process.GetSelectedThread()
                    print("Thread", currThread)
                    currFrame : lldb.SBFrame = currThread.GetSelectedFrame()
                    for frame in currThread.frames:
                        frame : lldb.SBFrame
                        print(frame)
                        frame.register
                    print(currThread.GetSelectedFrame())
                    process.Kill()

                listener = debugger.GetListener()
                # sign up for process state change events
                stop_idx = 0
                done = False
                while not done:
                    event = lldb.SBEvent()
                    if listener.WaitForEvent(options.event_timeout, event):
                        if lldb.SBProcess.EventIsProcessEvent(event):
                            state = lldb.SBProcess.GetStateFromEvent(event)
                            if state == lldb.eStateInvalid:
                                # Not a state event
                                print('process event = %s' % (event))
                            else:
                                print("process state changed event: %s" % (lldb.SBDebugger.StateAsCString(state)))
                                if state == lldb.eStateStopped:
                                    if stop_idx == 0:
                                        print("hi")
                                    else:
                                        if options.verbose:
                                            print("process %u stopped" % (pid))
                                        run_commands(
                                            command_interpreter, options.stop_commands)
                                    stop_idx += 1
                                    print_threads(process, options)
                                    print("continuing process %u" % (pid))
                                    process.Continue()
                                elif state == lldb.eStateExited:
                                    exit_desc = process.GetExitDescription()
                                    if exit_desc:
                                        print("process %u exited with status %u: %s" % (pid, process.GetExitStatus(), exit_desc))
                                    else:
                                        print("process %u exited with status %u" % (pid, process.GetExitStatus()))
                                    print("exited")
                                    done = True
                                elif state == lldb.eStateCrashed:
                                    print("process %u crashed" % (pid))
                                    print_threads(process, options)
                                    run_commands(
                                        command_interpreter, options.crash_commands)
                                    done = True
                                elif state == lldb.eStateDetached:
                                    print("process %u detached" % (pid))
                                    done = True
                                elif state == lldb.eStateRunning:
                                    # process is running, don't say anything,
                                    # we will always get one of these after
                                    # resuming
                                    if options.verbose:
                                        print("process %u resumed" % (pid))
                                elif state == lldb.eStateUnloaded:
                                    print("process %u unloaded, this shouldn't happen" % (pid))
                                    done = True
                                elif state == lldb.eStateConnected:
                                    print("process connected")
                                elif state == lldb.eStateAttaching:
                                    print("process attaching")
                                elif state == lldb.eStateLaunching:
                                    print("process launching")
                        else:
                            print('event = %s' % (event))
                    else:
                        # timeout waiting for an event
                        print("no process event for %u seconds, killing the process..." % (options.event_timeout))
                        done = True
                # Now that we are done dump the stdout and stderr
                process_stdout = process.GetSTDOUT(1024)
                if process_stdout:
                    print("Process STDOUT:\n%s" % (process_stdout))
                    while process_stdout:
                        process_stdout = process.GetSTDOUT(1024)
                        print(process_stdout)
                process_stderr = process.GetSTDERR(1024)
                if process_stderr:
                    print("Process STDERR:\n%s" % (process_stderr))
                    while process_stderr:
                        process_stderr = process.GetSTDERR(1024)
                        print(process_stderr)
                process.Kill()  # kill the process
            else:
                if error:
                    print(error)
                else:
                    if launch_info:
                        print('error: launch failed')
                    else:
                        print('error: attach failed')