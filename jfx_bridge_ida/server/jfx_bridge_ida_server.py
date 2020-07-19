""" Run a jfx_bridge_ida server for external python environments to interact with """

import logging
import subprocess
import functools
from jfx_bridge import bridge
from jfx_bridge_ida_port import DEFAULT_SERVER_PORT

import idaapi

# IDA specific hooking
# IDA 7.2 requires all APIs not explicitly marked THREAD_SAFE to be called from the main thread. It provides
# the idaapi.execute_sync function to carry this out, which takes a python callable to run, and returns an
# int.
#
# To handle this, we hook the local_call/local_eval functions in the bridge, and wrap whatever we were going to call in
# a bound callable that provides a way to return an arbitrary result, then pass that bound callable to execute_sync.


class WrapperReturn(object):
    """ class to return an arbitrary result """

    result = None


def wrapper_execute_on_main_thread(prepped_function, return_object):
    """ Wrapper to handle calling the prepped function (with bound arguments) on the main IDA thread after being run through execute_sync.
        Will execute the prepped function and pass the result back to the return_object provided """
    return_object.result = prepped_function()

    return 0


def hook_local_call_execute_on_main_thread(bridge_conn, args_dict):
    """ Hook the real local_call and handle generating a bound callable that will give us an arbitrary result back """
    # where we get our result
    return_object = WrapperReturn()

    # first, bind the real local call function to the arguments
    prepped_function = functools.partial(
        bridge.BridgeConn.REAL_LOCAL_CALL, bridge_conn, args_dict
    )

    # then bind it into the callable wrapper we'll pass to execute sync, along with the return object
    prepped_wrapper = functools.partial(
        wrapper_execute_on_main_thread, prepped_function, return_object
    )

    # run it on the main thread - we use MFF_WRITE to make sure that regardless of whether the operation reads/writes/ignores the database, it'll be fine
    idaapi.execute_sync(prepped_wrapper, idaapi.MFF_WRITE)

    # and we're done! (Note: this behaviour matches jfx_bridge >= 0.3.1, where serializing the results to a dictionary is handled centrally)
    return return_object.result


def hook_local_eval_execute_on_main_thread(bridge_conn, args_dict):
    """ Hook the real local_eval and handle generating a bound callable that will give us an arbitrary result back """
    # TODO extract kwargs to specify MFF level, or not to execute_sync

    # where we get our result
    return_object = WrapperReturn()

    # first, bind the real local eval function to the arguments
    prepped_function = functools.partial(
        bridge.BridgeConn.REAL_LOCAL_EVAL, bridge_conn, args_dict
    )

    # then bind it into the callable wrapper we'll pass to execute sync, along with the return object
    prepped_wrapper = functools.partial(
        wrapper_execute_on_main_thread, prepped_function, return_object
    )

    # run it on the main thread - we use MFF_WRITE to make sure that regardless of whether the operation reads/writes/ignores the database, it'll be fine
    idaapi.execute_sync(prepped_wrapper, idaapi.MFF_WRITE)
    # TODO if we can specify MFF level and do nowait, allow for returning the no wait result

    # and we're done! (Note: this behaviour matches jfx_bridge >= 0.3.1, where serializing the results to a dictionary is handled centrally)
    return return_object.result


# record what the real local_call/local_evals are, then replace them with hooks
if not hasattr(bridge.BridgeConn, "REAL_LOCAL_EVAL"):
    # hasn't been hooked before, so save the real call. Only do it once, so we don't hook the hook when we restart
    bridge.BridgeConn.REAL_LOCAL_CALL = bridge.BridgeConn.local_call
if not hasattr(bridge.BridgeConn, "REAL_LOCAL_EVAL"):
    # hasn't been hooked before, so save the real call. Only do it once, so we don't hook the hook when we restart
    bridge.BridgeConn.REAL_LOCAL_EVAL = bridge.BridgeConn.local_eval

bridge.BridgeConn.local_call = hook_local_call_execute_on_main_thread
bridge.BridgeConn.local_eval = hook_local_eval_execute_on_main_thread


def run_server(
    server_host=bridge.DEFAULT_HOST,
    server_port=DEFAULT_SERVER_PORT,
    response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT,
    background=True,
):
    """ Run a jfx_bridge_ida server (forever)
        server_host - what address the server should listen on
        server_port - what port the server should listen on
        response_timeout - default timeout in seconds before a response is treated as "failed"
        background - false to run the server in this thread (will lock up GUI), true for a new thread
    """
    server = bridge.BridgeServer(
        server_host=server_host,
        server_port=server_port,
        loglevel=logging.INFO,
        response_timeout=response_timeout,
    )

    if background:
        server.start()
        print(
            "Server launching in background - will continue to run after launch script finishes...\n"
        )
    else:
        server.run()


def run_script_across_bridge(script_file, python="python", argstring=""):
    """ Spin up a jfx_bridge_ida_Server and spawn the script in external python to connect back to it. Useful in scripts being triggered from
        inside an older IDA that's stuck in python2 or 32-bit python.

        The called script needs to handle the --connect_to_host and --connect_to_port command-line arguments and use them to start
        a jfx_bridge_ida client to talk back to the server.

        Specify python to control what the script gets run with. Defaults to whatever python is in the shell - if changing, specify a path
        or name the shell can find.
        Specify argstring to pass further arguments to the script when it starts up.
    """

    # spawn a jfx_bridge_ida server - use server port 0 to pick a random port
    server = bridge.BridgeServer(
        server_host="127.0.0.1", server_port=0, loglevel=logging.INFO
    )
    # start it running in a background thread
    server.start()

    try:
        # work out where we're running the server
        server_host, server_port = server.get_server_info()

        print("Running " + script_file)

        # spawn an external python process to run against it
        try:
            output = subprocess.check_output(
                "{python} {script} --connect_to_host={host} --connect_to_port={port} {argstring}".format(
                    python=python,
                    script=script_file,
                    host=server_host,
                    port=server_port,
                    argstring=argstring,
                ),
                stderr=subprocess.STDOUT,
                shell=True,
            )
            print(output)
        except subprocess.CalledProcessError as exc:
            print("Failed ({}):{}".format(exc.returncode, exc.output))

        print(script_file + " completed")

    finally:
        # when we're done with the script, shut down the server
        server.shutdown()


if __name__ == "__main__":
    run_server(background=True)
