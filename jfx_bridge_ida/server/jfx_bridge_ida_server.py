""" Run a jfx_bridge_ida server for external python environments to interact with """

import functools
import inspect
import logging
import os
import subprocess
import types
import sys

from jfx_bridge import bridge
from jfx_bridge_ida_port import DEFAULT_SERVER_PORT

import idaapi

# pull in idc and idautils so they're available for remote_evals without extra work
import idc
import idautils

# try to do the same thing with sark, but it's fine if it's not present
try:
    import sark
except ImportError:
    pass

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
    exception = None  # if not None, we hit an exception, and result isn't valid


def wrapper_execute_on_main_thread(prepped_function, return_object):
    """ Wrapper to handle calling the prepped function (with bound arguments) on the main IDA thread after being run through execute_sync.
        Will execute the prepped function and pass the result (or any exception) back to the return_object provided """
    try:
        return_object.result = prepped_function()
    except Exception as e:
        return_object.exception = e

    return 0


def call_execute_sync_and_get_result(
    prepped_function, execute_sync_flag=idaapi.MFF_WRITE
):
    """ we use MFF_WRITE to make sure that regardless of whether the operation reads/writes/ignores the database, it'll be fine """
    # if the caller has deliberately specified no execute_sync flag, don't call it - just call the prepped function directly and return the result
    if execute_sync_flag is None:
        return prepped_function()

    # where we get our result
    return_object = WrapperReturn()

    # bind the prepped function bound with args into the callable wrapper we'll pass to execute sync, along with the return object
    prepped_wrapper = functools.partial(
        wrapper_execute_on_main_thread, prepped_function, return_object
    )

    # run it on the main thread
    idaapi.execute_sync(prepped_wrapper, execute_sync_flag)

    if return_object.exception is not None:
        # something went wrong. reraise the exception on this thread, so it'll get passed back
        raise return_object.exception

    # and we're done!
    return return_object.result


# we don't wrap these, because we know they're safe and/or being wrapped may affect their operation
NO_WRAP_LIST = [idaapi.execute_sync, idaapi.is_main_thread]


def is_ida_module(module_name):
    """ Return true if it's an IDA-related module we want to execute_sync callables from
        sark, idaapi, idautils, idc - any ida_ (e.g., ida_kernwin), _ida_*.pyd, and a few edge cases (idadex.py, idc_bc695.py)
        We include __main__, because that's where any functions/classes that have been remotify-ed end up
    """
    return (
        module_name.startswith(("_ida_", "ida", "idc"))
        or module_name == "sark"
        or module_name == "__main__"
    )


def should_execute_sync(target_callable):
    """ Return true if target_callable is IDA-related and is something we should use execute_sync to run on the main thread """

    if (
        target_callable not in NO_WRAP_LIST
    ):  # exclude the ones we know we don't want to wrap
        module = inspect.getmodule(
            target_callable
        )  # easy mode - does it have a module inspect can tell us about
        if module is None:
            if isinstance(target_callable, functools.partial):
                # partials - get the module from the function that's been wrapped
                module = inspect.getmodule(target_callable.func)
            elif "method-wrapper" in str(type(target_callable)):
                # bound to an instance of an object (in __self__)
                obj = target_callable.__self__
                if isinstance(obj, types.GeneratorType):
                    # generators need some additional inspection to see if they're IDA code
                    module = os.path.basename(obj.gi_code.co_filename).split(".")[0]
                else:  # expect the object to have __module__
                    module = inspect.getmodule(target_callable)
            elif "wrapper_descriptor" in str(type(target_callable)):
                # slot wrappers for things like base object implementation of __str__ - has a class in __objclass__
                module = inspect.getmodule(target_callable.__objclass__)

        if module is None:
            if hasattr(target_callable, "__module__"):
                if isinstance(
                    target_callable.__module__, bridge.STRING_TYPES
                ):  # if python2: unicode as well as str
                    if isinstance(target_callable, type):
                        # this is a type created for a remote bridge (e.g., inheriting from a local type, or in a remotify-ed module)
                        # by default, we'll assume we should execute_sync. The only exception is if the __init__ is bridged - we need to let
                        # that go back through the bridge normally, so we don't block if it in turn calls an IDA related function
                        if (
                            "__init__" in target_callable.__dict__
                            and bridge._is_bridged_object(
                                target_callable.__dict__["__init__"]
                            )
                        ):
                            # has a bridged init, no execute_sync - if the bridged init calls an ida function, we can execute_sync that when it comes in
                            return False

                        return True
                    else:  # not a type - probably a function in a remotified module - assume we need to execute_sync
                        return True

            # don't know what this is, complain
            raise Exception(
                "Unknown module for : "
                + str(target_callable)
                + " "
                + str(type(target_callable))
                + " "
                + str(target_callable.__dict__)
            )

        if inspect.ismodule(module):
            module = module.__name__

        return is_ida_module(module)

    return False


def hook_local_call(bridge_conn, target_callable, *args, **kwargs):
    """ Hook the real local_call and see if we should use execute_sync to run the target on the main thread """

    execute_sync_flag = None  # if it's not IDA-related, we'll skip the execute_sync
    if should_execute_sync(target_callable):
        execute_sync_flag = idaapi.MFF_WRITE

    # Possible future - pull an execute sync flag kwarg from the callable args, to allow explicitly marking a particular call as MFF_READ or not needing execute sync

    # bind the target to the arguments
    prepped_function = functools.partial(target_callable, *args, **kwargs)

    return call_execute_sync_and_get_result(
        prepped_function, execute_sync_flag=execute_sync_flag
    )


def hook_local_eval(bridge_conn, eval_expr, eval_globals, eval_locals):
    """ Hook the real local_eval and use execute_sync to run the eval on the main thread """

    # first, bind the eval function to the arguments
    prepped_function = functools.partial(eval, eval_expr, eval_globals, eval_locals)

    return call_execute_sync_and_get_result(prepped_function)


def exec_wrapper(exec_expr, exec_globals=None, exec_locals=None):
    """ Wrap exec, to provide backcompat for python2, where it's not a function and so can't be bound
        with functools.partial """
    exec(exec_expr, exec_globals, exec_locals)


def hook_local_exec(bridge_conn, exec_expr, exec_globals):
    """ Hook the real local_exec and use execute_sync to run the exec on the main thread """

    # first, bind the exec function to the arguments
    prepped_function = functools.partial(exec_wrapper, exec_expr, exec_globals)

    return call_execute_sync_and_get_result(prepped_function)


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
        local_call_hook=hook_local_call,
        local_eval_hook=hook_local_eval,
        local_exec_hook=hook_local_exec,
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
        server_host="127.0.0.1",
        server_port=0,
        loglevel=logging.INFO,
        local_call_hook=hook_local_call,
        local_eval_hook=hook_local_eval,
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
