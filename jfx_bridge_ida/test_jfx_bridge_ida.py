import unittest
import os
import logging
import functools

import jfx_bridge
import jfx_bridge_ida
from jfx_bridge_ida.server import jfx_bridge_ida_port

from . import test_module


def print_stats(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        start_stats = self.test_bridge.get_stats()
        func(self, *args, **kwargs)
        print(
            "\n{}:\n\t{}\n".format(
                func.__name__, self.test_bridge.get_stats() - start_stats
            )
        )

    return wrapper


class TestIDABridge(unittest.TestCase):
    """ Assumes there's an IDA bridge server running at DEFAULT_SERVER_PORT """

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", jfx_bridge_ida_port.DEFAULT_SERVER_PORT))
        cls.test_bridge = jfx_bridge_ida.IDABridge(
            connect_to_port=port, loglevel=logging.DEBUG, record_stats=True
        )

    @print_stats
    def test_get_screen_ea(self):
        """ Confirm we can get the current address - this is not a threadsafe function, so if this works, our execute_sync wrapper is working """
        idaapi = self.test_bridge.get_idaapi()
        idaapi.get_screen_ea()

    @print_stats
    def test_threadsafe_generator(self):
        """ Confirm we can wrap a generator to use execute_sync """
        idautils = self.test_bridge.get_idautils()
        next(idautils.Segments())

    @print_stats
    def test_remote_eval(self):
        """ Confirm that we can do a remote_eval fine - that the ida functions are still wrapped """
        idc = self.test_bridge.get_idc()
        idautils = self.test_bridge.get_idautils()

        # pre IDA 7 compat
        get_func_name_fn_name = (
            "get_func_name" if "get_func_name" in dir(idc) else "GetFunctionName"
        )
        segment_end_fn_name = "get_segm_end" if "get_segm_end" in dir(idc) else "SegEnd"
        for segea in idautils.Segments():
            self.test_bridge.bridge.remote_eval(
                "[(funcea, idc.{}(funcea)) for funcea in idautils.Functions(segea, idc.{}(segea))]".format(
                    get_func_name_fn_name, segment_end_fn_name
                ),
                segea=segea,
                timeout_override=20,
            )

    @print_stats
    def test_remote_eval_exception(self):
        """ Confirm that we can still get exceptions from the remote_eval after execute_sync """
        with self.assertRaises(jfx_bridge.bridge.BridgeException):
            self.test_bridge.bridge.remote_eval("1/0")

    @print_stats
    def test_inheritance(self):
        """ Check we can inherit from an IDA object and override a method (e.g., __init__) which calls another IDA function (e.g., the parent __init__)
            without getting caught in an execute_sync deadlock """
        idaapi = self.test_bridge.get_idaapi()

        class TestListener(idaapi.UI_Hooks):
            called = False

            def __init__(self):
                idaapi.UI_Hooks.__init__(self)
                self.called = True

        t = TestListener()

        self.assertTrue(t.called)

    @print_stats
    def test_callback(self):
        """ Test we can get a callback 
        
        Expected failure on pre 7.2 - screen_ea_changed doesn't exist
        """
        idaapi = self.test_bridge.get_idaapi()

        class TestListener(idaapi.UI_Hooks):
            called = False

            def screen_ea_changed(self, new_ea, prev_ea):
                self.called = True
                return 0

        t = TestListener()
        try:
            t.hook()
            idaapi.jumpto(idaapi.get_screen_ea() + 0x10)
        finally:
            t.unhook()

        self.assertTrue(t.called)

    @print_stats
    def test_function_help(self):
        """ Check that we can view the function help """
        idaapi = self.test_bridge.get_idaapi()
        self.assertTrue("get_screen_ea()" in idaapi.get_screen_ea.__doc__)

    @print_stats
    def test_type_instantiate(self):
        """ check we can instantiate an IDA type that isn't threadsafe in its init 
        
        Expected failure in IDA pre 7 - no idadex. Haven't found another class with a non-threadsafe init
        """
        idadex = self.test_bridge.remote_import("idadex")
        try:
            idadex.Dex()
        except Exception as e:  # idadex.Dex will except if not operating on a dex - only care about the main thread error
            self.assertTrue(
                "Function can be called from the main thread only" not in str(e)
            )

    @print_stats
    def test_type_instantiate_inherited_but_non_overridden_init(self):
        """ check we can instantiate an type we've created from an IDA type that isn't threadsafe in its init, and we haven't overridden that init 
        
        Expected failure in IDA pre 7 - no idadex. Haven't found another class with a non-threadsafe init
        """
        idadex = self.test_bridge.remote_import("idadex")

        class TestDex(idadex.Dex):
            pass

        try:
            t = TestDex()
        except Exception as e:  # idadex.Dex will except if not operating on a dex - only care about the main thread error
            self.assertTrue(
                "Function can be called from the main thread only" not in str(e),
                "Original __init__ not running on main thread",
            )

    @print_stats
    def test_type_instantiate_inherited_with_overridden_init(self):
        """ check we can instantiate an type we've created from an IDA type that isn't threadsafe in its init, we've overridden that init, but we're still calling it in our init 
        
        Expected failure in IDA pre 7 - no idadex. Haven't found another class with a non-threadsafe init
        """
        idadex = self.test_bridge.remote_import("idadex")

        parent = self

        class TestDex(idadex.Dex):
            def __init__(self):
                try:
                    idadex.Dex.__init__(self)
                except Exception as e:  # idadex.Dex will except if not operating on a dex - only care about the main thread error
                    parent.assertTrue(
                        "Function can be called from the main thread only"
                        not in str(e),
                        "Original __init__ not running on main thread",
                    )

        t = TestDex()

    @print_stats
    def test_remoteify_function_using_idaapi(self):
        """ Test that we can remoteify a function using something from the idaapi, that should run into execute_sync problems"""

        def foobar():
            return idaapi.get_screen_ea()

        remote_foobar = self.test_bridge.remoteify(foobar)

        self.assertIsNotNone(remote_foobar())

    @print_stats
    def test_remoteify_function_with_imports(self):
        """ Test that we can remoteify a function that uses imported modules, that should run into execute_sync problems """

        def importer():
            from ida_kernwin import get_screen_ea

            return get_screen_ea()

        remote_importer = self.test_bridge.remoteify(importer)
        self.assertIsNotNone(remote_importer())

    @print_stats
    def test_remoteify_class(self):
        """ Test that we can remoteify a class, that should run into execute_sync problems"""

        class CLZ:
            def __init__(self):
                self.ea = idaapi.get_screen_ea()

            def get_fns(self):
                import idautils

                return list(idautils.Functions())

        remote_clz = self.test_bridge.remoteify(CLZ)

        rc = remote_clz()
        self.assertTrue(0 < len(rc.get_fns()))

    @print_stats
    def test_remoteify_module(self):
        """ Check we can remoteify a module, that should run into execute_sync problems (both when importing, and when running functions) """
        remote_test_module = self.test_bridge.remoteify(test_module)

        self.assertIsNotNone(remote_test_module.run())
        self.assertIsNotNone(remote_test_module.TestingClass())

    @print_stats
    def test_idaapi_with_string(self):
        """ Check we can call an IDA function that takes a string, and that the string is correctly set to plain (only relevant for IDA running python 2) """
        idautils = self.test_bridge.get_idautils()

        f = next(idautils.Functions())

        idaapi = self.test_bridge.get_idaapi()
        idaapi.set_name(f, "test_name")  # should work without error

