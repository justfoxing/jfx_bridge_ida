import unittest
import os
import logging

import jfx_bridge
import jfx_bridge_ida
from jfx_bridge_ida.server import jfx_bridge_ida_port


class TestIDABridge(unittest.TestCase):
    """ Assumes there's an IDA bridge server running at DEFAULT_SERVER_PORT """

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", jfx_bridge_ida_port.DEFAULT_SERVER_PORT))
        TestIDABridge.test_bridge = jfx_bridge_ida.IDABridge(
            connect_to_port=port, loglevel=logging.DEBUG
        )

    def test_get_screen_ea(self):
        """ Confirm we can get the current address - this is not a threadsafe function, so if this works, our execute_sync wrapper is working """
        idaapi = TestIDABridge.test_bridge.get_idaapi()
        idaapi.get_screen_ea()

    def test_threadsafe_generator(self):
        """ Confirm we can wrap a generator to use execute_sync """
        idautils = TestIDABridge.test_bridge.get_idautils()
        next(idautils.Segments())

    def test_remote_eval(self):
        """ Confirm that we can do a remote_eval fine - that the ida functions are still wrapped """
        idc = TestIDABridge.test_bridge.get_idc()
        idautils = TestIDABridge.test_bridge.get_idautils()

        for segea in idautils.Segments():
            TestIDABridge.test_bridge.bridge.remote_eval(
                "[(funcea, idc.get_func_name(funcea)) for funcea in idautils.Functions(segea, idc.get_segm_end(segea))]",
                segea=segea,
                timeout_override=20,
            )

    def test_remote_eval_exception(self):
        """ Confirm that we can still get exceptions from the remote_eval after execute_sync """
        with self.assertRaises(jfx_bridge.bridge.BridgeException):
            TestIDABridge.test_bridge.bridge.remote_eval("1/0")

    def test_inheritance(self):
        """ Check we can inherit from an IDA object and override a method (e.g., __init__) which calls another IDA function (e.g., the parent __init__)
            without getting caught in an execute_sync deadlock """
        idaapi = TestIDABridge.test_bridge.get_idaapi()

        class TestListener(idaapi.UI_Hooks):
            called = False

            def __init__(self):
                idaapi.UI_Hooks.__init__(self)
                self.called = True

        t = TestListener()

        self.assertTrue(t.called)

    def test_callback(self):
        """ Test we can get a callback """
        idaapi = TestIDABridge.test_bridge.get_idaapi()

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

    def test_function_help(self):
        """ Check that we can view the function help """
        idaapi = TestIDABridge.test_bridge.get_idaapi()
        self.assertTrue("get_screen_ea()" in idaapi.get_screen_ea.__doc__)

    def test_type_instantiate(self):
        """ check we can instantiate an IDA type that isn't threadsafe in its init """
        idadex = TestIDABridge.test_bridge.remote_import("idadex")
        try:
            idadex.Dex()
        except Exception as e:  # idadex.Dex will except if not operating on a dex - only care about the main thread error
            self.assertTrue(
                "Function can be called from the main thread only" not in str(e)
            )

    def test_type_instantiate_inherited_but_non_overridden_init(self):
        """ check we can instantiate an type we've created from an IDA type that isn't threadsafe in its init, and we haven't overridden that init """
        idadex = TestIDABridge.test_bridge.remote_import("idadex")

        class TestDex(idadex.Dex):
            pass

        try:
            t = TestDex()
        except Exception as e:  # idadex.Dex will except if not operating on a dex - only care about the main thread error
            self.assertTrue(
                "Function can be called from the main thread only" not in str(e),
                "Original __init__ not running on main thread",
            )

    def test_type_instantiate_inherited_with_overridden_init(self):
        """ check we can instantiate an type we've created from an IDA type that isn't threadsafe in its init, we've overridden that init, but we're still calling it in our init """
        idadex = TestIDABridge.test_bridge.remote_import("idadex")

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
