""" Run a jfx_bridge_ida client to remotely communicate with a jfx_bridge_ida server
running in an IDA instance """

import sys

from jfx_bridge import bridge

from .server.jfx_bridge_ida_port import DEFAULT_SERVER_PORT


class IDABridge(bridge.BridgeClient):
    idc = None
    idaapi = None
    idautils = None
    sark = None

    def __init__(
        self,
        connect_to_host=bridge.DEFAULT_HOST,
        connect_to_port=DEFAULT_SERVER_PORT,
        loglevel=None,
        response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT,
        do_import=True,
        hook_import=False,
    ):
        """ Set up a bridge. Default settings connect to the default jfx_bridge_ida server

        loglevel for what logging messages you want to capture

        response_timeout is how long to wait for a response before throwing an exception, in seconds
        
        If do_import is true, gets the remote idaapi, idc and idautils modules and loads them into sys.modules,
        to make importing sark locally easy
        
        Set hook_import to True to use the jfx_bridge import hooking feature and allow easy importing. This may cause issues
        with running multiple IDABridges in the same process.
        """
        super().__init__(
            connect_to_host=connect_to_host,
            connect_to_port=connect_to_port,
            loglevel=loglevel,
            response_timeout=response_timeout,
            hook_import=hook_import,
        )

        if do_import:
            self.get_idaapi(do_import=True)
            self.get_idc(do_import=True)
            self.get_idautils(do_import=True)

    def get_idaapi(self, do_import=False):
        """ Get the idaapi from the remote connection. 
        If do_import is true, store it into sys.modules so other things can import it easily
         - you probably don't want this, use do_import when setting up the bridge instead """
        if self.idaapi is None:
            self.idaapi = self.remote_import("idaapi")

        if do_import:
            sys.modules["idaapi"] = self.idaapi

        return self.idaapi

    def get_idc(self, do_import=False):
        """ Get the idc module from the remote connection. 
        If do_import is true, store it into sys.modules so other things can import it easily
        - you probably don't want this, use do_import when setting up the bridge instead """
        if self.idc is None:
            self.idc = self.remote_import("idc")

        if do_import:
            sys.modules["idc"] = self.idc

        return self.idc

    def get_idautils(self, do_import=False):
        """ Get the idautils module from the remote connection. 
        If do_import is true, store it into sys.modules so other things can import it easily
        - you probably don't want this, use do_import when setting up the bridge instead """
        if self.idautils is None:
            self.idautils = self.remote_import("idautils")

        if do_import:
            sys.modules["idautils"] = self.idautils

        return self.idautils

    def get_sark(self, do_import=False):
        """ Import sark from the remote IDA context 
            If do_import is true, store it into sys.modules so other things can import it easily - you probably don't want this """
        if self.sark is None:
            self.sark = self.remote_import("sark")

        if do_import:
            sys.modules["sark"] = self.sark

        return self.sark
