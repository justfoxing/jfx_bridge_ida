import sys
import weakref
import pydoc

from jfx_bridge import bridge

from .server.jfx_bridge_ida_port import DEFAULT_SERVER_PORT

""" Use this list to exclude modules and names loaded by the remote jfx_bridge_ida side from being loaded into namespaces (they'll 
still be present in the BridgedObject for the __main__ module. This prevents the jfx_bridge_ida imported by jfx_bridge_ida_server 
being loaded over the local jfx_bridge_ida and causing issues. You probably only want this for stuff imported by the jfx_bridge_ida_server
script that might conflict on the local side (or which is totally unnecessary on the local side, like GhidraBridgeServer).
"""
EXCLUDED_REMOTE_IMPORTS = ["logging", "subprocess", "sys",
                           "jfx_bridge_ida", "bridge", "IDABridgeServer"]

class IDABridge():
    def __init__(self, connect_to_host=bridge.DEFAULT_HOST, connect_to_port=DEFAULT_SERVER_PORT, loglevel=None, namespace=None, interactive_mode=None, response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT):
        """ Set up a bridge. Default settings connect to the default ghidra bridge server,

        If namespace is specified (e.g., locals() or globals()), automatically calls get_flat_api() with that namespace. 

        loglevel for what logging messages you want to capture

        interactive_mode should auto-detect interactive environments (e.g., ipython or not in a script), but 
        you can force it to True or False if you need to. False is normal ghidra script behaviour 
        (currentAddress/getState() etc locked to the values when the script started. True is closer to the 
        behaviour in the Ghidra Jython shell - current*/getState() reflect the current values in the GUI

        response_timeout is how long to wait for a response before throwing an exception, in seconds
        """
        self.bridge = bridge.BridgeClient(
            connect_to_host=connect_to_host, connect_to_port=connect_to_port, loglevel=loglevel, response_timeout=response_timeout)

  

    def get_idaapi(self):
        """ get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script.
            Note that the module returned from get_flat_api() will also contain the ghidra module, so you may not need to call this.
        """
        idaapi = self.bridge.remote_import("idaapi")
        sys.modules["idaapi"] = idaapi
        return idaapi

    def get_idc(self):
        idc = self.bridge.remote_import("idc")
        sys.modules["idc"] = idc
        return idc

    def get_idautils(self):
        idautils = self.bridge.remote_import("idautils")
        sys.modules["idautils"] = idautils
        return idautils

