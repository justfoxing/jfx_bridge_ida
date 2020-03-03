""" Shutdown a running jfx_bridge_ida server cleanly """

from jfx_bridge import bridge
from jfx_bridge_ida_port import DEFAULT_SERVER_PORT

if __name__ == "__main__":
    print("Requesting server shutdown")
    client = bridge.BridgeClient(
        connect_to_host="127.0.0.1", connect_to_port=DEFAULT_SERVER_PORT
    )

    print(client.remote_shutdown())
