JFX Bridge for IDA (IDABridge)
=====================
IDA's a great reverse engineering tool, and I like scripting my RE as much as possible.

Like [Ghidra Bridge](https://github.com/justfoxing/ghidra_bridge/), IDABridge is a Python RPC bridge that aims to break you out of the IDA Python environment, so you can more easily integrate with tools like IPython and Jupyter, while being as transparent as possible so you don't have to rewrite all of your scripts.

How to use for IDA
======================

## Install the jfx_bridge_ida package and server scripts
1. Install the jfx_bridge_ida package (packaged at https://pypi.org/project/jfx-bridge-ida/):
```
pip install jfx_bridge_ida
```

2. Install the server scripts to a directory you'll load in IDA.
```
python -m jfx_bridge_ida.install_server ~/.ida_scripts
```

3. If you're using IDA with a different python environment (e.g., using python2), install the jfx-bridge package into that python environment. That'll look something like the following:
```
python2 -m pip install jfx_bridge
```

## Start Server
### IDA Context

1. Open File->Script file... <Alt-F7>
2. Navigate to where you installed the server scripts
3. Run jfx_bridge_ida_server.py


## Setup Client
From the client python environment:
```python
import jfx_bridge_ida

b = jfx_bridge_ida.IDABridge()

idaapi = b.get_idaapi()
idc = b.get_idc()
idautils = b.get_idautils()

print(idc.ScreenEA())

# or use the sark module for easier scripting! Remember to install sark in the IDA python environment
sark = b.get_sark()
print(sark.Line())
```

Security warning
=====================
Be aware that when running, an IDABridge server effectively provides code execution as a service. If an attacker is able to talk to the port the bridge server is running on, they can trivially gain execution with the privileges IDA is run with. 

Also be aware that the protocol used for sending and receiving bridge messages is unencrypted and unverified - a person-in-the-middle attack would allow complete control of the commands and responses, again providing trivial code execution on the server (and with a little more work, on the client). 

By default, the server only listens on localhost to slightly reduce the attack surface. Only listen on external network addresses if you're confident you're on a network where it is safe to do so. Additionally, it is still possible for attackers to send messages to localhost (e.g., via malicious javascript in the browser, or by exploiting a different process and attacking the bridge to elevate privileges). You can mitigate this risk by running the bridge server from a IDA process with reduced permissions (a non-admin user, or inside a container), by only running it when needed, or by running on non-network connected systems.

Remote eval
=====================
IDABridge is designed to be transparent, to allow easy porting of non-bridged scripts without too many changes. However, if you're happy to make changes, and you run into slowdowns caused by running lots of remote queries (e.g., something like `for f in sark.functions(): doSomething()` can be quite slow with a large number of functions as each function will result in a message across the bridge), you can make use of the bridge.remote_eval() function to ask for the result to be evaluated on the bridge server all at once, which will require only a single message roundtrip.

The following example demonstrates getting a list of all the names of all the functions in a binary:
```python
import jfx_bridge_ida 
b = jfx_bridge_ida.IDABridge(namespace=globals())
name_list = b.bridge.remote_eval("[ f.name for f in sark.functions()]")
```

If your evaluation is going to take some time, you might need to use the timeout_override argument to increase how long the bridge will wait before deciding things have gone wrong.

If you need to supply an argument for the remote evaluation, you can provide arbitrary keyword arguments to the remote_eval function which will be passed into the evaluation context as local variables. The following argument passes in a function:
```python
import jfx_bridge_ida 
b = jfx_bridge_ida.IDABridge(namespace=globals())
func = b.get_sark().Function()
calls_list = b.bridge.remote_eval("[ sark.Function(x.to).name for x in f.xrefs_from ]", f=func)
```
As a simplification, note also that the evaluation context has the same globals loaded into the \_\_main\_\_ of the script that started the server - in the case of the IDABridge server, these include the idaapi, idautils and idc module, and sark if it was installed when the server was started.

How it works
=====================
The actual bridge RPC code is implemented in [jfx-bridge](https://github.com/justfoxing/jfx_bridge/). Check it out there and file non-IDA specific issues related to the bridge there.

Tested
=====================
* IDA 6.9/Windows/Python 2.7.17->Python 3.7.2
* IDA 7.2/Linux/2.7.17->Python 3.7.2

Contributors
=====================
* Thx @fmagin for better iPython support, and much more useful reprs!
* Thanks also to @fmagin for remote_eval, allowing faster remote processing for batch queries!
