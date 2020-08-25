JFX Bridge for IDA (IDABridge)
=====================
IDA's a great reverse engineering tool, and I like scripting my RE as much as possible.

IDABridge is a Python RPC bridge that aims to break you out of the IDA Python environment, so you can more easily integrate with tools like IPython and Jupyter, while being as transparent as possible so you don't have to rewrite all of your scripts.

If you like this, you might also be interested in the equivalents for other reverse-engineering tools:
* [ghidra_bridge](https://github.com/justfoxing/ghidra_bridge) for Ghidra [![ghidra_bridge PyPi version](https://img.shields.io/pypi/v/ghidra_bridge.svg)](https://pypi.org/project/ghidra-bridge/)
* [jfx_bridge_jeb](https://github.com/justfoxing/jfx_bridge_jeb) for JEB Decompiler [![jfx_bridge_jeb PyPi version](https://img.shields.io/pypi/v/jfx_bridge_jeb.svg)](https://pypi.org/project/jfx-bridge-jeb/)

Table of contents
======================
* [How to use for IDA](#how-to-use-for-ida)
* [Security warning](#security-warning)
* [Remote eval](#remote-eval)
* [Long-running commands](#long-running-commands)
* [Remote imports](#remote-imports)
* [Thread safety, callbacks and avoiding blocking](#thread-safety-callbacks-and-avoiding-blocking)
* [How it works](#how-it-works)
* [Tested](#tested)
* [Contributors](#contributors)

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
IDABridge is designed to be transparent, to allow easy porting of non-bridged scripts without too many changes. However, if you're happy to make changes, and you run into slowdowns caused by running lots of remote queries (e.g., something like `for f in sark.functions(): doSomething()` can be quite slow with a large number of functions as each function will result in a message across the bridge), you can make use of the remote_eval() function to ask for the result to be evaluated on the bridge server all at once, which will require only a single message roundtrip.

The following example demonstrates getting a list of all the names of all the functions in a binary:
```python
import jfx_bridge_ida 
b = jfx_bridge_ida.IDABridge()
name_list = b.remote_eval("[f.name for f in sark.functions()]")
```

If your evaluation is going to take some time, you might need to use the timeout_override argument to increase how long the bridge will wait before deciding things have gone wrong.

If you need to supply an argument for the remote evaluation, you can provide arbitrary keyword arguments to the remote_eval function which will be passed into the evaluation context as local variables. The following argument passes in a function:
```python
import jfx_bridge_ida 
b = jfx_bridge_ida.IDABridge()
func = b.get_sark().Function()
calls_list = b.remote_eval("[sark.Function(x.to).name for x in f.xrefs_from]", f=func)
```
As a simplification, note also that the evaluation context has the same globals loaded into the \_\_main\_\_ of the script that started the server - in the case of the IDABridge server, these include the idaapi, idautils and idc module, and sark if it was installed when the server was started.

Long-running commands
=====================
If you have a particularly slow call in your script, it may hit the response timeout that the bridge uses to make sure the connection hasn't broken. If this happens, you'll see something like `Exception: Didn't receive response <UUID> before timeout`.

There are two options to increase the timeout. When creating the bridge, you can set a timeout value in seconds with the response_timeout argument (e.g., `b = jfx_bridge_ida.IDABridge(response_timeout=20)`) which will apply to all commands run across the bridge. Alternatively, if you just want to change the timeout for one command, you can use remote_eval as mentioned above, with the timeout_override argument (e.g., `b.remote_eval("[f.name for f in sark.functions()]", timeout_override=20)`). If you use the value -1 for either of these arguments, the response timeout will be disabled and the bridge will wait forever for your response to come back - note that this can cause your script to hang if the bridge runs into problems.

Remote imports
=====================
If you want to import modules from the IDA-side, you have a range of options (in order of most-recommended to least):
* If you're using one of the main IDA api modules (idaapi, idautils, idc, sark), by default IDABridge grabs thes from the remote-side and copies them into sys.modules when the IDABridge is created, so you can do `import idaapi` after the bridge is created. If that causes problems, you can disable that functionality with the do_import argument when the bridge is created (e.g., `b = jfx_bridge_ida.IDABridge(do_import=False)`.
* Alternatively, if you're using one of the main IDA api modules and you don't want to use the import functionality, IDABridge provides get functions for these (e.g., `idaapi = b.get_idaapi()`). You can also specify do_import=True on these get functions to embed the modules into sys.modules and allow importing as above for that specific module.
* If you're not after one of the main IDA modules (e.g., you want something like ida_kernwin), you can use remote_import to get a BridgedModule back directly (e.g., `ida_kernwin = b.remote_import("ida_kernwin")`). This has the advantage that you have exact control over getting the remote module (and can get remote modules with the same name as local modules) and when it's released, but it does take a little more work than the following method.
* Alternatively, you can specify hook_import=True when creating the bridge (e.g., `b = jfx_bridge_ida.IDABridge(hook_import=True)`). This will add a hook to the import machinery such that, if nothing else can fill the import, the bridge will try to handle it. This allows you to just use the standard `from ida_kernwin import get_screen_ea` syntax after you've connected the bridge. This has the advantage that it may be a little easier to use (you still have to make sure the imports happen AFTER the bridge is connected), but it doesn't allow you to import remote modules with the same name as local modules (the local imports take precedence) and it places the remote modules in sys.modules as proper imports, so they and the bridge will likely stay loaded until the process terminates. Additionally, multiple bridges with hook_import=True will attempt to resolve imports in the order they were connected, which may not be the behaviour you want.

Thread safety, callbacks and avoiding blocking
=====================
As of IDA 7.2, all APIs not explicitly marked THREAD_SAFE have to be called from the main thread in IDA. If they aren't, IDA throws a `RuntimeError: Function can be called from the main thread only`. 

However, the IDABridge server can't run on the main thread, or you wouldn't be able to use IDA while it was running. To handle this, we inspect call commands being sent over the bridge to see if they refer to IDA APIs. If they do, they're wrapped in the IDA execute_sync() function, which will ship them off to the main thread. All remote_eval and remote_exec commands and calls to remoteify-ed objects are also shipped to the main thread - it's too hard to inspect them to see if they use IDA APIs, so we just assume they all do.

All of this should happen transparently, so you shouldn't need to make any changes to your code - with one exception. If your local code is being called from IDA over the bridge (e.g., you've subclassed idaapi.UI_Hooks and overridden the screen_ea_changed() function to get callbacks when the visible address changes), you MUST allow that call to return BEFORE you call another IDA function. 

This is because IDA will call your local code from the main thread, then block waiting for a response. If your local code then attempts to call an IDA function over the bridge, it will need to get on the main thread to do so - but the main thread is still held by IDA code that called you. This will lead to a `Didn't receive response <UUID> before timeout` exception. 

If you need to call an IDA function, trigger a different thread to do it and allow the original call to return quickly. Using a different thread is also recommended if you need to pause and ask the user for something or do some intensive computation. Generally, the best practice is return calls from IDA as quickly as possible - the main thread is also responsible for the IDA UI, so if it's spending a lot of time waiting for responses across the bridge, the UI will be slow or unusable.

Note that this doesn't apply to local \_\_init\_\_ code on a class that inherits from an IDA class - the bridge recognises the \_\_\_init\_\_ will run on the non-IDA side. So the following will work fine:
```python
class X(idaapi.UI_Hooks): 
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
```

Finally, the call inspection logic is pretty gnarly, so it's possible that something has been missed. If you see a `RuntimeError: Function can be called from the main thread only` when you do a call, please open an issue on Github with the code that causes it so we can get it fixed.

How it works
=====================
The actual bridge RPC code is implemented in [jfx-bridge](https://github.com/justfoxing/jfx_bridge/). Check it out there and file non-IDA specific issues related to the bridge there.

Tested
=====================
* IDA 7.4/Windows/Python 3.7.3->Python 3.7.3
* IDA 7.2/Linux/Python 2.7.17->Python 3.7.2
* IDA 6.9/Windows/Python 2.7.17->Python 3.7.2


Contributors
=====================
* Thx @fmagin for better iPython support, and much more useful reprs!
* Thanks also to @fmagin for remote_eval, allowing faster remote processing for batch queries!
