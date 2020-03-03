""" Handle installing the jfx_bridge_ida server scripts to a specified directory.

    Note: we don't install the jfx_bridge module itself - pip install that into the python used by your IDA manually
"""
import argparse
import os
import pkg_resources

JFX_BRIDGE = "jfx_bridge"
IDA_BRIDGE = "jfx_bridge_ida"
SERVER_DIR = "server"


def do_install(install_dir):
    if not os.path.isdir(install_dir):
        os.makedirs(install_dir)

    # list the files from jfx_bridge_ida server directory
    server_files = [
        f
        for f in pkg_resources.resource_listdir(IDA_BRIDGE, SERVER_DIR)
        if f not in ["__init__.py", "__pycache__"]
    ]

    print("Installing jfx_bridge_ida server scripts...")

    # write out the jfx_bridge_ida server files directly in the install dir
    for f in server_files:
        dest_path = os.path.join(install_dir, f)
        with pkg_resources.resource_stream(
            IDA_BRIDGE, SERVER_DIR + "/" + f
        ) as resource:
            with open(dest_path, "wb") as dest:
                print("\t" + dest_path)
                dest.write(resource.read())

    print("Install completed")
    print(
        "!! If your IDA is using a different python instance to this one, remember to pip install jfx-bridge in that python instance !!"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Install jfx_bridge_ida server scripts"
    )
    parser.add_argument(
        "install_dir",
        help="A directory where you want to store scripts to run from IDA",
    )

    args = parser.parse_args()

    do_install(args.install_dir)
