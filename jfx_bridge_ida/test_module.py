""" Module purely for testing that we can remoteify a module, and that when the elements in the module are called, they don't have execute_sync problems  """

idaapi = None
try:
    import idaapi

    EA_AT_IMPORT = idaapi.get_screen_ea()
except ImportError:
    pass


def run():
    return idaapi.get_imagebase()


class TestingClass:
    def __init__(self):
        self.ea = idaapi.get_screen_ea()
