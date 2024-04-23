"""
IDA Pro Plugin to import /proc/kallsyms
"""

import ida_kernwin
import idaapi
import ida_name
import idautils
import idc

PLUG_NAME = "import-kallsyms"

class ImportFilePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Import /proc/kallsyms for the kernel"
    help = f"Select '{PLUG_NAME}' from the File menu"
    wanted_name = PLUG_NAME
    wanted_hotkey = ""

    def init(self):
        """ Initialize the plugin """
        self.menu_context = None
        return idaapi.PLUGIN_OK

    def term(self):
        """ Terminate the plugin """
        if self.menu_context is not None:
            idaapi.del_menu_item(self.menu_context)

    def run(self, arg):
        """ Execute the plugin """
        # Ask the user for the file path
        file_path = ida_kernwin.ask_file(0, "*.*", "Select a file to import")
        if file_path:
            func_dict = {}
            fp = open(file_path, "r")
            for line in fp.readlines():
                content = line.strip()
                if content:
                    # Split "ffffffff81000000 T _text"
                    items = content.split(' ')
                    address = int(items[0], 16)
                    name = items[2]
                    func_dict[address] = name
            fp.close()

            for func_address in idautils.Functions():
                if func_address in func_dict:
                    ida_name.set_name(func_address, func_dict[func_address], ida_name.SN_NOWARN)

            print(f"[{PLUG_NAME}] Import kallsyms successfully.")

    def add_menu_item(self):
        """ Add menu item to the File menu """
        self.menu_context = idaapi.add_menu_item("File/", "Import /proc/kallsyms", "", 0, self.run, (None,))

# Register the plugin with IDA Pro
def PLUGIN_ENTRY():
    return ImportFilePlugin()
