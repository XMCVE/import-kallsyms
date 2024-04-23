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
    comment = "Import /proc/kallsyms for Linux Kernel"
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = ""

    def init(self):
        """ Initialize the plugin """
        return idaapi.PLUGIN_OK

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

# Register the plugin with IDA Pro
def PLUGIN_ENTRY():
    return ImportFilePlugin()
