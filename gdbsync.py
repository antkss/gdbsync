import ida_dbg
import idaapi
import ida_nalt
import idc
import json
bpt_file = {}
len_bpt_file = 0
target_file = ""
target_ida_debug = ""
try:
    target_file = idaapi.get_root_filename()
    target_ida_debug = "." + idaapi.get_root_filename() + ".idbg"
except:
    pass
def list_all_breakpoints() -> list:
    """
    Iterates through all breakpoints and prints their properties.
    """
    print("--- Listing All Breakpoints ---")
    # Get the total number of breakpoints
    bpt_qty = ida_dbg.get_bpt_qty()
    print(f"Found {bpt_qty} breakpoint(s):\n")
    bpt_list = []
    for i in range(bpt_qty):
        bpt = idaapi.bpt_t()  # Create a breakpoint object to store the details
        if not ida_dbg.getn_bpt(i, bpt):
            print(f"Warning: Could not retrieve breakpoint at index {i}")
            continue
        bpt_list.append(bpt)
    return bpt_list
def remove_bpt(addr):
    try:
        bpt_file[addr] = 0
    except:
        pass
def add_bookmark(offset, comment, check_duplicate=True):
        """
        :param offset:
        :param comment:
        :param check_duplicate:
        :return:
        """
        for bslot in range(0, 1024, 1):
            slotval = idc.get_bookmark(bslot)
            if check_duplicate:
                if slotval == offset:
                    break

            if slotval == 0xffffffffffffffff:
                idc.put_bookmark(offset, 0, 0, 0, bslot, comment)
                break
def remove_bookmark(offset):
    for bslot in range(0, 1024, 1):
        slotval = idc.get_bookmark(bslot)
        if slotval == offset:
            idc.put_bookmark(0, 0, 0, 0, bslot, "")
            return
def diff_breakpoint():
    global bpt_file
    global len_bpt_file
    print("checking breakpoint ...")
    if target_ida_debug:
        try: 
            bpt_file = json.loads(open(target_ida_debug, "r").read())
        except:
            pass
    len_bpt_file = len(bpt_file)
    image_base = ida_nalt.get_imagebase()   
    bpt_all = parse_address(list_all_breakpoints())
    for item in bpt_file:
        if item not in bpt_all and bpt_file[item] == 1:
            ida_dbg.add_bpt(eval(item) + image_base, 0, idaapi.BPT_SOFT)
            add_bookmark(eval(item) + image_base, item)
        elif bpt_file[item] == 0:
            ida_dbg.del_bpt(eval(item) + image_base)
            remove_bookmark(eval(item) + image_base)
    print(f"File Name: {target_ida_debug}")
    print("setting up hook... ")       

# --- Run the function ---
class MyDbgHook(idaapi.DBG_Hooks):
    def dbg_bpt_changed(self, bptev_code: int, bpt) ->None:
        print("breakpoint changed... \n")
        print("checking breakpoint ...")
        # print(f"bpt: {bpt.loc.ea()}")
        image_base = ida_nalt.get_imagebase()   
        addr = hex(bpt.ea - image_base)
        is_enabled = bpt.flags & idaapi.BPT_ENABLED
        if eval(addr) > 0:
            if addr in bpt_file:
                if bpt_file[addr] == 0:
                    bpt_file[addr] = 1
                    add_bookmark(bpt.ea, addr)
                elif is_enabled:
                    if bpt_file[addr] == 1:
                        remove_bpt(addr)
                        remove_bookmark(bpt.ea)
            else:
               bpt_file[addr] = 1
               add_bookmark(bpt.ea, addr)               
        if target_ida_debug:
            print("written breakpoints")
            open(target_ida_debug, "w").write(json.dumps(bpt_file))
        print(f"target: {target_ida_debug}")
        print(f"{bpt_file = }")
        print(f"current_change: {hex(bpt.ea)}")
def diff_list(list_a, list_b):
    set_a = set(list_a)
    set_b = set(list_b)
    result_set = set_a ^ set_b
    return list(result_set)
def parse_address(bpt) -> dict:
    image_base = ida_nalt.get_imagebase()   
    list_item = {}
    for item in bpt:
        is_enabled = item.flags & idaapi.BPT_ENABLED
        if is_enabled:
            list_item[hex(item.ea - image_base)] = 1
    return list_item

class GdbSyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "GdbSync"
    help = "GdbSync"
    wanted_name = "GdbSync"
    wanted_hotkey = ""
    def init(self):
        diff_breakpoint()


mydbghook = MyDbgHook()
mydbghook.hook()
def PLUGIN_ENTRY():
    return GdbSyncPlugin()
