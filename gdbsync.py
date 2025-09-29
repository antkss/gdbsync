import ida_dbg
import idaapi
import ida_nalt
import idc
import json
bpt_file = {}
target_file = ""
target_ida_debug = ""
try:
    target_file = idaapi.get_root_filename()
    target_ida_debug = "." + target_file + ".idbg"
except:
    pass
def check_pie(path):
    if path:
        with open(path, "rb") as f:
            f.seek(16)   # skip to e_type field in ELF header
            e_type = int.from_bytes(f.read(2), "little")
            if e_type == 3:   # ET_DYN
                return True
            elif e_type == 2: # ET_EXEC
                return False
            else:
                return None
    else:
        return None

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
    print("checking breakpoint ...")
    if target_ida_debug:
        try: 
            bpt_file = json.loads(open(target_ida_debug, "r").read())
        except:
            pass
    image_base = ida_nalt.get_imagebase()   
    bpt_all = parse_address(list_all_breakpoints())
    is_pie = check_pie(target_file)
    print(f"target_file: {target_file}")
    if is_pie == None:
        print("can't check pie")
    if is_pie:
        for item in bpt_file:
            if item not in bpt_all and bpt_file[item] == 1:
                ida_dbg.add_bpt(eval(item) + image_base, 0, idaapi.BPT_SOFT)
                add_bookmark(eval(item) + image_base, item)
            elif bpt_file[item] == 0:
                ida_dbg.del_bpt(eval(item) + image_base)
                remove_bookmark(eval(item) + image_base)
    else:
        for item in bpt_file:
            if item not in bpt_all and bpt_file[item] == 1:
                ida_dbg.add_bpt(eval(item), 0, idaapi.BPT_SOFT)
                add_bookmark(eval(item), item)
            elif bpt_file[item] == 0:
                ida_dbg.del_bpt(eval(item))
                remove_bookmark(eval(item))
    print(f"File Name: {target_ida_debug}")
    print("setting up hook... ")       

# --- Run the function ---
class MyDbgHook(idaapi.DBG_Hooks):
    def dbg_bpt_changed(self, bptev_code: int, bpt) ->None:
        print("breakpoint changed... \n")
        print("checking breakpoint ...")
        # print(f"bpt: {bpt.loc.ea()}")
        is_pie = check_pie(target_file)
        image_base = ida_nalt.get_imagebase()   
        is_exist = ida_dbg.exist_bpt(bpt.ea)
        addr = 0
        if is_pie:
            addr = hex(bpt.ea - image_base)
        else:
            addr = hex(bpt.ea)
        if eval(addr) > 0:
           if is_exist:
               bpt_file[addr] = 1
               add_bookmark(bpt.ea, addr)               
           else:
               bpt_file[addr] = 0
               remove_bookmark(bpt.ea)
        if target_ida_debug:
            print("written breakpoints")
            open(target_ida_debug, "w").write(json.dumps(bpt_file))
        # print(f"target: {target_ida_debug}")
        # print(f"{bpt_file = }")
        # print(f"is enabled: {is_exist}")
        # print(f"current_change: {hex(bpt.ea)}")
def diff_list(list_a, list_b):
    set_a = set(list_a)
    set_b = set(list_b)
    result_set = set_a ^ set_b
    return list(result_set)
def parse_address(bpt) -> dict:
    image_base = ida_nalt.get_imagebase()   
    is_pie = check_pie(target_file)
    list_item = {}
    for item in bpt:
        is_enabled = item.flags & idaapi.BPT_ENABLED
        address = 0
        if is_pie:
            address = item.ea - image_base
        else:
            address = item.ea
        if is_enabled:
            list_item[hex(address)] = 1
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
