import pwndbg
from pwndbg.dbg import EventType
import pwndbg.gdblib
import pwndbg.auxv
import gdb
import os
import json
import pwndbg.gdblib.vmmap
import threading
import time
def translate_offset(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.gdblib.vmmap.get()))


    first_page = min(pages, key=lambda page: page.vaddr)
    addr = offset - first_page.vaddr
    if not any(offset in p for p in pages):
        # print(
        #     "Offset 0x%x rebased to module %s as 0x%x is beyond module's "
        #     "memory pages:" % (addr, module, offset)
        # )
        # for p in pages:
        #     print(p)
        return 0

    return addr
def check_addr(addr, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.gdblib.vmmap.get()))
    first_page = min(pages, key=lambda page: page.vaddr)
    if not any(addr in p for p in pages):
        # print(
        #     "Offset 0x%x rebased to module %s as 0x%x is beyond module's "
        #     "memory pages:" % (addr, module, addr)
        # )
        # for p in pages:
        #     print(p)
        return False
    return True
def get_exe_name():
    """
    Returns exe name, tries AUXV first which should work fine on both
    local and remote (gdbserver, qemu gdbserver) targets.

    If the value is somehow not present in AUXV, we just fallback to
    local exe filepath.

    NOTE: This might be wrong for remote targets.
    """
    path = pwndbg.auxv.get().AT_EXECFN

    # When GDB is launched on a file that is a symlink to the target,
    # the AUXV's AT_EXECFN stores the absolute path of to the symlink.
    # On the other hand, the vmmap, if taken from /proc/pid/maps will contain
    # the absolute and real path of the binary (after symlinks).
    # And so we have to read this path here.
    real_path = pwndbg.gdblib.file.readlink(path)

    if real_path == "":  # the `path` was not a symlink
        real_path = path

    if real_path is not None:
        # We normalize the path as `AT_EXECFN` might contain e.g. './a.out'
        # so matching it against Page.objfile later on will be wrong;
        # We want just 'a.out'
        return os.path.normpath(real_path)

    return pwndbg.gdblib.proc.exe
def gdbsync():
    # file = open(".")
    prog = gdb.current_progspace()
    filename = ""
    file_path = ""
    bpt_file = {}
    # bpt_file_len = 0
    gdb_bpt = [ hex(translate_offset(b.locations[0].address, get_exe_name())) for b in gdb.breakpoints()]
    # print(gdb_bpt)
    if prog:
        file_path = prog.filename
    if file_path:
        filename = os.path.basename(file_path)
    if filename:
        debug_target = "." + filename + ".idbg"
        try:
            bpt_file = json.loads(open(debug_target, "r").read())
        except:
            pass
        # bpt_file_len = len(bpt_file)
        for item in bpt_file:
            if item not in gdb_bpt and bpt_file[item] == 1:
                gdb.execute(f"brva {item}", to_string=True)
        # print(f"debug_target: {debug_target}")
    for b in gdb.breakpoints():
        offset = hex(translate_offset(b.locations[0].address, get_exe_name()))
        # if offset not in bpt_file and offset in gdb_bpt:
        if offset in bpt_file and bpt_file[offset] == 0:
            b.delete()
    # for item in gdb.breakpoints():
    #     print(item.locations)



