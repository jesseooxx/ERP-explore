
# IDA Python Script - Analyze nrp32.exe
import idaapi
import idc
import idautils

print("="*70)
print("IDA Auto-Analysis: nrp32.exe")
print("="*70)

# Find SetMapMode calls
for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)

    if 'SetMapMode' in func_name or 'TextOut' in func_name:
        print(f"\nFunction: {func_name} @ 0x{func_ea:08X}")

        # Find all xrefs
        for xref in idautils.XrefsTo(func_ea):
            if xref.type == idaapi.fl_CN or xref.type == idaapi.fl_CF:
                call_addr = xref.frm
                print(f"  Called from: 0x{call_addr:08X}")

                # Print instructions before call
                addr = idc.prev_head(call_addr, 20)
                for i in range(10):
                    if addr >= call_addr:
                        break
                    print(f"    0x{addr:08X}: {idc.GetDisasm(addr)}")
                    addr = idc.next_head(addr)

# Find constants
print("\n" + "="*70)
print("Constant Search")
print("="*70)

constants = [900, 1200, 595, 842, 72, 254]
for const in constants:
    ea = idc.find_imm(0, idaapi.SEARCH_DOWN, const)
    if ea != idaapi.BADADDR:
        print(f"  Found {const} @ 0x{ea:08X}")
