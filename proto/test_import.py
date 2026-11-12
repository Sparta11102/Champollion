import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macho
print("macho module OK")
print("MH_MAGIC_64 = %s" % hex(macho.MH_MAGIC_64))
print("CPU_TYPE_ARM64 = %s" % hex(macho.CPU_TYPE_ARM64))
print("LC_SEGMENT_64 = %s" % hex(macho.LC_SEGMENT_64))
print("VM_PROT_EXEC = %s" % hex(macho.VM_PROT_EXEC))
print("All constants importable")
