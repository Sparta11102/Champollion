import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm64_decode import Arm64Decoder

dec = Arm64Decoder()

# Test MOVZ (0x12800000 with opc=0 -> sf=0)
r = dec.decode(0x12800000, bytes([0x00, 0x00, 0x20, 0x12]))
print(f"MOVZ w0, #0: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test MOVZ x0, #0 (sf=1)
r = dec.decode(0x92800000, bytes([0x00, 0x00, 0x20, 0x92]))
print(f"MOVZ x0, #0: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test ADD w0, w1, w2
r = dec.decode(0x12818800, bytes([0x00, 0x88, 0x01, 0x12]))
print(f"ADD w0, w1, w2: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test ADD x0, x1, x2
r = dec.decode(0x92818800, bytes([0x00, 0x88, 0x01, 0x92]))
print(f"ADD x0, x1, x2: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test SUBS
r = dec.decode(0x92C18800, bytes([0x00, 0x88, 0x01, 0x92]))
print(f"SUBS: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test AND logical
r = dec.decode(0x12018800, bytes([0x00, 0x88, 0x01, 0x12]))
print(f"AND: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test CMP
r = dec.decode(0x53018800, bytes([0x00, 0x88, 0x01, 0x53]))
print(f"CMP: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

# Test CBZ
r = dec.decode(0xB4000000, bytes([0x00, 0x00, 0x00, 0xB4]))
print(f"CBZ: mnemonic={r.inst.mnemonic}, operands={r.inst.operands}")

print("\nAll basic tests done")