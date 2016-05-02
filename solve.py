import capstone
import z3

with open('u','rb') as fd:
	rawdat = fd.read()
inst = rawdat[0x5bd:0x722]
ibase = 0x400000
vbase = 0x6042c0

s = z3.Solver()
reg = {}
'''
reg = { 'eax':0,
		'al' :0,
		'ecx':0,
		'cl' :0,
		'edx':0,
		'dl' :0,
		'esi':0,
		'sil':0,
		'edi':0,
		'dil':0,
		'r8d':0,
		'r8b':0 }
'''

def regular( r ):
	if r == 'al':
		return 'eax'
	if r == 'cl':
		return 'ecx'
	if r == 'dl':
		return 'edx'
	if r == 'sil':
		return 'esi'
	if r == 'dil':
		return 'edi'
	if r == 'r8b':
		return 'r8d'

vec = [z3.BitVec('BV{}'.format(n), 8) for n in range(0x43)]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for i in md.disasm(inst, 0x4005bd):
	#print "0x%x : %s\t%s"%(i.address, i.mnemonic, i.op_str)
	if i.mnemonic == 'call':
		caddr = int(i.op_str, 16)
		for ii in md.disasm(rawdat[caddr-ibase:], caddr):
			#print "\t0x%x : %s\t%s"%(ii.address, ii.mnemonic, ii.op_str)
			if ii.mnemonic == 'movzx':
				tareg = ii.op_str.strip().split(',')[0].strip()
				idx =  ii.address + ii.size
				idx += int(ii.op_str.strip().split('+')[1].strip()[:-1], 16)
				idx -= vbase
				reg[tareg] = vec[idx]
				#print idx
				continue
			if ii.mnemonic == 'add':
				oprand1 = ii.op_str.strip().split(',')[0].strip()
				oprand2 = ii.op_str.strip().split(',')[1].strip()
				reg[oprand1] = reg[oprand1] + reg[oprand2]
				#print ii.mnemonic, ' ', ii.op_str
				continue
			if ii.mnemonic == 'sub':
				oprand1 = ii.op_str.strip().split(',')[0].strip()
				oprand2 = ii.op_str.strip().split(',')[1].strip()
				reg[oprand1] = reg[oprand1] - reg[oprand2]
				#print ii.mnemonic, ' ', ii.op_str
				continue
			if ii.mnemonic == 'xor':
				oprand1 = ii.op_str.strip().split(',')[0].strip()
				oprand2 = ii.op_str.strip().split(',')[1].strip()
				reg[oprand1] = reg[oprand1] ^ reg[oprand2]
				#print ii.mnemonic, ' ', ii.op_str
				continue
			if ii.mnemonic == 'mov':
				oprand1 = ii.op_str.strip().split(',')[0].strip()
				oprand2 = ii.op_str.strip().split(',')[1].strip()
				reg[oprand1] = reg[oprand2]
				#print ii.mnemonic, ' ', ii.op_str
				continue
			if ii.mnemonic == 'cmp':
				oprand1 = regular(ii.op_str.strip().split(',')[0].strip())
				oprand2 = regular(ii.op_str.strip().split(',')[1].strip())
				s.add(reg[oprand1] == reg[oprand2])
				#print ii.mnemonic, ' ', ii.op_str
				continue
			if ii.mnemonic == 'ret' or ii.mnemonic == 'jne':
				break
			print ii.mnemonic

s.add(vec[0] == ord('C'))
s.add(vec[1] == ord('T'))
s.add(vec[2] == ord('F'))
s.add(vec[3] == ord('{'))
s.add(vec[0x42] == ord('}'))

for i in range(4, 0x42, 1):
	s.add(vec[i] > 0x21, vec[i] < 0x7e)

if s.check() == z3.sat:
	m = s.model()
	print [m.evaluate(vec[j]) for j in range(0x43)]
else:
	print "FAILED"
