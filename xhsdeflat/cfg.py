import intruction_mgr
from ins_helper import is_jmp, get_jmp_dest, is_jmp_no_ret
from xhsdeflat import is_not_use_block


def addr_in_blocks(addr, blocks):
    for b in blocks:
        if (b.start <= addr and b.end > addr):
            return True
        #
    #
    return False
#

class CodeBlock:

    def __init__(self, start=0, end=0):
        self.start = start
        self.end = end
        self.parent = set()
        self.childs = set()
    #

    def __repr__(self):
        return "CodeBlock(0x%08X, 0x%08X)"%(self.start, self.end)
    #

    def __lt__(self, others):
        return self.start < others.start
    #
    
#

#create cfg like ida
def create_cfg(f, base_addr, size, thumb):
    #thumb is same as IDA Atl+G
    ins_mgr = intruction_mgr.IntructionManger(thumb)
    block_starts_map = {}
    blocks = []
    f.seek(base_addr, 0)
    code_bytes = f.read(size)
    codes = ins_mgr.disasm(code_bytes, base_addr)
    m = 0
    
    cb = CodeBlock()
    cb.start = base_addr
    block_starts_map[base_addr] = cb
    blocks.append(cb)
    block_back_jump = set()
    cb_now = None
    # print (hex(base_addr))
    codeslist = []
    for i in codes:
        codeslist.append(i)
    #
    listlen = len(codeslist)
    skip_to_addr = -1
    for index in range(0, listlen):
        i = codeslist[index]
        addr = i.address
        if (skip_to_addr > addr):
            continue
        #
        if (addr in block_starts_map):
            if (cb_now != None and cb_now.end == 0):
                cb_now.end = addr
            #
            cb_now = block_starts_map[addr]
        #

        mne = i.mnemonic
        addr_this_ins_end = addr + i.size
        addr_next_ins = codeslist[index+1].address if index < listlen-1 else addr_this_ins_end

        # instruction_str = ''.join('{:02X} '.format(x) for x in i.bytes)
        # line = "[%16s]0x%08X:\t%s\t%s"%(instruction_str, addr, i.mnemonic.upper(), i.op_str.upper())
        # print (i.mnemonic)
        if (is_jmp(i)):
            #print("in")
            jmp_dest = get_jmp_dest(i)
            #跳转指令，需要获取跳转目标，以跳转目标为start新建block
            if (jmp_dest != None):
                cb_now.end = addr_this_ins_end
                child_start = jmp_dest
                #print ("target_block 0x%08X"%child_start)
                target_block = None
                if (child_start not in block_starts_map):
                    #print ("hhh %08X"%child_start)
                    target_block = CodeBlock()
                    target_block.start = child_start
                    block_starts_map[child_start] = target_block
                    blocks.append(target_block)
                    if (child_start < addr):
                        #print ("back jump 0x%08X to 0x%08X"%(addr, child_start))
                        block_back_jump.add(target_block)
                    #
                #
                else:
                    target_block = block_starts_map[child_start]
                #

                #print ("cb_now %r child %r"%(cb_now, target_block))
                cb_now.childs.add(target_block)
                #print(cb_now.childs)
                target_block.parent.add(cb_now)
            #
            elif (mne in ("tbb", "tbh", "tbb.w", "tbh.w")):
                assert index-2 > 0, "tbb/tbh list range not found..."
                code_cmp = codeslist[index-2]
                assert code_cmp.mnemonic == "cmp", "tbb/tbh list range not found..."
                op_str = code_cmp.op_str
                imm_id=op_str.find("#")
                ntable = int(op_str[imm_id+1:], 16)+1
                itemsz = 2 #tbh
                if (mne.startswith("tbb")):
                    itemsz = 1
                #
                cb_now.end = addr_this_ins_end
                assert i.op_str.find("pc")>-1, "table jump not by pc is not support now"
                for jmp_id in range(0, ntable):
                    f.seek(addr_this_ins_end + jmp_id * itemsz, 0)
                    jmp_off_b = f.read(itemsz)
                    jmp_off = int.from_bytes(jmp_off_b, byteorder='little')
                    dest = addr + 4 + jmp_off*2
                    #tbb/tbh only support forward jump
                    target_block = None
                    if (dest not in block_starts_map):
                        target_block = CodeBlock(dest, 0)                        
                        block_starts_map[dest] = target_block
                        blocks.append(target_block)
                    #
                    else:
                        target_block = block_starts_map[dest]
                    #
                    #print ("cb_now %r child %r"%(cb_now, target_block))
                    cb_now.childs.add(target_block)
                    #print(cb_now.childs)
                    target_block.parent.add(cb_now)
                #
                skip_to_addr = addr_this_ins_end + ntable * itemsz
                addr_next_ins = skip_to_addr
            #
            #print (mne + " " + i.op_str)
            if (addr_next_ins < base_addr + size):
                if (addr_next_ins not in block_starts_map):
                    next_block = CodeBlock()
                    next_block.start = addr_next_ins
                    block_starts_map[next_block.start] = next_block
                    blocks.append(next_block)
                #
            #
        #
        #print (hex(addr_next))
        if (addr_next_ins in block_starts_map):
            #print ("cb_now %r child %r"%(cb_now, next_block))
            #pop xxx, pc mov pc, xxx and so on
            #if it is not a no return jump , there will be two branch 
            if not is_jmp_no_ret(i):
                next_block = block_starts_map[addr_next_ins]
                next_block.parent.add(cb_now)
                cb_now.childs.add(next_block)
            #
        #
        if (i.size + addr >= base_addr + size):
            cb_now.end = i.size+addr
        #
    #
    blocks.sort()

    #修复因为有往回跳的指令而出现的block overlap问题
    for bjb in block_back_jump:
        print ("fix bjb:%r"%bjb)
        for b in blocks:
            if bjb == b:
                continue
            elif(b.start < bjb.start and b.end > bjb.start):
                assert(bjb.end == 0)

                bjb.end = b.end
                b.end = bjb.start
                bjb.childs.update(b.childs)
                b.childs.clear()
                b.childs.add(bjb)
                bjb.parent.add(b)

                print ("-new bjb:%r"%bjb)
                break
            #
        #
    #
    return blocks
#

def is_real_block(addr, real_block):
    for i in real_block:
        if addr in range(i.start, i.end):
            return i
    return None

def clean_bytes(f, addr_from, addr_to):
    f.seek(addr_from, 0)
    nleft = addr_to - addr_from
    assert nleft>=0
    for _ in range(0, nleft):
        b = bytearray([0])
        f.write(b)

def read_code(block):
    size = block.end - block.start
    f.seek(block.start, 0)
    ins_mgr = intruction_mgr.IntructionManger(1)
    code_bytes = f.read(size)
    codes = ins_mgr.disasm(code_bytes, block.start)
    codes_list = []
    for i in codes:
        codes_list.append(i)
    return codes_list




if (__name__ == "__main__"):
    path = 'libshield.so'
    base_addr = 0x0005CE60
    end_addr = 0x0005CF8A
    with  open(path, "rb") as f:
        c = create_cfg(f, base_addr, end_addr - base_addr, 1)

    count = 0
    f = open(path, 'rb')
    print(c)
    # 删除死循环部分
    real_block = []

    deal_list = c[len(c) - 1]
    c.remove(c[len(c) - 1])
    for i in c:
        if not is_not_use_block(f, i.start, i.end):
            real_block.append(i)
    print('真实块长度:', len(real_block))
    # 得到真实块， 根据trace文件得到执行流程。
    cf = []
    with open('xhs.trc', "r") as f:
        for line in f:
            line = line.strip()
            sa = line.split(":")
            start = sa[0].rfind("]") + 1
            addr = int(sa[0][start:], 16)
            addr = addr - 0x48E05000
            print(hex(addr))
            if len(cf) != 0 and addr in range(cf[len(cf) - 1].start, cf[len(cf) - 1].end):
                # 当前指令的真实块已保存，读吓一跳trace指令
                continue
            if is_real_block(addr, real_block):
                # 保存真实块的执行路径
                cf.append(is_real_block(addr, real_block))
    f = open(path, 'rb+')
    # 清除死循环， 单独处理
    f.seek(deal_list.start, 0)
    for _ in range(0, 2):
        b = bytearray([0])
        f.write(b)
    for i in c:
        if i not in real_block:
            # 代表虚假块
            print('虚假块:', i)
            clean_bytes(f, i.start, i.end)


    #
    # pathch, 连接真实块
    mgr = intruction_mgr.IntructionManger(True)
    for i in range(len(cf) - 1):
        asm_str = "b #0x%08x" % cf[i + 1].start
        bs = bytearray(mgr.asm(asm_str, cf[i].end - 2)[0])

        # 解析真实块指令
        f.seek(cf[i].start)
        code_bytes = f.read(cf[i].end - cf[i].start)
        codes = mgr.disasm(code_bytes, cf[i].start)
        codes_list = []
        for j in codes:
            codes_list.append(j)
        if codes_list[len(codes_list) - 1].mnemonic[0] != 'b':
            print(codes_list[len(codes_list) - 1].mnemonic)
            print("不填充的指令:", hex(cf[i].end))
            bs = bytearray(mgr.asm(asm_str, cf[i].end)[0])
            f.seek(cf[i].end)
        else:
            f.seek(cf[i].end - 2)
        print(asm_str, bs, hex(cf[i].end - 2))
        f.write(bs)
