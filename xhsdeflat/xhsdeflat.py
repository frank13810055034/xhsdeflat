from intruction_mgr import IntructionManger


def is_not_use_block(f, base, end):
    # 特征匹配，获取虚假块
    size = end - base
    f.seek(base, 0)
    ins_mgr = IntructionManger(1)
    code_bytes = f.read(size)
    codes = ins_mgr.disasm(code_bytes, base)
    codes_list = []
    for i in codes:
        codes_list.append(i)
    if len(codes_list) == 4:
        if codes_list[0].mnemonic == 'movw' and codes_list[1].mnemonic == 'movt' and codes[2].mnemonic == 'cmp' \
                and (codes_list[3].mnemonic[0] == 'b' and codes_list[3].mnemonic not in ("b", "bl", "blx", "bic", "bics")):
            return True
    if len(codes_list) == 2:
        if codes_list[0].mnemonic == 'cmp' \
                and (codes_list[1].mnemonic[0] == 'b' and codes_list[1].mnemonic not in ("b", "bl", "blx", "bic", "bics")):
            return True
    if len(codes_list) == 5:
        if codes_list[0].mnemonic == 'movw' and codes_list[1].mnemonic == 'movt' and codes[2].mnemonic == 'cmp' and codes[3].mnemonic == 'mov' \
                and (codes_list[4].mnemonic[0] == 'b' and codes_list[4].mnemonic not in ("b", "bl", "blx", "bic", "bics")):
            return True
    if len(codes_list) == 3:
        if codes_list[0].mnemonic == 'cmp' and codes_list[1].mnemonic == 'mov' \
                and (codes_list[2].mnemonic[0] == 'b' and codes_list[2].mnemonic not in ("b", "bl", "blx", "bic", "bics")):
            return True
    if len(codes_list) == 3:
        if codes_list[0].mnemonic == 'mov' and codes_list[1].mnemonic == 'cmp' \
                and (
                codes_list[2].mnemonic[0] == 'b' and codes_list[2].mnemonic not in ("b", "bl", "blx", "bic", "bics")):
            return True
    return False

