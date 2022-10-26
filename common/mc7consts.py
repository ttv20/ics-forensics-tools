def get_val_def(dict_from, val):
    if val in dict_from:
        return dict_from[val]
    else:
        return 'Attribute ID %s' % hex(val)

BLOCK_ATTRIBUTE = {0: 'Unlinked',
                   1: 'Linked',
                   2: 'Standard block',
                   3: 'Standard block, Linked',
                   4: '',
                   8: 'Know-how protection',
                   9: 'Know-how protection, Linked',
                   32: 'Non Retain',
                   64: 'Safety block'
                   }

BLOCK_LANGUAGE = {1: 'AWL',
                  2: 'KOP',
                  3: 'FUP',
                  4: 'SCL',
                  5: 'DB',
                  6: 'GRAPH',
                  7: 'SDB',
                  8: 'CPU-DB'}

BLOCK_TYPE = {0x08: 'OB',
              0x0A: 'DB',
              0x0B: 'SDB',
              0x0C: 'FC',
              0x0D: 'SFC',
              0x0E: 'FB',
              0x0F: 'SFB'}

UNSUPPORTED_BLOCK_TYPE = {0x00: 'UDT',
              0x1B: 'VAT'}


BLOCK_TYPE_STR = {
    'OB': 'OrganisationBlock',
    'DB': 'DataBlock',
    'SDB': 'SystemDataBlock',
    'FC': 'FunctionCode',
    'SFC': 'SystemFunctionCode',
    'FB': 'SystemBlock',
    'SFB': 'SystemFunctionBlock',
    'UDT': 'UserDefinedDataType',
    'VAT': 'VariableTable'
}

PARAMETERS_TYPE = {0x01: 'IN',
                   0x02: 'OUT',
                   0x03: 'IN_OUT',
                   0x04: 'STATIC',
                   0x05: 'TEMP',
                   0x06: 'RET',
                   0x09: 'IN_Init',
                   0x0A: 'OUT_Init',
                   0x0B: 'IN_OUT_Init',
                   0x0C: 'STATIC_Init',
                   0x11: 'IN_Ex',
                   0x12: 'OUT_Ex',
                   0x13: 'IN_OUT_Ex',
                   0x14: 'STATIC_Ex',
                   0x15: 'TEMP_Ex',
                   0x16: 'RET_Ex',
                   0x19: 'IN_Ex_Init',
                   0x1A: 'OUT_Ex_Init',
                   0x1B: 'IN_OUT_Ex_Init',
                   0x1C: 'STATIC_Ex_Init'}

DATA_BLOCK_PARAMS_TYPE = {0x00: 'NULL',
                          0x01: 'BOOL',
                          0x02: 'BYTE',
                          0x03: 'CHAR',
                          0x04: 'WORD',
                          0x05: 'INT',
                          0x06: 'DWORD',
                          0x07: 'DINT',
                          0x08: 'REAL',
                          0x09: 'DATE',
                          0x0A: 'TIME_OF_DAY',
                          0x0b: 'TIME',
                          0x0c: 'S5TIME',
                          0x0e: 'DATE_AND_TIME',
                          0x10: 'ARRAY',
                          0x11: 'STRUCT',
                          0x13: 'STRING',
                          0x14: 'POINTER',
                          0x15: 'STATIC_FB_MultiInstace',
                          0x16: 'ANY',
                          0x17: 'IN_BLOCK_FB',
                          0x18: 'IN_BLOCK_FC',
                          0x19: 'IN_BLOCK_DB',
                          0x1a: 'IN_BLOCK_SDB',
                          0x1b: 'STATIC_SFB_MultiInstance',
                          0x1c: 'COUNTER',
                          0x1d: 'TIMER',
                          0xff: 'UNKNOWN',
                          0x20: 'UDT',
                          0x21: 'SFB',
                          0x22: 'FB',
                          0x101: 'SINT',
                          0x102: 'USINT',
                          0x103: 'LINT',
                          0x104: 'ULINT',
                          0x105: 'LREAL',
                          0x106: 'UINT',
                          0x107: 'UDINT'}

CONNECTION_TYPE = {0x11: 'TCP',
                   0x12: 'ISO on TCP',
                   0x13: 'UDP',
                   0x01: 'TCP (compatibility mode)'}

HEADER_SIZE = 36
