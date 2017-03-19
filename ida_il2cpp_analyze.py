#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os

try:
  import idc
  import idaapi
  import idautils
  import re
except:
  sys.exit()

#-------------------------------------------------------------------------------
name_re     = re.compile(r'^\((((a)|(off_))\w+)')
method_re   = re.compile(r'^[\w.:]+')
nameref_re  = re.compile(r'((g_)|(off_)|(dword_)|(unk_))[^ .]+')
is_x86 = False
is_x64 = False
is_ARM = False

#-------------------------------------------------------------------------------
def main():
  #print('INF_VERSION:  %s' % (str(idc.GetLongPrm(idc.INF_VERSION))))
  #print('INF_PROCNAME: %s' % (str(idc.GetLongPrm(idc.INF_PROCNAME))))
  #print('INF_COMPILER: %s' % (str(idc.GetLongPrm(idc.INF_COMPILER))))
  #print('INF_FILETYPE: %s' % (str(idc.GetLongPrm(idc.INF_FILETYPE))))

  processor = str(idc.GetLongPrm(idc.INF_PROCNAME))

  is_x86 = processor == 'metapc'
  is_ARM = processor == 'ARM'

  if not is_x86:
    idc.Message('*** Sorry, currently only supported x86.\n')
    return

  def_struct()

  code_reg, meta_reg = analyze_reg()

  if code_reg != idc.BADADDR:
    analyze_code_reg(code_reg)

  if meta_reg != idc.BADADDR:
    analyze_meta_reg(meta_reg)

  init_array = analyze_init_array()
  analyze_invoke_unityengine()
  analyze_invoke_library()

  print('%X: INIT_IL2CPP' % (idc.LocByName('INIT_IL2CPP')))
  print('%X: %s' % (code_reg, idc.Name(code_reg)))
  print('%X: %s' % (meta_reg, idc.Name(meta_reg)))
  print('%X: .init_array' % (init_array))

#-------------------------------------------------------------------------------
def new_struct(name):
  id  = idc.AddStrucEx(-1, name, 0)

  print('  %d: %s' % (id, name))

  return id

#-------------------------------------------------------------------------------
def def_struct():
  print('def_struct')

  if 0xFFFFFFFF == idc.GetStrucIdByName('CodeRegistration'):
    id  = new_struct('CodeRegistration')
    mid = idc.AddStrucMember(id, 'methodPointersCount',                       0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'methodPointers',                            0x04,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'delegateWrappersFromNativeToManagedCount',  0x08,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'delegateWrappersFromNativeToManaged',       0x0C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'delegateWrappersFromManagedToNativeCount',  0x10,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'delegateWrappersFromManagedToNative',       0x14,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'marshalingFunctionsCount',                  0x18,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'marshalingFunctions',                       0x1C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'ccwMarshalingFunctionsCount',               0x20,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'ccwMarshalingFunctions',                    0x24,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'genericMethodPointersCount',                0x28,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'genericMethodPointers',                     0x2C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'invokerPointersCount',                      0x30,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'invokerPointers',                           0x34,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'customAttributeCount',                      0x38,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'customAttributeGenerators',                 0x3C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'guidCount',                                 0x40,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'guids',                                     0x44,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)

  if 0xFFFFFFFF == idc.GetStrucIdByName('MetaRegistration'):
    id  = new_struct('MetaRegistration')
    mid = idc.AddStrucMember(id, 'genericClassesCount',                       0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'genericClasse',                             0x04,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'genericInstsCount',                         0x08,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'genericInsts',                              0x0C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'genericMethodTableCount',                   0x10,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'genericMethodTable',                        0x14,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'typesCount',                                0x18,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'types',                                     0x1C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'methodSpecsCount',                          0x20,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'methodSpecs',                               0x24,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'fieldOffsetsCount',                         0x28,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'fieldOffsets',                              0x2C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'typeDefinitionsSizesCount',                 0x30,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'typeDefinitionsSizes',                      0x34,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'metadataUsagesCount',                       0x38,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'metadataUsages',                            0x3C,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppGenericClass'):
    id  = new_struct('Il2CppGenericClass')
    mid = idc.AddStrucMember(id, 'typeDefinitionIndex',                       0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'class_inst',                                0x04,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'method_inst',                               0x08,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'cached_class',                              0x0C,  0x20000400,  -1,  4)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppGenericInst'):
    id  = new_struct('Il2CppGenericInst')
    mid = idc.AddStrucMember(id, 'type_count',                                0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'types',                                     0x04,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppGenericMethodFunctionsDefinitions'):
    id  = new_struct('Il2CppGenericMethodFunctionsDefinitions')
    mid = idc.AddStrucMember(id, 'field_0',                                   0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'field_4',                                   0x04,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'field_8',                                   0x08,  0x20000400,  -1,  4)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppType'):
    id  = new_struct('Il2CppType')
    mid = idc.AddStrucMember(id, 'data',                                      0x00,  0x25500400,  0XFFFFFFFF,  4,  0XFFFFFFFF,  0,  0x000002)
    mid = idc.AddStrucMember(id, 'flags',                                     0x04,  0x20000400,  -1,  4)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppMethodSpec'):
    id  = new_struct('Il2CppMethodSpec')
    mid = idc.AddStrucMember(id, 'MethodDefinition',                          0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'ClassIndex',                                0x04,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'MethodIndex',                               0x08,  0x20000400,  -1,  4)

  if 0xFFFFFFFF == idc.GetStrucIdByName('Il2CppTypeDefinitionSizes'):
    id  = new_struct('Il2CppTypeDefinitionSizes')
    mid = idc.AddStrucMember(id, 'instance_size',                             0x00,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'native_size',                               0x04,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'static_fields_size',                        0x08,  0x20000400,  -1,  4)
    mid = idc.AddStrucMember(id, 'thread_static_fields_size',                 0x0C,  0x20000400,  -1,  4)

#-------------------------------------------------------------------------------
def analyze_invoke_unityengine():
  print('analyze_invoke_unityengine')

  resolve = get_resolve()

  print('  %X: %s' % (resolve, idc.Name(resolve)))

  if resolve != idc.BADADDR:
    return

  addr = idc.RfirstB(resolve)

  while addr != idc.BADADDR:
    analyze_invoke(addr)

    addr = idc.RnextB(resolve, addr)

#-------------------------------------------------------------------------------
def analyze_invoke(funcaddr):
  #print('funcaddr : %08X - %s' % (funcaddr, GetFunctionName(funcaddr)))

  func_st   = idc.GetFunctionAttr(funcaddr, idc.FUNCATTR_START)
  func_en   = idc.GetFunctionAttr(funcaddr, idc.FUNCATTR_END)
  funcname  = idc.GetFunctionName(func_st)
  addr      = func_st

  if not funcname.startswith('sub_'):
    return

  while addr < func_en:
    mnem = idc.GetMnem(addr)

    #print('  %08X: %s' % (addr, mnem))

    if mnem == 'lea':
      oprand1 = idc.GetOpnd(addr, 1)
      match   = name_re.match(oprand1)

      #print('              %s' % (oprand1))

      if match is not None:
        #print('              %s' % (match.group(1)))

        strname    = match.group(1)
        nameaddr   = idc.LocByName(strname)
        methodname = idc.GetString(nameaddr, -1, idc.ASCSTR_C)
        methodname = method_re.match(methodname).group(0)

        print('%08X = %s' % (func_st, methodname))

        idc.MakeNameEx(func_st, methodname, idc.SN_NOWARN | idc.SN_AUTO)

        break

    addr = idc.NextHead(addr, func_en)

    if addr == idc.BADADDR:
      break

#-------------------------------------------------------------------------------
def analyze_invoke_library():
  print('analyze_invoke_library')

  resolve = idc.LocByName('._ZN6il2cpp2vm14PlatformInvoke7ResolveERK16PInvokeArguments')

  print('  %X: %s' % (resolve, idc.Name(resolve)))

  if resolve == idc.BADADDR:
    return

  addr = idc.RfirstB(resolve)

  while addr != idc.BADADDR:
    analyze_invoke2(addr)

    addr = idc.RnextB(resolve, addr)

#-------------------------------------------------------------------------------
def analyze_invoke2(funcaddr):
  #print('funcaddr : %08X - %s' % (funcaddr, GetFunctionName(funcaddr)))

  func_st   = idc.GetFunctionAttr(funcaddr, idc.FUNCATTR_START)
  func_en   = idc.GetFunctionAttr(funcaddr, idc.FUNCATTR_END)
  funcname  = idc.GetFunctionName(func_st)
  addr      = func_st
  state     = 0

  if not funcname.startswith('sub_'):
    return

  while addr < func_en:
    mnem = idc.GetMnem(addr)

    #print('  %08X: %s' % (addr, mnem))

    if mnem == 'lea':
      oprand1 = idc.GetOpnd(addr, 1)
      match   = name_re.match(oprand1)

      #print('              %s' % (oprand1))

      if match is not None:
        #print('              %s' % (match.group(1)))

        strname   = match.group(1)
        nameaddr  = idc.LocByName(strname)

        if strname.startswith('off'):
          idc.MakeStr(nameaddr, idc.BADADDR);

        name      = idc.GetString(nameaddr, -1, idc.ASCSTR_C)

        #print('    opaddr:   %X' % addr)
        #print('    strname:  %s' % strname)
        #print('    nameaddr: %X' % nameaddr)
        #print('    name:     %s' % name)

        if state == 0:
          libname = name
          state   = 1
        else:
          name    = method_re.match(name).group(0)

          print('    %X: %s @%s' % (func_st, name, libname))

          idc.MakeNameEx(func_st, name, idc.SN_NOWARN | idc.SN_AUTO)
          break

    addr = idc.NextHead(addr, func_en)

    if addr == idc.BADADDR:
      break

#-------------------------------------------------------------------------------
def analyze_init_array():
  print('analyze_init_array')

  seg    = idc.SegByName('.init_array')
  addr   = idc.SegByBase(seg)
  seg_st = idc.GetSegmentAttr(addr, idc.SEGATTR_START)
  seg_en = idc.GetSegmentAttr(addr, idc.SEGATTR_END)

  print('  .init_array = %08X - %08X' % (seg_st, seg_en))

  if addr == idc.BADADDR:
    return

  while addr < seg_en:
    funcaddr = idc.Dword(addr)

    if funcaddr > 0:
      name = idc.Name(funcaddr)

      if name is None or name.startswith('sub_'):
        idc.MakeName(funcaddr, 'INIT_%X' % funcaddr)

      print('    %08X: %s' % (funcaddr, idc.Name(funcaddr)))

    addr += 4

  return seg_st

#-------------------------------------------------------------------------------
def analyze_reg():
  print('analyze_reg')

  name = '._ZN6il2cpp2vm13MetadataCache8RegisterEPK22Il2CppCodeRegistrationPK26Il2CppMetadataRegistrationPK20Il2CppCodeGenOptions'
  addr = idc.LocByName(name)
  addr = idc.RfirstB(addr)

  if addr == idc.BADADDR:
    return (idc.BADADDR, idc.BADADDR)

  func_st   = idc.GetFunctionAttr(addr, idc.FUNCATTR_START)
  func_en   = idc.GetFunctionAttr(addr, idc.FUNCATTR_END)
  funcname  = idc.GetFunctionName(func_st)
  addr      = func_st
  args      = []

  idc.MakeNameEx(func_st, 'INIT_IL2CPP', idc.SN_NOWARN | idc.SN_AUTO)

  print('  %X: %s' % (func_st, idc.Name(func_st)))

  while addr != idc.BADADDR and addr < func_en:
    mnem = idc.GetMnem(addr)

    #print('  %08X: %s' % (addr, mnem))

    if mnem == 'lea' or mnem == 'mov':
      oprand1 = idc.GetOpnd(addr, 1)
      match   = nameref_re.search(oprand1)

      #print('              %s' % (oprand1))

      if match is not None:
        args.append(match.group())

        if len(args) == 3:
          code_reg = idc.LocByName(args[2])
          meta_reg = idc.Dword(idc.LocByName(args[1]))

          print('  code_reg = %08X' % (code_reg))
          print('  meta_reg = %08X' % (meta_reg))

          return (code_reg, meta_reg)

    addr = idc.NextHead(addr, func_en)

  return (idc.BADADDR, idc.BADADDR)

#-------------------------------------------------------------------------------
def analyze_code_reg(code_reg):
  print('analyze_code_reg')

  names = [
    'methodPointers',
    'delegateWrappersFromNativeToManaged',
    'delegateWrappersFromManagedToNative',
    'marshalingFunctions',
    'ccwMarshalingFunctions',
    'genericMethodPointers',
    'invokerPointers',
    'customAttributeGenerators',
    #'guids',
  ]
  defaddr = code_reg

  idc.MakeNameEx(code_reg, 'g_code_reg', idc.SN_NOWARN | idc.SN_AUTO)
  idc.MakeStruct(code_reg, 'CodeRegistration')

  for i in range(len(names)):
    defaddr = make_func_table(True, defaddr, names[i])

#-------------------------------------------------------------------------------
def analyze_meta_reg(meta_reg):
  print('analyze_meta_reg')

  defs      = [
    (0,  'GenericClasses',       'genclass',     'Il2CppGenericClass'),
    (0,  'GenericInsts',         'geninst',      'Il2CppGenericInst'),
    (12, 'GenericMethodTable',   'genmethodtbl', 'Il2CppGenericMethodFunctionsDefinitions'),
    (0,  'Types',                'type',         'Il2CppType'),
    (12, 'MethodSpec',           'methodspec',   'Il2CppMethodSpec'),
    (0,  'FieldOffsets',         'fieldoff',     'int'),
    (0,  'TypeDefinitionsSizes', 'typedefsize',  'Il2CppTypeDefinitionSizes'),
    (0,  'MetadataUsages',       'metausage',    'int'),
  ]
  defaddr   = meta_reg

  idc.MakeNameEx(meta_reg, 'g_meta_reg', idc.SN_NOWARN | idc.SN_AUTO)
  idc.MakeStruct(meta_reg, 'MetaRegistration')

  for i in defs:
    if i[0] == 0:
      defaddr = make_ref_table(True, defaddr, i[1], i[2], i[3])
    else:
      defaddr = make_table(True, defaddr, i[1], i[2], i[3], i[0])

#-------------------------------------------------------------------------------
def get_resolve():
  # il2cpp::vm::InternalCalls::Resolve
  resolve = idc.LocByName('_ZN6il2cpp2vm13InternalCalls7ResolveEPKc')
  addr = idc.RfirstB(resolve)

  while addr != idc.BADADDR:
    name = idc.Name(addr)

    if name == '__ZN6il2cpp2vm13InternalCalls7ResolveEPKc':
      return addr;

    addr = idc.RnextB(resolve, addr)

  return idc.BADADDR

#-------------------------------------------------------------------------------
def get_count_addr(name, addr):
  n     = idc.Dword(addr)
  addr  = idc.Dword(addr + 4)

  #print('  %X: %d - %s' % (addr, n, name))

  return (n, addr)

#-------------------------------------------------------------------------------
def make_ref_table(enable, defaddr, tblname, name, classname):
  n, addr = get_count_addr(tblname, defaddr)

  print('  %X/%d: %s' % (addr, n, name))

  if enable and addr != idc.BADADDR:
    idc.MakeNameEx(addr, 'g_%s' % name, idc.SN_NOWARN | idc.SN_AUTO)

    for i in range(n):
      make_data(idc.Dword(addr + i * 4), i, name, classname)

  return defaddr + 8

#-------------------------------------------------------------------------------
def make_table(enable, defaddr, tblname, name, classname, elemsize):
  n, addr = get_count_addr(tblname, defaddr)

  print('  %X/%d: %s' % (addr, n, name))

  if enable and addr != idc.BADADDR:
    for i in range(n):
      make_data(addr + i * elemsize, i, name, classname)

  return defaddr + 8

#-------------------------------------------------------------------------------
def make_func_table(enable, defaddr, name):
  n    = idc.Dword(defaddr + 0)
  addr = idc.Dword(defaddr + 4)

  print('  %X/%d: %s' % (addr, n, name))

  if enable and addr != 0:
    idc.MakeNameEx(addr, 'g_%s' % name, idc.SN_NOWARN | idc.SN_AUTO)

    for i in range(n):
      make_func(idc.Dword(addr + i * 4), i, name)

  return defaddr + 8

#-------------------------------------------------------------------------------
def make_data(addr, index, name, classname):
  if index == 0:
    print('    %s[%d] = %X' % (name, index, addr))
    print('      :')

  if addr == 0:
    return

  if classname == 'int':
    idc.MakeDword(addr)
  else:
    idc.MakeStruct(addr, classname)

  idc.MakeNameEx(addr, 'g_%s_%X' % (name, addr), idc.SN_NOWARN | idc.SN_AUTO)

def is_func(addr):
  start = idc.GetFunctionAttr(addr, idc.FUNCATTR_START)

  return start == addr

#-------------------------------------------------------------------------------
def make_func(addr, index, name):
  if index == 0:
    print('    %s[%d] = %X' % (name, index, addr))
    print('      :')

  if addr == 0:
    return

  if is_func(addr):
    funcname = idc.GetFunctionName(addr)

    #print('    %08X: %s' % (funcaddr, funcname))

    if not funcname.startswith('sub_'):
      print('    #CHECK# %X: %s' % (addr, funcname))
  else:
    #print('    MakeFunction(0x%X)' % addr)

    idc.MakeFunction(addr)
    idc.MakeNameEx(addr, 'sub_%X' % addr, idc.SN_NOWARN | idc.SN_AUTO)

main()
