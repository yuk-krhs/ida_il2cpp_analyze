#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import struct
import re
import collections

try:
  import idc
  import idaapi
  import idautils
except:
  sys.exit()

def read_all_bytes(file):
  with open(file, 'rb') as f:
    return f.read()

class DataObject(object):
  def add_field(self, name, value):
    self.__dict__[name] = value

  def dump(self):
    print(self.__class__.__name__)

    for k, v in self.__dict__.iteritems():
      print('  %s: %s' % (k, str(v)))

class IL2CppMetaData(DataObject):
  def __init__(self, file):
    self.data = read_all_bytes(file)
    self.parse()

  def parse(self):
    self.defs = [
      ('stringLiteral',                         None),
      ('stringLiteralData',                     None),
      ('strings',                               None),
      ('events',                                None),
      ('properties',                            (72, '18i', [
        'nameIndex', 'field04', 'field08', 'field0C', 'field10', 'field14', 'field18', 'field1C',
        'field20', 'field24', 'field28', 'field2C', 'field30', 'field34', 'field38', 'field3C',
        'field40', 'field44'])),
      ('methods',                               (56, '11iI4H', [
        'nameIndex', 'declaringType', 'returnType', 'parameterStart', 'customAttributeIndex',
        'genericContainerIndex', 'methodIndex', 'invokerIndex', 'delegateWrapperIndex',
        'rgctxStartIndex', 'rgctxCount', 'token', 'flags', 'iflags', 'slot', 'parameterCount'])),
      ('parameterDefaultValues',                None),
      ('fieldDefaultValues',                    None),
      ('fieldAndParameterDefaultValueData',     None),
      ('fieldMarshaledSizes',                   None),
      ('parameters',                            None),
      ('fields',                                (16, '3iI', [
        'nameIndex', 'typeIndex', 'customAttributeIndex', 'token'])),
      ('genericParameters',                     None),
      ('genericParameterConstraints',           None),
      ('genericContainers',                     None),
      ('nestedTypes',                           None),
      ('interfaces',                            None),
      ('vtableMethods',                         None),
      ('interfaceOffsets',                      None),
      ('typeDefinitions',                       (120, '24i8H2i', [
        'nameIndex', 'namespaceIndex', 'customAttributeIndex', 'byvalTypeIndex', 'byrefTypeIndex',
        'declaringTypeIndex', 'parentIndex', 'elementTypeIndex', 'rgctxStartIndex', 'rgctxCount',
        'genericContainerIndex', 'delegateWrapperFromManagedToNativeIndex', 'marshalingFunctionsIndex',
        'ccwFunctionIndex', 'guidIndex', 'flags', 'fieldStart', 'methodStart', 'eventStart',
        'propertyStart', 'nestedTypesStart', 'interfacesStart', 'vtableStart', 'interfaceOffsetsStart',
        'method_count', 'property_count', 'field_count', 'event_count', 'nested_type_count', 'vtable_count',
        'interfaces_count', 'interface_offsets_count', 'bitfield', 'token'])),
      ('rgctxEntries',                          None),
      ('images',                                (24, '5iI', [
        'nameIndex', 'assemblyIndex', 'typeStart', 'typeCount', 'entryPointIndex', 'token'])),
      ('assemblies',                            (16, '4i', [
        'imageIndex', 'customAttributeIndex', 'referencedAssemblyStart', 'referencedAssemblyCount'])),
      ('metadataUsageLists',                    None),
      ('metadataUsagePairs',                    None),
      ('fieldRefs',                             None),
      ('referencedAssemblies',                  None),
      ('attributesInfo',                        None),
      ('attributeTypes',                        None),
    ]

    self.parse_header()

    for i in self.defs:
      if i[1] is not None:
        self.parse_data(i[0], i[1])

  def parse_header(self):
    print('parse_header')

    values = struct.unpack('2I58i', self.data[0:240])

    self.header = DataObject()
    self.header.sanity   = values[0]
    self.header.vedrsion = values[1]
    self.header.regions = {}

    print('  %s' % (str(self.header.sanity)))

    for i in range(len(self.defs)):
      name = self.defs[i][0]

      self.header.regions[name] = (values[i*2+2], values[i*2+3])

      print('  0x%08X/%6d: %s' % (
        self.header.regions[name][0],
        self.header.regions[name][1],
        name))

    #self.header.dump()

    self.strings = self.header.regions['strings']

  def parse_data(self, name, define):
    elemsize, format, names = define
    baseaddr, size          = self.header.regions[name]
    count                   = size / elemsize
    dataarray               = []

    print('%s: %08X: %d/%d=%d' % (name, baseaddr, size, elemsize, count))

    for i in range(count):
      addr     = baseaddr + i * elemsize
      values   = struct.unpack(format, self.data[addr:addr+elemsize])
      obj      = self.create_obj(names, values)
      obj.index= i
      obj.addr = addr

      if 'nameIndex' in obj.__dict__:
        obj.name = self.get_string(obj.nameIndex)

        if obj.index == 0:
          print('  %08X: %7d "%s"' % (obj.addr, obj.index, obj.name))
          print('    :')
      else:
        if obj.index == 0:
          print('  %08X: %7d' % (obj.addr, obj.index))
          print('    :')

      #obj.dump()
      dataarray.append(obj)

    self.add_field(name, dataarray)

    return dataarray

  def create_obj(self, names, values):
    #print(values)

    obj    = DataObject()

    assert len(values) == len(names), 'error'

    for i in range(len(names)):
      obj.add_field(names[i], values[i])

    obj.values = values

    return obj

  def get_string(self, pos):
    start = self.strings[0] + pos

    #print('# get_string: start = %X' % (start))

    for i in range(0, 65536):
      if self.data[start + i] == '\0':
        return self.data[start:start+i].decode("utf-8") 

    return None

# TEST
"""
def main():
  dir = os.path.dirname(GetIdbPath())
  metafile = dir + '/' + 'global-metadata.dat'

  if not os.path.exists(metafile):
    print('File not found. %s' % metafile)
    return

  metadata = IL2CppMetaData(metafile)

main()
"""
