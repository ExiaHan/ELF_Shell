#!/usr/bin/env python3

import struct
import fileinput
import sys
import ctypes
import os

ctype = ctypes
sct = struct
fin = fileinput
mysys = sys
myos = os

#enumation

"""This data_types just for Note"""
elf32_data_types = {"Elf32_Addr": "I", "Elf32_Half": "H", "Elf32_Off": "I",
"Elf32_Sword": "i", "Elf32_Word": "I", "Unsigned Char": "B"}

elf32_h_types = {"ET_NONE": 0x0, "ET_REL": 0x1, "ET_EXEC": 0x2,
"ET_DYN": 0x3, "ET_CORE": 0x4, "ET_LOPORC":0xff00, "ET_HIPROC": 0xffff}

elf32_h_machine = {"EM_NONE": 0x0, "EM_M32": 0x1, "EM_SPARC": 0x2,
"EM_386": 0x3, "EM_68K": 0x4, "EM_88K": 0x5, "EM_860": 0x7, "EM_MIPS": 0x8}

elf32_h_version = {"EV_NONE": 0x0, "EV_CURRENT": 0x1}

elf32_h_e_ident = {"EI_MAG0": 0x0,"EI_MAG1": 0x1,"EI_MAG2": 0x2,
"EI_MAG3": 0x3,"EI_CLASS": 0x4,"EI_DATA": 0x5,"EI_VERSION": 0x6,
"EI_PAD": 0x7,"EI_NIDENT": 0x10}

elf32_h_ei_class = {"ELFCLASSNONE": 0x0, "ELFCLASS32": 0x1, "ELFCLASS64": 0x2}

elf32_h_ei_data = {"ELFDATANONE": 0x0, "ELFDATA2LSB": 0x1, "ELFDATA2MSB": 0x2}

elf32_shn = {"SHN_UDEF": 0x0, "SHN_LORESERVE": 0xFF00, "SHN_LOPROC": 0xFF00,
"SHN_HIPROC": 0xFFFF, "SHN_ABS": 0xFFF1, "SHN_COMMON": 0xFFF2,
"SHN_HIRESERVE": 0xFFFF}

elf32_sht = {"SHT_NULL": 0x0, "SHT_PROGBITS": 0x1, "SHT_SYMTAB": 0x2, "SHT_STRTAB": 0x3,
"SHT_RELA": 0x4, "SHT_HASH": 0x5, "SHT_DYNAMIC": 0x6, "SHT_NOTE": 0x7, "SHUT_NOBITS": 0x8,
"SHT_REL": 0x9, "SHT_SHLIB": 0xA, "SHT_DYNSYM": 0xB, "SHT_LOPROC": 0x70000000,
"SHT_HIPROC": 0x7FFFFFFF, "SHT_LOUSER": 0x80000000, "SHT_HIUSER": 0x8FFFFFFF}

elf32_sht_re = {0x0: "SHT_NULL", 0x1: "SHT_PROGBITS", 0x2: "SHT_SYMTAB", 0x3: "SHT_STRTAB",
0x4: "SHT_RELA", 0x5: "SHT_HASH", 0x6: "SHT_DYNAMIC", 0x7: "SHT_NOTE", 0x8: "SHUT_NOBITS",
0x9: "SHT_REL", 0xA: "SHT_SHLIB", 0xB: "SHT_DYNSYM", 0x70000000: "SHT_LOPROC",
0x7FFFFFFF: "SHT_HIPROC", 0x80000000: "SHT_LOUSER", 0x8FFFFFFF: "SHT_HIUSER"}

elf32_section_userdef = "USER_DEFINE"

elf32_pht_re = {0x0: "PT_NULL", 0x1: "PT_LOAD", 0x2: "PT_DYNAMIC", 0x3: "PT_INTERP",
0x4: "PT_NOTE", 0x5: "PT_SHLIB", 0x6: "PT_PHDR", 0x70000000: "PT_LOPROC", 0x7FFFFFFF: "PT_HIPROC"}

elf32_program_userdef = "USER_DEFINE"


class Elf32_Header(object):
    def __init__(self, fobj):
        self.fobj = fobj
        self.e_ident = self.fobj.read(elf32_h_e_ident["EI_NIDENT"])
        #self.e_type = sct.unpack('H', self.fobj.read(ctype.sizeof(ctype.c_int16)))[0]
        self.e_type = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_machine = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_version = sct.unpack('I', self.fobj.read(sct.calcsize("I")))[0]
        self.e_entry = sct.unpack('I', self.fobj.read(sct.calcsize("I")))[0]
        self.e_phoff = sct.unpack('I', self.fobj.read(sct.calcsize("I")))[0]
        self.e_shoff = sct.unpack('I', self.fobj.read(sct.calcsize("I")))[0]
        self.e_flags = sct.unpack('I', self.fobj.read(sct.calcsize("I")))[0]
        self.e_ehsize = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_phentsize = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_phnum = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_shentsize = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_shnum = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]
        self.e_shstrndx = sct.unpack('H', self.fobj.read(sct.calcsize("H")))[0]

class Elf32_Section_Header_Name_String_Table(object):
    """docstring for Elf32_Section_Header_Name_String_Table"""
    def __init__(self, fobj, elfHeader):
        super(Elf32_Section_Header_Name_String_Table, self).__init__()
        self.fobj = fobj
        self.elfHeader = elfHeader
        self.fobj.seek(self.elfHeader.e_shoff + self.elfHeader.e_shentsize * self.elfHeader.e_shstrndx + sct.calcsize("IIII"))
        self.sh_offset = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]

    def getSectionHeaderName(self, strOffset):
        self.fobj.seek(self.sh_offset + strOffset)
        self.nameLstByte = []
        self.nameLst = []
        self.nameStr = ''
        while True:
            self.bChar = self.fobj.read(sct.calcsize("b"))
            if self.bChar == b"\x00":
                break
            else:
                self.nameLstByte.append(sct.unpack("s", self.bChar)[0])
        #self.nameLstByte.insert(0, b"\x5b")
        #self.nameLstByte.append(b"\x5d")
        for ele in self.nameLstByte:
            self.nameLst.append(ele.decode())
        self.nameStr = self.nameStr.join(self.nameLst)
        return self.nameStr

class Elf32_Section_Header(object):
    """docstring for Elf32_Section_Header"""
    def __init__(self, fobj, elfShtStrT):
        super(Elf32_Section_Header, self).__init__()
        self.fobj = fobj
        self.elfShtStrT = elfShtStrT
        self.sh_name = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_type = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_flags = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_addr = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_offset = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_size = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_link = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_info = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_addralign = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]
        self.sh_entsize = sct.unpack("I", self.fobj.read(sct.calcsize("I")))[0]

class Elf32_Section_Header_Table(object):
    """docstring for Elf32_Section_Header_Table"""
    def __init__(self, fobj, elfHeader, elfShtStrT):
        super(Elf32_Section_Header_Table, self).__init__()
        self.fobj = fobj
        self.elfHeader = elfHeader
        self.elfShtStrT = elfShtStrT
        self.elfShdrList = []
        self.fobj.seek(self.elfHeader.e_shoff)
        for i in range(0, self.elfHeader.e_shnum, 1):
            self.elfShdrList.append(Elf32_Section_Header(self.fobj, self.elfShtStrT))

    def findFixedSection(self, strName = "SectionName"):
        for ele in self.elfShdrList:
            if strName == self.elfShtStrT.getSectionHeaderName(ele.sh_name):
                return (ele.sh_offset, ele.sh_size, ele.sh_addr, ele.sh_addralign)
        return 0

class Elf32_File(object):
    """docstring for Elf32_File"""
    def __init__(self, filename):
        super(Elf32_File, self).__init__()
        self.filename = filename
        """Open the target file"""
        try:
            self.efile = open(filename, 'rb+')
        except Exception as e:
            print(e)
            exit(-1)

        """Initial ELF Header"""
        self.elf32_header = Elf32_Header(self.efile)

        """Initial ELF Section String Name Table"""
        self.elf32_shstrt = Elf32_Section_Header_Name_String_Table(self.efile, self.elf32_header)

        """Initial ELF Section Header Table"""
        self.elf32_sht = Elf32_Section_Header_Table(self.efile, self.elf32_header, self.elf32_shstrt)

        """Get the section that want to crypt"""
        #give the name of the target section
        self.fixSection = self.elf32_sht.findFixedSection("mysection")
        self.fixOffset = self.fixSection[0]
        self.fixSize = self.fixSection[1]
        self.fixAddr = self.fixSection[2]
        self.fixAlign = self.fixSection[3]

        """Write sh_addr and sh_size to Elf_header's e_shoff and e_shentsize"""
        self.efile.seek(sct.calcsize("16BHHIII"))
        self.efile.write(sct.pack("I", self.fixAddr))
        self.efile.seek(sct.calcsize("16BHHIIIIIHHH"))
        self.efile.write(sct.pack("I", self.fixSize))
        print("""Offset:0x%08x\nSize:0x%08x\nAddr:0x08%x\nAlign:0x08%x"""
        %(self.fixOffset,self.fixSize,self.fixAddr, self.fixAlign))
        self.efile.seek(self.fixOffset)
        self.SectionData = self.efile.read(self.fixSize)
        #print(self.SectionData)
        self.fmt = '' + str(len(self.SectionData)) + 'B'
        self.SectionData = list(sct.unpack(self.fmt, self.SectionData))
        print(len(self.SectionData))
        #for i in range(0, len(self.SectionData), 1):
        #    print(self.SectionData[i], end = ' ')
        #print()
        """Do the ecrypt(xor) for each byte"""
        for i in range(0, len(self.SectionData), 1):
            self.SectionData[i] = self.SectionData[i] ^ 0x1
        self.SectionData = bytes(self.SectionData)
        self.efile.seek(self.fixOffset)
        self.efile.write(self.SectionData)

if __name__ == '__main__':
    if len(mysys.argv) != 2:
        print("Usage: ./elfshell.py ELF_FILE")
        exit(-1)
    elf32_file = Elf32_File(mysys.argv[1])
