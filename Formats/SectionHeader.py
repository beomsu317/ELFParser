import struct

from Formats.Parser import Parser


class SectionHeader(Parser):
    def __init__(self, elf_header):
        super().__init__()
        self.elf_header = elf_header
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None
        self.name = ""

    def parse(self, section_data):
        (self.sh_name,) = struct.unpack('<L', section_data[0x0:0x4])
        (self.sh_type,) = struct.unpack('<L', section_data[0x4:0x8])
        if self.elf_header.e_ident.EI_CLASS == 0x1:
            (self.sh_flags,) = struct.unpack('<L', section_data[0x8:0xc])
            (self.sh_addr,) = struct.unpack('<L', section_data[0xc:0x10])
            (self.sh_offset,) = struct.unpack('<L', section_data[0x10:0x14])
            (self.sh_size,) = struct.unpack('<L', section_data[0x14:0x18])
            (self.sh_link,) = struct.unpack('<L', section_data[0x18:0x1c])
            (self.sh_info,) = struct.unpack('<L', section_data[0x1c:0x20])
            (self.sh_addralign,) = struct.unpack('<L', section_data[0x20:0x24])
            (self.sh_entsize,) = struct.unpack('<L', section_data[0x24:0x28])
        elif self.elf_header.e_ident.EI_CLASS == 0x2:
            (self.sh_flags,) = struct.unpack('<Q', section_data[0x8:0x10])
            (self.sh_addr,) = struct.unpack('<Q', section_data[0x10:0x18])
            (self.sh_offset,) = struct.unpack('<Q', section_data[0x18:0x20])
            (self.sh_size,) = struct.unpack('<Q', section_data[0x20:0x28])
            (self.sh_link,) = struct.unpack('<L', section_data[0x28:0x2c])
            (self.sh_info,) = struct.unpack('<L', section_data[0x2c:0x30])
            (self.sh_addralign,) = struct.unpack('<Q', section_data[0x30:0x38])
            (self.sh_entsize,) = struct.unpack('<Q', section_data[0x38:0x40])

    def print_section_header(self):
        self.logger.info("name : {}".format(self.name))
        self.logger.info("sh_name : {}".format(hex(self.sh_name)))
        self.print_sh_type()
        self.print_sh_flags()
        self.logger.info("sh_addr : {}".format(hex(self.sh_addr)))
        self.logger.info("sh_offset : {}".format(hex(self.sh_offset)))
        self.logger.info("sh_size : {}".format(hex(self.sh_size)))
        self.logger.info("sh_link : {}".format(hex(self.sh_link)))
        self.logger.info("sh_info : {}".format(hex(self.sh_info)))
        self.logger.info("sh_addralign : {}".format(hex(self.sh_addralign)))
        self.logger.info("sh_entsize : {}".format(hex(self.sh_entsize)))
        self.logger.info("================================")

    def print_sh_type(self):
        sh_type_info = "sh_type["
        if self.sh_type == 0x0:
            sh_type_info += "SHT_NULL]"
        elif self.sh_type == 0x1:
            sh_type_info += "SHT_PROGBITS]"
        elif self.sh_type == 0x2:
            sh_type_info += "SHT_SYMTAB]"
        elif self.sh_type == 0x3:
            sh_type_info += "SHT_STRTAB]"
        elif self.sh_type == 0x4:
            sh_type_info += "SHT_RELA]"
        elif self.sh_type == 0x5:
            sh_type_info += "SHT_HASH]"
        elif self.sh_type == 0x6:
            sh_type_info += "SHT_DYNAMIC]"
        elif self.sh_type == 0x7:
            sh_type_info += "SHT_NOTE]"
        elif self.sh_type == 0x8:
            sh_type_info += "SHT_NOBITS]"
        elif self.sh_type == 0x9:
            sh_type_info += "SHT_REL]"
        elif self.sh_type == 0xa:
            sh_type_info += "SHT_SHLIB]"
        elif self.sh_type == 0xb:
            sh_type_info += "SHT_DYNSYM]"
        elif self.sh_type == 0xe:
            sh_type_info += "SHT_INIT_ARRAY]"
        elif self.sh_type == 0xf:
            sh_type_info += "SHT_FINI_ARRAY]"
        elif self.sh_type == 0x10:
            sh_type_info += "SHT_PREINIT_ARRAY]"
        elif self.sh_type == 0x11:
            sh_type_info += "SHT_GROUP]"
        elif self.sh_type == 0x12:
            sh_type_info += "SHT_SYMTAB_SHNDX]"
        elif self.sh_type == 0x13:
            sh_type_info += "SHT_NUM]"
        elif self.sh_type == 0x6ffffffa:
            sh_type_info += "SHT_SUNW_move]"
        elif self.sh_type == 0x6ffffffb:
            sh_type_info += "SHT_SUNW_COMDAT]"
        elif self.sh_type == 0x6ffffffc:
            sh_type_info += "SHT_SUNW_syminfo]"
        elif self.sh_type == 0x6ffffffd:
            sh_type_info += "SHT_SUNW_verdef]"
        elif self.sh_type == 0x6ffffffe:
            sh_type_info += "SHT_SUNW_verneed]"
        elif self.sh_type == 0x6fffffff:
            sh_type_info += "SHT_SUNW_versym]"
        elif self.sh_type == 0x70000000:
            sh_type_info += "SHT_LOPROC]"
        elif self.sh_type == 0x7fffffff:
            sh_type_info += "SHT_HIPROC]"
        elif self.sh_type == 0x80000000:
            sh_type_info += "SHT_LOUSER]"
        elif self.sh_type == 0xffffffff:
            sh_type_info += "SHT_HIUSER]"
        else:
            sh_type_info += "unknown]"
        sh_type_info += " : {}"
        self.logger.info(sh_type_info.format(hex(self.sh_type)))

    def print_sh_flags(self):
        sh_flags_info = "sh_flags : {} - "
        if self.sh_flags & 0x1 == 0x1:
            sh_flags_info += "SHF_WRITE | "
        elif self.sh_flags & 0x2 == 0x2:
            sh_flags_info += "SHF_ALLOC | "
        elif self.sh_flags & 0x4 == 0x4:
            sh_flags_info += "SHF_EXECINSTR | "
        elif self.sh_flags & 0x10 == 0x10:
            sh_flags_info += "SHF_MERGE | "
        elif self.sh_flags & 0x20 == 0x20:
            sh_flags_info += "SHF_STRINGS | "
        elif self.sh_flags & 0x40 == 0x40:
            sh_flags_info += "SHF_INFO_LINK | "
        elif self.sh_flags & 0x80 == 0x80:
            sh_flags_info += "SHF_INFO_LINK | "
        elif self.sh_flags & 0x100 == 0x100:
            sh_flags_info += "SHF_INFO_LINK | "
        elif self.sh_flags & 0x200 == 0x200:
            sh_flags_info += "SHF_INFO_LINK | "
        elif self.sh_flags & 0x400 == 0x400:
            sh_flags_info += "SHF_INFO_LINK | "
        elif self.sh_flags & 0x0ff00000 == 0x0ff00000:
            sh_flags_info += "SHF_MASKOS | "
        elif self.sh_flags & 0xf0000000 == 0xf0000000:
            sh_flags_info += "SHF_MASKPROC | "
        elif self.sh_flags & 0x4000000 == 0x4000000:
            sh_flags_info += "SHF_ORDERED | "
        elif self.sh_flags & 0x8000000 == 0x8000000:
            sh_flags_info += "SHF_EXCLUDE | "
        sh_flags_info = sh_flags_info[:-2]
        self.logger.info(sh_flags_info.format(hex(self.sh_flags)))
