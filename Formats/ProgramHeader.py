import struct

from Formats.Parser import Parser


class ProgramHeader(Parser):
    def __init__(self, elf_header):
        super().__init__()
        self.elf_header = elf_header
        self.p_type = None
        self.p_flags = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_align = None

    def parse(self, program_data):
        (self.p_type,) = struct.unpack('<L', program_data[0x0:0x4])
        if self.elf_header.e_ident.EI_CLASS == 0x1:
            (self.p_offset,) = struct.unpack('<L', program_data[0x4:0x8])
            (self.p_vaddr,) = struct.unpack('<L', program_data[0x8:0xc])
            (self.p_paddr,) = struct.unpack('<L', program_data[0xc:0x10])
            (self.p_filesz,) = struct.unpack('<L', program_data[0x10:0x14])
            (self.p_memsz,) = struct.unpack('<L', program_data[0x14:0x18])
            (self.p_flags,) = struct.unpack('<L', program_data[0x18:0x1c])
            (self.p_align,) = struct.unpack('<L', program_data[0x1c:0x20])
        elif self.elf_header.e_ident.EI_CLASS == 0x2:
            (self.p_flags,) = struct.unpack('<L', program_data[0x4:0x8])
            (self.p_offset,) = struct.unpack('<Q', program_data[0x8:0x10])
            (self.p_vaddr,) = struct.unpack('<Q', program_data[0x10:0x18])
            (self.p_paddr,) = struct.unpack('<Q', program_data[0x18:0x20])
            (self.p_filesz,) = struct.unpack('<Q', program_data[0x20:0x28])
            (self.p_memsz,) = struct.unpack('<Q', program_data[0x28:0x30])
            (self.p_align,) = struct.unpack('<Q', program_data[0x30:0x38])

    def print_program_header(self):
        self.print_p_type()
        self.print_p_flag()
        self.logger.info("p_offset : {}".format(hex(self.p_offset)))
        self.logger.info("p_vaddr : {}".format(hex(self.p_vaddr)))
        self.logger.info("p_paddr : {}".format(hex(self.p_paddr)))
        self.logger.info("p_filesz : {}".format(hex(self.p_filesz)))
        self.logger.info("p_memsz : {}".format(hex(self.p_memsz)))
        self.logger.info("p_align : {}".format(hex(self.p_align)))
        self.logger.info("================================")

    def print_p_type(self):
        p_type_info = "p_type"
        if self.p_type == 0x0:
            p_type_info += "[PT_NULL] : {}"
        elif self.p_type == 0x1:
            p_type_info += "[PT_LOAD] : {}"
        elif self.p_type == 0x2:
            p_type_info += "[PT_DYNAMIC] : {}"
        elif self.p_type == 0x3:
            p_type_info += "[PT_INTERP] : {}"
        elif self.p_type == 0x4:
            p_type_info += "[PT_NOTE] : {}"
        elif self.p_type == 0x5:
            p_type_info += "[PT_SHLIB] : {}"
        elif self.p_type == 0x6:
            p_type_info += "[PT_PHDR] : {}"
        elif self.p_type == 0x7:
            p_type_info += "[PT_TLS] : {}"
        elif self.p_type == 0x60000000:
            p_type_info += "[PT_LOOS] : {}"
        elif self.p_type == 0x6FFFFFFF:
            p_type_info += "[PT_HIOS] : {}"
        elif self.p_type == 0x70000000:
            p_type_info += "[PT_LOPROC] : {}"
        elif self.p_type == 0x7FFFFFFF:
            p_type_info += "[PT_HIPROC] : {}"
        else:
            p_type_info += "[unknown]: {}"
        self.logger.info(p_type_info.format(hex(self.p_type)))

    def print_p_flag(self):
        p_flags_info = "p_flags : {} - ".format(hex(self.p_flags))
        if self.p_flags & 0x1 == 0x1:
            p_flags_info += "PF_X | "
        if self.p_flags & 0x2 == 0x2:
            p_flags_info += "PF_W | "
        if self.p_flags & 0x4 == 0x4:
            p_flags_info += "PF_R | "
        if self.p_flags & 0xf0000000 == 0xf0000000:
            p_flags_info += "PF_MASKPROC | "
        p_flags_info = p_flags_info[:-2]
        self.logger.info(p_flags_info)
