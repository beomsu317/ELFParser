import struct

from Formats.Parser import Parser


class Dynsym(Parser):
    def __init__(self, elf_header, section_header):
        super().__init__()
        self.elf_header = elf_header
        self.section_header = section_header
        self.st_name = None
        self.st_info = None
        self.st_other = None
        self.st_shndx = None
        self.st_value = None
        self.st_size = None
        self.name = ""

    def parse(self, dynsym_data, idx, size):
        if self.elf_header.e_ident.EI_CLASS == 0x1:
            (self.st_name,) = struct.unpack('<L', dynsym_data[(idx * size):(idx * size) + 0x4])
            (self.st_value,) = struct.unpack('<L', dynsym_data[(idx * size) + 0x4:(idx * size) + 0x8])
            (self.st_size,) = struct.unpack('<L', dynsym_data[(idx * size) + 0x8:(idx * size) + 0xc])
            (self.st_info,) = struct.unpack('<B', dynsym_data[(idx * size) + 0xc:(idx * size) + 0xd])
            (self.st_other,) = struct.unpack('<B', dynsym_data[(idx * size) + 0xd:(idx * size) + 0xe])
            (self.st_shndx,) = struct.unpack('<H', dynsym_data[(idx * size) + 0xe:(idx * size) + 0x10])
        if self.elf_header.e_ident.EI_CLASS == 0x2:
            (self.st_name,) = struct.unpack('<L', dynsym_data[(idx * size):(idx * size) + 0x4])
            (self.st_info,) = struct.unpack('<B', dynsym_data[(idx * size) + 0x4:(idx * size) + 0x5])
            (self.st_other,) = struct.unpack('<B', dynsym_data[(idx * size) + 0x5:(idx * size) + 0x6])
            (self.st_shndx,) = struct.unpack('<H', dynsym_data[(idx * size) + 0x6:(idx * size) + 0x8])
            (self.st_value,) = struct.unpack('<Q', dynsym_data[(idx * size) + 0x8:(idx * size) + 0x10])
            (self.st_size,) = struct.unpack('<Q', dynsym_data[(idx * size) + 0x10:(idx * size) + 0x18])

    def print_dynsym(self):
        self.logger.info("name : {}".format(self.name))
        self.logger.info("st_name : {}".format(hex(self.st_name)))
        self.logger.info("st_value : {}".format(hex(self.st_value)))
        self.logger.info("st_size : {}".format(hex(self.st_size)))
        self.print_st_info()
        self.print_st_other()
        self.logger.info("st_other : {}".format(hex(self.st_other)))
        self.logger.info("st_shndx : {}".format(hex(self.st_shndx)))
        self.logger.info("============================")

    def print_st_info(self):
        self.logger.info("st_info : {}".format(hex(self.st_info)))
        st_bind = self.st_info >> 4
        st_bind_info = "    st_bind_info : {} - ".format(hex(st_bind))
        if st_bind == 0x0:
            st_bind_info += "STB_LOCAL | "
        elif st_bind == 0x1:
            st_bind_info += "STB_GLOBAL | "
        elif st_bind == 0x2:
            st_bind_info += "STB_WEAK | "
        elif st_bind == 0x10:
            st_bind_info += "STB_LOOS | "
        elif st_bind == 0x12:
            st_bind_info += "STB_HIOS | "
        elif st_bind == 0x13:
            st_bind_info += "STB_LOPROC | "
        elif st_bind == 0x15:
            st_bind_info += "STB_HIPROC | "

        st_bind_info = st_bind_info[:-2]
        self.logger.info(st_bind_info)

        st_type = self.st_info & 0xf
        st_type_info = "    st_type_info : {} - ".format(hex(st_type))
        if st_type == 0x0:
            st_type_info += "STT_NOTYPE | "
        if st_type == 0x1:
            st_type_info += "STT_OBJECT | "
        if st_type == 0x2:
            st_type_info += "STT_FUNC | "
        if st_type == 0x3:
            st_type_info += "STT_SECTION | "
        if st_type == 0x4:
            st_type_info += "STT_FILE | "
        if st_type == 0x5:
            st_type_info += "STT_COMMON | "
        if st_type == 0x10:
            st_type_info += "STT_LOOS | "
        if st_type == 0x12:
            st_type_info += "STT_HIOS | "
        if st_type == 0x13:
            st_type_info += "STT_LOPROC | "
        if st_type == 0x13:
            st_type_info += "STT_SPARC_REGISTER | "
        if st_type == 0x13:
            st_type_info += "STT_HIPROC | "

        st_type_info = st_type_info[:-2]
        self.logger.info(st_type_info)

    def print_st_other(self):
        st_other_info = "st_other : {} - ".format(hex(self.st_other))
        if self.st_other == 0x0:
            st_other_info += "STV_DEFAULT | "
        if self.st_other == 0x1:
            st_other_info += "STV_INTERNAL | "
        if self.st_other == 0x2:
            st_other_info += "STV_HIDDEN | "
        if self.st_other == 0x3:
            st_other_info += "STV_PROTECTED | "
        st_other_info = st_other_info[:-2]
        self.logger.info(st_other_info)