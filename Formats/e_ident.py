import struct

from Formats.Parser import Parser


class e_ident(Parser):
    def __init__(self):
        super().__init__()
        self.EI_MAG = None
        self.EI_CLASS = None
        self.EI_DATA = None
        self.EI_VERSION = None
        self.EI_OSABI = None
        self.EI_ABIVERSION = None
        self.EI_PAD = None

    def parse(self, data):
        self.EI_MAG = data[0x0:0x4]
        (self.EI_CLASS,) = struct.unpack('<B', data[0x4:0x5])
        (self.EI_DATA,) = struct.unpack('<B', data[0x5:0x6])
        (self.EI_VERSION,) = struct.unpack('<B', data[0x6:0x7])
        (self.EI_OSABI,) = struct.unpack('<B', data[0x7:0x8])
        (self.EI_ABIVERSION,) = struct.unpack('<B', data[0x8:0x9])
        (self.EI_PAD,) = struct.unpack('<B', data[0x9:0x0a])

    def print_e_ident(self):
        self.print_magic()
        self.print_class()
        self.print_data()
        self.print_version()
        self.print_osabi()
        # self.check_abi_version()
        # self.check_pad()

    def print_magic(self):
        self.logger.info("e_ident[EI_MAG] : {}".format(self.EI_MAG))

    def print_class(self):
        class_info = "e_ident[EI_CLASS] : "
        if self.EI_CLASS == 1:
            class_info += "32-bit objects"
        elif self.EI_CLASS == 2:
            class_info += "64-bit objects"
        else:
            class_info += "Invalid class"
        self.logger.info(class_info)

    def print_data(self):
        data_info = "e_ident[EI_DATA] : "
        if self.EI_DATA == 1:
            data_info += "Little endian"
        elif self.EI_DATA == 2:
            data_info += "Big endian"
        else:
            data_info += "Invalid data encoding"
        self.logger.info(data_info)

    def print_version(self):
        if self.EI_VERSION == 1:
            self.logger.info("e_ident[EI_Version] : original and current version of ELF")
        else:
            self.logger.info("e_ident[EI_Version] : unknown version")

    def print_osabi(self):
        osabi_info = "e_ident[EI_OSABI] : "
        if self.EI_OSABI == 0x0:
            osabi_info += "System V"
        elif self.EI_OSABI == 0x1:
            osabi_info += "HP-UX"
        elif self.EI_OSABI == 0x2:
            osabi_info += "NetBSD"
        elif self.EI_OSABI == 0x3:
            osabi_info += "Linux"
        elif self.EI_OSABI == 0x4:
            osabi_info += "GNU Hurd"
        elif self.EI_OSABI == 0x6:
            osabi_info += "Solaris"
        elif self.EI_OSABI == 0x7:
            osabi_info += "AIX"
        elif self.EI_OSABI == 0x8:
            osabi_info += "IRIX"
        elif self.EI_OSABI == 0x9:
            osabi_info += "FreeBSD"
        elif self.EI_OSABI == 0xa:
            osabi_info += "Tru64"
        elif self.EI_OSABI == 0xb:
            osabi_info += "Novell Modesto"
        elif self.EI_OSABI == 0xc:
            osabi_info += "OpenBSD"
        elif self.EI_OSABI == 0xd:
            osabi_info += "OpenVMS"
        elif self.EI_OSABI == 0xe:
            osabi_info += "NonStop Kernel"
        elif self.EI_OSABI == 0xf:
            osabi_info += "AROS"
        elif self.EI_OSABI == 0x10:
            osabi_info += "Fenix OS"
        elif self.EI_OSABI == 0x11:
            osabi_info += "CloudABI"
        elif self.EI_OSABI == 0x12:
            osabi_info += "Stratus Technologies OpenVOS"
        self.logger.info(osabi_info)

    def print_abi_version(self):
        pass

    def print_pad(self):
        pass