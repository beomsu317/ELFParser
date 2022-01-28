import struct

from Formats.Parser import Parser
from Formats.e_ident import e_ident

class ElfHeader(Parser):
    def __init__(self):
        super().__init__()
        self.e_ident = None
        self.e_type = None
        self.e_vesrion = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None

    def parse(self, data):
        self.e_ident = e_ident()
        self.e_ident.parse(data)

        (self.e_type,) = struct.unpack('<H', data[0x10:0x12])
        (self.e_machine,) = struct.unpack('<H', data[0x10:0x12])
        (self.e_vesrion,) = struct.unpack('<L', data[0x14:0x18])
        if self.e_ident.EI_CLASS == 1:
            (self.e_entry,) = struct.unpack('<L', data[0x18:0x1c])
            (self.e_phoff,) = struct.unpack('<L', data[0x1c:0x20])
            (self.e_shoff,) = struct.unpack('<L', data[0x20:0x24])
            (self.e_flags,) = struct.unpack('<L', data[0x24:0x28])
            (self.e_ehsize,) = struct.unpack('<H', data[0x28:0x2a])
            (self.e_phentsize,) = struct.unpack('<H', data[0x2a:0x2c])
            (self.e_phnum,) = struct.unpack('<H', data[0x2c:0x2e])
            (self.e_shentsize,) = struct.unpack('<H', data[0x2e:0x30])
            (self.e_shnum,) = struct.unpack('<H', data[0x30:0x32])
            (self.e_shstrndx,) = struct.unpack('<H', data[0x32:0x34])
        elif self.e_ident.EI_CLASS == 2:
            (self.e_entry,) = struct.unpack('<Q', data[0x18:0x20])
            (self.e_phoff,) = struct.unpack('<Q', data[0x20:0x28])
            (self.e_shoff,) = struct.unpack('<Q', data[0x28:0x30])
            (self.e_flags,) = struct.unpack('<L', data[0x30:0x34])
            (self.e_ehsize,) = struct.unpack('<H', data[0x34:0x36])
            (self.e_phentsize,) = struct.unpack('<H', data[0x36:0x38])
            (self.e_phnum,) = struct.unpack('<H', data[0x38:0x3a])
            (self.e_shentsize,) = struct.unpack('<H', data[0x3a:0x3c])
            (self.e_shnum,) = struct.unpack('<H', data[0x3c:0x3e])
            (self.e_shstrndx,) = struct.unpack('<H', data[0x3e:0x40])

        # self.e_phentsize = 0x20
        # self.e_shentsize = 0x28

    def print_elf_header(self):
        self.logger.info("=========================[ELF Header]=========================")
        self.e_ident.print_e_ident()
        self.print_e_type()
        self.print_e_machine()
        self.print_e_version()

        self.logger.info("e_entry : {}".format(self.e_entry))
        self.logger.info("e_phoff : {}".format(hex(self.e_phoff)))
        self.logger.info("e_shoff : {}".format(hex(self.e_shoff)))

        self.print_e_flags()

        self.logger.info("e_ehsize : {}".format(hex(self.e_ehsize)))
        self.logger.info("e_phentsize : {}".format(hex(self.e_phentsize)))
        self.logger.info("e_phnum : {}".format(hex(self.e_phnum)))
        self.logger.info("e_shentsize : {}".format(hex(self.e_shentsize)))
        self.logger.info("e_shnum : {}".format(hex(self.e_shnum)))
        self.logger.info("e_shstrndx : {}".format(hex(self.e_shstrndx)))
        self.logger.info("==============================================================")

    def print_e_type(self):
        type_info = "e_type["
        if self.e_type == 0x0:
            type_info += "ET_NONE]"
        elif self.e_type == 0x1:
            type_info += "ET_REL]"
        elif self.e_type == 0x2:
            type_info += "ET_EXEC]"
        elif self.e_type == 0x3:
            type_info += "ET_DYN]"
        elif self.e_type == 0x4:
            type_info += "ET_CORE]"
        elif self.e_type == 0xfe00:
            type_info += "ET_LOOS]"
        elif self.e_type == 0xfeff:
            type_info += "ET_HIOS]"
        elif self.e_type == 0xff00:
            type_info += "ET_LOPROC]"
        elif self.e_type == 0xffff:
            type_info += "ET_HIPROC]"
        type_info += " : {}".format(hex(self.e_type))
        self.logger.info(type_info)

    def print_e_machine(self):
        machine_info = "e_machine : "
        if self.e_machine == 0x0:
            machine_info("No specific instruction set")
        elif self.e_machine == 0x01:
            machine_info += "AT&T WE 32100"
        elif self.e_machine == 0x02:
            machine_info += "SPARC"
        elif self.e_machine == 0x03:
            machine_info += "x86"
        elif self.e_machine == 0x04:
            machine_info += "Motorola 68000 (M68k)"
        elif self.e_machine == 0x05:
            machine_info += "Motorola 88000 (M88k)"
        elif self.e_machine == 0x06:
            machine_info += "Intel MCU"
        elif self.e_machine == 0x07:
            machine_info += "Intel 80860"
        elif self.e_machine == 0x08:
            machine_info += "MIPS"
        elif self.e_machine == 0x09:
            machine_info += "IBM System/370"
        elif self.e_machine == 0x0A:
            machine_info += "MIPS RS3000 Little-endian"
        elif self.e_machine >= 0x0B and self.e_machine <= 0x0D:
            machine_info += "Reserved for future use"
        elif self.e_machine == 0x0E:
            machine_info += "Hewlett-Packard PA-RISC"
        elif self.e_machine == 0x0F:
            machine_info += "Reserved for future use"
        elif self.e_machine == 0x13:
            machine_info += "Intel 80960"
        elif self.e_machine == 0x14:
            machine_info += "PowerPC"
        elif self.e_machine == 0x15:
            machine_info += "PowerPC (64-bit)"
        elif self.e_machine == 0x16:
            machine_info += "S390, including S390x"
        elif self.e_machine == 0x17:
            machine_info += "IBM SPU/SPC"
        elif self.e_machine >= 0x18 and self.e_machine <= 0x23:
            machine_info += "Reserved for future use"
        elif self.e_machine == 0x24:
            machine_info += "NEC V800"
        elif self.e_machine == 0x25:
            machine_info += "Fujitsu FR20"
        elif self.e_machine == 0x26:
            machine_info += "TRW RH-32"
        elif self.e_machine == 0x27:
            machine_info += "Motorola RCE"
        elif self.e_machine == 0x28:
            machine_info += "ARM (up to ARMv7/Aarch32)"
        elif self.e_machine == 0x29:
            machine_info += "Digital Alpha"
        elif self.e_machine == 0x2A:
            machine_info += "SuperH"
        elif self.e_machine == 0x2B:
            machine_info += "SPARC Version 9"
        elif self.e_machine == 0x2C:
            machine_info += "Siemens TriCore embedded processor"
        elif self.e_machine == 0x2D:
            machine_info += "Argonaut RISC Core"
        elif self.e_machine == 0x2E:
            machine_info += "Hitachi H8/300"
        elif self.e_machine == 0x2F:
            machine_info += "Hitachi H8/300H"
        elif self.e_machine == 0x30:
            machine_info += "Hitachi H8S"
        elif self.e_machine == 0x31:
            machine_info += "Hitachi H8/500"
        elif self.e_machine == 0x32:
            machine_info += "IA-64"
        elif self.e_machine == 0x33:
            machine_info += "Stanford MIPS-X"
        elif self.e_machine == 0x34:
            machine_info += "Motorola ColdFire"
        elif self.e_machine == 0x35:
            machine_info += "Motorola M68HC12"
        elif self.e_machine == 0x36:
            machine_info += "Fujitsu MMA Multimedia Accelerator"
        elif self.e_machine == 0x37:
            machine_info += "Siemens PCP"
        elif self.e_machine == 0x38:
            machine_info += "Sony nCPU embedded RISC processor"
        elif self.e_machine == 0x39:
            machine_info += "Denso NDR1 microprocessor"
        elif self.e_machine == 0x3A:
            machine_info += "Motorola Star*Core processor"
        elif self.e_machine == 0x3B:
            machine_info += "Toyota ME16 processor"
        elif self.e_machine == 0x3C:
            machine_info += "STMicroelectronics ST100 processor"
        elif self.e_machine == 0x3D:
            machine_info += "Advanced Logic Corp. TinyJ embedded processor family"
        elif self.e_machine == 0x3E:
            machine_info += "AMD x86-64"
        elif self.e_machine == 0x8C:
            machine_info += "TMS320C6000 Family"
        elif self.e_machine == 0xAF:
            machine_info += "MCST Elbrus e2k"
        elif self.e_machine == 0xB7:
            machine_info += "ARM 64-bits (ARMv8/Aarch64)"
        elif self.e_machine == 0xF3:
            machine_info += "RISC-V"
        elif self.e_machine == 0xF7:
            machine_info += "Berkeley Packet Filter"
        elif self.e_machine == 0x101:
            machine_info += "WDC 65C816"
        self.logger.info(machine_info)

    def print_e_version(self):
        e_version_info = "e_version["
        if self.e_vesrion == 0:
            e_version_info += "EV_NONE]"
        elif self.e_vesrion >= 1:
            e_version_info += "EV_CURRENT]"
        e_version_info += " : {}"
        self.logger.info(e_version_info.format(self.e_vesrion))

    def print_e_flags(self):
        e_flags_info = "e_flags : {} - "
        if self.e_flags & 0xffff00 == 0xffff00:
            e_flags_info += "EF_SPARC_EXT_MASK | "
        if self.e_flags & 0x000100 == 0x000100:
            e_flags_info += "EF_SPARC_32PLUS | "
        if self.e_flags & 0x000200 == 0x000200:
            e_flags_info += "EF_SPARC_SUN_US1 | "
        if self.e_flags & 0x000400 == 0x000400:
            e_flags_info += "EF_SPARC_HAL_R1 | "
        if self.e_flags & 0x000800 == 0x000800:
            e_flags_info += "EF_SPARC_SUN_US3 | "
        if self.e_flags & 0x3 == 0x3:
            e_flags_info += "EF_SPARCV9_MM | "
        if self.e_flags & 0x0 == 0x0:
            e_flags_info += "EF_SPARCV9_TSO | "
        if self.e_flags & 0x1 == 0x1:
            e_flags_info += "EF_SPARCV9_PSO | "
        if self.e_flags & 0x2 == 0x2:
            e_flags_info += "EF_SPARCV9_RMO | "

        e_flags_info = e_flags_info[:-2]
        self.logger.info(e_flags_info.format(hex(self.e_flags)))
