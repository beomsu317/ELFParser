import logging
import struct


class Parser:
    def __init__(self):
        self.logger = logging.getLogger()

    def parse(self, data):
        pass


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
        self.logger.info("p_flag : {}".format(hex(self.p_flags)))
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


class ProgramHeaders(Parser):
    def __init__(self, elf_header):
        super().__init__()
        self.elf_header = elf_header
        self.program_headers = []

    def parse(self, data):
        for i in range(self.elf_header.e_phnum):
            program_data = data[self.elf_header.e_phoff + (self.elf_header.e_phentsize * i):self.elf_header.e_phoff + (
                    self.elf_header.e_phentsize * i) + self.elf_header.e_phentsize]
            program_header = ProgramHeader(self.elf_header)
            program_header.parse(program_data)
            self.program_headers.append(program_header)

    def print_program_headers(self):
        self.logger.info("============[Program Headers]===========")
        for program_header in self.program_headers:
            program_header.print_program_header()


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
        self.logger.info("st_info : {}".format(hex(self.st_info)))
        self.logger.info("st_other : {}".format(hex(self.st_other)))
        self.logger.info("st_shndx : {}".format(hex(self.st_shndx)))
        self.logger.info("============================")

class DynamicSymbols(Parser):
    def __init__(self, elf_header, section_header):
        super().__init__()
        self.elf_header = elf_header
        self.section_header = section_header
        self.dynsyms = []

    def parse(self, data):
        dynsym_data = data[self.section_header.sh_offset:self.section_header.sh_offset + self.section_header.sh_size]
        if self.elf_header.e_ident.EI_CLASS == 0x1:
            size = 0x10
            for idx in range(0, int(self.section_header.sh_size / size)):
                dynsym = Dynsym(self.elf_header, self.section_header)
                dynsym.parse(dynsym_data, idx, size)
                self.dynsyms.append(dynsym)
        elif self.elf_header.e_ident.EI_CLASS == 0x2:
            size = 0x18
            for idx in range(0, int(self.section_header.sh_size / size)):
                dynsym = Dynsym(self.elf_header, self.section_header)
                dynsym.parse(dynsym_data, idx, size)
                self.dynsyms.append(dynsym)

    def print_dynamic_symbols(self):
        self.logger.info("=======================[Dynamic Symbols]=====================")
        for dynsym in self.dynsyms:
            dynsym.print_dynsym()
        self.logger.info("===========================================================")


class Sections(Parser):
    def __init__(self, elf_header):
        super().__init__()
        self.elf_header = elf_header
        self.section_headers = []
        self.sections = []
        self.strtab_section_header = None
        self.dynstr_section_header = None

    def parse_section_headers(self, data):
        for i in range(self.elf_header.e_shnum):
            secion_data = data[self.elf_header.e_shoff + (self.elf_header.e_shentsize * i): self.elf_header.e_shoff + (
                    self.elf_header.e_shentsize * i) + self.elf_header.e_shentsize]
            secion_header = SectionHeader(self.elf_header)
            secion_header.parse(secion_data)
            self.section_headers.append(secion_header)
        self.strtab_section_header = self.section_headers[self.elf_header.e_shstrndx]
        for section_header in self.section_headers:
            idx = 0
            while True:
                s = data[self.strtab_section_header.sh_offset + section_header.sh_name + idx]
                if s == 0x0:
                    break
                idx += 1
                section_header.name += chr(s)

    def print_section_headers(self):
        self.logger.info("============[Secion Headers]===========")
        for section_header in self.section_headers:
            section_header.print_section_header()

    def parse_sections(self, data):
        for section_header in self.section_headers:
            section = None
            if section_header.name == ".dynsym":
                section = DynamicSymbols(self.elf_header, section_header)
                section.parse(data)
            elif section_header.name == ".dynstr":
                self.dynstr_section_header = section_header
            else:
                self.logger.debug(section_header.name)


            self.sections.append(section)

        for section in self.sections:
            if type(section) is DynamicSymbols:
                for dynsym in section.dynsyms:
                    idx = 0
                    while True:
                        c = data[self.dynstr_section_header.sh_offset + dynsym.st_name + idx]
                        if c == 0x0:
                            break
                        dynsym.name += chr(c)
                        idx += 1
                break

    def print_sections(self):
        for section in self.sections:
            if type(section) is DynamicSymbols:
                section.print_dynamic_symbols()
