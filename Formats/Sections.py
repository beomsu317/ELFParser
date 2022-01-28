from Formats.Dynsym import Dynsym
from Formats.Parser import Parser
from Formats.SectionHeader import SectionHeader


class Sections(Parser):
    def __init__(self, elf_header):
        super().__init__()
        self.elf_header = elf_header
        self.section_headers = []
        self.dynsyms = []
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
            if section_header.name == ".dynsym":
                dynsym_data = data[
                              section_header.sh_offset:section_header.sh_offset + section_header.sh_size]
                if self.elf_header.e_ident.EI_CLASS == 0x1:
                    size = 0x10
                elif self.elf_header.e_ident.EI_CLASS == 0x2:
                    size = 0x18
                for idx in range(0, int(section_header.sh_size / size)):
                    dynsym = Dynsym(self.elf_header, section_header)
                    dynsym.parse(dynsym_data, idx, size)
                    self.dynsyms.append(dynsym)
            elif section_header.name == ".dynstr":
                self.dynstr_section_header = section_header
            else:
                self.logger.debug(section_header.name)


        for dynsym in self.dynsyms:
            idx = 0
            while True:
                c = data[self.dynstr_section_header.sh_offset + dynsym.st_name + idx]
                if c == 0x0:
                    break
                dynsym.name += chr(c)
                idx += 1

    def print_sections(self):
        for section in self.sections:
            if type(section) is DynamicSymbols:
                section.print_dynamic_symbols()
