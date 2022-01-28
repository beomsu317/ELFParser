import logging
import coloredlogs
import struct

from Formats.ElfHeader import ElfHeader
from Formats.ProgramHeaders import ProgramHeaders
from Formats.Sections import Sections


class ElfParser:
    def __init__(self, file):
        self.logger = logging.getLogger()
        self.file = file
        self.elf_header = None
        self.program_headers = None
        self.sections = None

    def parseElf(self):
        with open(self.file, 'rb') as f:
            data = f.read()
        self.parse_header(data)

        self.parse_program_headers(data)

        self.parse_sections(data)

    def parse_header(self, data):
        self.elf_header = ElfHeader()
        self.elf_header.parse(data)
        # self.elf_header.print_elf_header()

    def parse_program_headers(self, data):
        self.program_headers = ProgramHeaders(self.elf_header)
        self.program_headers.parse(data)
        self.program_headers.print_program_headers()

    def parse_sections(self, data):
        self.sections = Sections(self.elf_header)
        self.sections.parse_section_headers(data)
        # self.sections.print_section_headers()

        self.sections.parse_sections(data)
        # self.sections.print_sections()


if __name__ == "__main__":
    logger = logging.getLogger()
    coloredlogs.install(level='DEBUG')
    file = "/Users/beomsulee/Desktop/AppGuard/SampleProjects/CPPProject/app/release/app-release/BetterZip Recovered Files 1/lib/armeabi-v7a/libcpp.so"
    # file = "/Users/beomsulee/Desktop/AppGuard/SampleProjects/CPPProject/app/release/app-release/BetterZip Recovered Files 1/lib/arm64-v8a/libcpp.so"
    # file = "/Users/beomsulee/Desktop/AppGuard/TEST/issue/swordmaster/libpmt.so"
    # file = "/Users/beomsulee/Desktop/AppGuard/TEST/issue/swordmaster/libpmt_fix.so"

    # data = None
    # with open(file, 'rb') as f:
    #     data = f.read()
    #
    # data = data[:0x2a] + struct.pack('<H', 0x20) + data[0x2c:]
    # data = data[:0x3a] + struct.pack('<H', 0x28) + data[0x3c:]
    # with open("/Users/beomsulee/Desktop/AppGuard/TEST/issue/swordmaster/libpmt_fix.so", 'wb') as f:
    #     f.write(data)

    e = ElfParser(file)
    e.parseElf()

    # # elif self.e_machine == 0x0:
    # #     machine_info("No specific instruction set")
    # for line in text.split('\n'):
    #     splitted = line.split('\t')
    #     print(f"elif self.e_machine == {splitted[0]}:")
    #     print(f"    machine_info += \"{splitted[1]}\"")
