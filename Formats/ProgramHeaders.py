from Formats.Parser import Parser
from Formats.ProgramHeader import ProgramHeader


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
