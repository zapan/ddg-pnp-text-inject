import sys
import lief

def add_section_to_elf(elf_file, section_name, content_file, output_file):
    try:
        # Read content file
        with open(content_file, 'rb') as content:
            content_data = content.read()

        # Convert content_data to a list of integers
        content_data_int = [int(byte) for byte in content_data]

        # Open the original ELF file
        binary = lief.ELF.parse(elf_file)

        # Create a new section
        new_section = lief.ELF.Section(section_name)
        new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
        new_section.flags = lief.ELF.SECTION_FLAGS.ALLOC
        new_section.alignment = 8
        # new_section.content = content_data_int
        new_section.content = bytearray(content_data)
        new_section.size = len(new_section.content)
        new_section.virtual_address = 1500000

        # Add the new section to the binary
        binary.add(new_section)

        # Save the modified binary to the output file
        binary.write(output_file)

        print("Section added successfully to", output_file)
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python add_section_to_elf.py <elf_file> <content_file> <output_file>")
    else:
        elf_file = sys.argv[1]
        content_file = sys.argv[2]
        output_file = sys.argv[3]
        add_section_to_elf(elf_file, ".trans", content_file, output_file)
