import sys
import lief


def print_symbols_in_section(file_path, section_name):
    # Cargar el archivo binario
    binary = lief.ELF.parse(file_path)

    # Obtener la sección deseada
    section = binary.get_section(section_name)
    if section is None:
        print(f"La sección '{section_name}' no fue encontrada.")
        return

    # Obtener los símbolos y filtrar los que pertenecen a la sección
    section_symbols = []
    for symbol in binary.symbols:
        if symbol.section and symbol.section.name == section_name:
            # if symbol.shndx == 15
            if 0x00426318 <= symbol.value <= 0x004295C8:
                section_symbols.append(symbol)

    if not section_symbols:
        print(f"No hay símbolos en la sección '{section_name}'.")
        return

    # Imprimir los símbolos
    print(f"Símbolos en la sección '{section_name}':")
    for symbol in section_symbols:
        print(symbol.name)


def print_string_hex(string, encoding='utf-8'):
    # Convertir el string a bytes en la codificación especificada
    if isinstance(string, str):
        encoded_string = string.encode(encoding)
    else:
        encoded_string = string

    # Iterar sobre cada byte en el string codificado
    for byte in encoded_string:
        # Obtener el valor hexadecimal del byte
        hex_value = format(byte, '02x')  # '02x' para asegurar que tenga 2 caracteres y esté en minúsculas
        # Imprimir el valor hexadecimal
        print(hex_value, end=' ')

    # Imprimir una nueva línea al final
    print()


def utf8_a_shiftjis(string_utf8):
    encoding = 'cp932'
    encoding = 'shift_jis'
    # print_string_hex(string_utf8)
    # print(string_utf8)
    string_utf8 = string_utf8.encode()
    string_shiftjis = string_utf8.decode('utf-8').encode(encoding)
    # print_string_hex(string_shiftjis, encoding)
    return string_shiftjis


def convertir_a_bytearray_con_padding(archivo_entrada):
    # Lista para almacenar los bytearrays convertidos
    bytearrays_con_padding = []
    padding = 4
    # Abrir el archivo en modo de lectura
    with open(archivo_entrada, 'r', encoding='utf-8') as archivo:
        # Leer cada línea del archivo
        for linea in archivo:
            # Eliminar espacios en blanco al principio y al final de la línea
            linea = linea.strip()
            linea = linea.replace('＇', '')
            linea = linea.replace('＂', '')
            linea = linea.replace('－', '')
            string_shift_jis = utf8_a_shiftjis(linea)

            # Convertir la línea a bytearray
            bytearray_linea = bytearray(string_shift_jis)
            # Calcular la longitud actual del bytearray
            longitud_actual = len(bytearray_linea)
            # Calcular la cantidad de bytes de padding necesarios
            padding_necesario = padding - (longitud_actual % padding)
            # Añadir el padding al bytearray
            bytearray_linea.extend(b'\x00' * padding_necesario)
            # Agregar el bytearray con padding a la lista
            bytearrays_con_padding.append(bytearray_linea)

    return bytearrays_con_padding


def modify_symbol_pointer(ruta_archivo, posicion, nuevo_valor):
    with open(ruta_archivo, "r+b") as archivo:
        archivo.seek(posicion)
        archivo.write(int_to_little_endian_32(nuevo_valor))


# Función para convertir un entero de 32 bits en formato little endian a una secuencia de bytes
def int_to_little_endian_32(valor):
    return valor.to_bytes(4, byteorder='little', signed=False)


def fusionar_bytearrays(lista_bytearrays):
    # Crear un bytearray vacío
    bytearray_final = bytearray()

    # Recorrer la lista de bytearrays
    for bytearray_elemento in lista_bytearrays:
        # Agregar el bytearray actual al bytearray final
        bytearray_final.extend(bytearray_elemento)

    return bytearray_final


def add_section_to_elf(elf_file, section_name, content_data, output_file):
    # # Read content file
    # with open(content_file, 'rb') as content:
    #     content_data = content.read()

    bytearray_fusionado = fusionar_bytearrays(content_data)

    # Open the original ELF file
    binary = lief.ELF.parse(elf_file)

    # Create a new section
    new_section = lief.ELF.Section(section_name)
    new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
    new_section.flags = lief.ELF.SECTION_FLAGS.ALLOC
    new_section.alignment = 8
    new_section.content = bytearray_fusionado
    new_section.size = len(new_section.content)

    # Add the new section to the binary
    binary.add(new_section)

    # Save the modified binary to the output file
    binary.write(output_file)

    section = binary.get_section(".trans")
    section_vma = section.file_offset + 0x8000
    section.virtual_address = section_vma
    binary.write(output_file)

    print("Section added successfully to", output_file, "VMA", section_vma, "Size", new_section.size)
    return section_vma


def updates_symbols_references(output_file, section_vma, content_data, rva, entry_size):
    data_offset = 0
    symbol_offset = 0
    for data in content_data:
        data_address = section_vma + data_offset
        symbol_address = rva + symbol_offset
        modify_symbol_pointer(output_file, symbol_address, data_address)
        data_offset += len(data)
        symbol_offset += entry_size
        # print("Updated symbol at address ", symbol_address, "to point at VMA", data_address, "file offset", data_address - 0x8000)


def text_inject(input_file, content_file, output_file):
    # print_symbols_in_section(input_file, ".rodata")
    lect_content_data = convertir_a_bytearray_con_padding(content_file)
    section_vma = add_section_to_elf(input_file, ".trans", lect_content_data, output_file)

    lectdat_rva = 0x005A87FC
    lectdat_entry_size = 0x50
    updates_symbols_references(output_file, section_vma, lect_content_data, lectdat_rva, lectdat_entry_size)

    # print_symbols_in_section(output_file, ".rodata")
    # print_symbols_in_section(output_file, ".data")
    # print_symbols_in_section(output_file, ".trans")

    lsmenu_rva = 0x005B8B7C
    lsmenu_rva_entry_size = 0xc


if __name__ == "__main__":
    sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)
    # utf8_a_shiftjis("~c 96,96,96$W2730$H2730$w13$h16Ｗｅｌｃｏｍｅ　ｔｏ　ｔｈｅ　~c 128,112,80ｉｎｔｒｏｄｕｃｔｏｒｙ$nｄｉａｇｒａｍ！~c 96,96,96Ｉ＇ｌｌ　ｂｅ　ｔｅａｃｈｉｎｇ　ｙｏｕ　ｈｏｗ$nｔｏ　ｄｒｉｖｅ　ｔｈｅ　ｔｒａｉｎ．　　")
    if len(sys.argv) != 4:
        print("Usage: python add_section_to_elf.py <elf_file> <content_file> <output_file>")
    else:
        text_inject(sys.argv[1], sys.argv[2], sys.argv[3])
        print("patched elf in ", sys.argv[3])
