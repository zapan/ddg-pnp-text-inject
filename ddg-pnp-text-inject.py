import os
import sys
import lief


def print_symbols_menu_in_section(file_path, section_name):
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

    string_utf8 = string_utf8.strip()
    string_utf8 = string_utf8.replace('＇', '')
    string_utf8 = string_utf8.replace('＂', '')
    string_utf8 = string_utf8.replace('－', '')

    before = string_utf8

    string_utf8 = string_utf8.encode()

    try:
        string_shiftjis = string_utf8.decode('utf-8').encode(encoding)
    except UnicodeEncodeError as e:
        print(e, "error", before)
        sys.exit()

    z = len(string_shiftjis)
    if z >= 265:
        print("String exceeds maximum length 265. Shift-JIS length is", str(z).zfill(3), "| CONTENT:", before)

        # print("SJIS Len", str(z).zfill(3), "| CONTENT:", before)
    # print_string_hex(string_utf8)
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


def overwrite_section(output_file, content_data, offset):
    bytearray_fusionado = fusionar_bytearrays(content_data)
    with open(output_file, 'r+b') as archivo_destino:
        archivo_destino.seek(offset)
        archivo_destino.write(bytearray_fusionado)
        current = archivo_destino.tell()
    return current


def setup_elf_padding(input_file, output_file):
    path = os.path.dirname(os.path.abspath(output_file))
    rodata_pad = path + "/dgf_rodata_padded"
    command = ""
    if not os.path.exists(rodata_pad):
        command += 'arm-none-eabi-objdump -h ' + input_file + '| grep .rodata | awk \'{print "dd if=' + input_file + ' of=' + rodata_pad + ' bs=1 count=$((0x"$3")) skip=$((0x"$6"))"}\' | bash ;'
        command += "dd if=/dev/zero count=128 >> " + rodata_pad + ";"

    command += "arm-none-eabi-objcopy --input-target elf32-littlearm --output-target elf32-littlearm --update-section .rodata=" + rodata_pad + " " + input_file + " " + output_file
    # print(command)
    out = os.system(command)
    if out != 0:
        print("Unable to setup rodata padding in " + output_file)
        sys.exit()

    print("Padded rodata in " + output_file)


def find_magic_bytes(archivo, secuencia):
    with open(archivo, 'rb') as f:
        datos = f.read()

    secuencia = secuencia.replace(' ', '')
    secuencia_bytes = bytes.fromhex(secuencia)
    offset = datos.find(secuencia_bytes)
    return offset


def text_inject(input_file, output_file, lect_file, ls_menu_file):
    setup_elf_padding(input_file, output_file)
    lect_content_data = convertir_a_bytearray_con_padding(lect_file)
    ls_menu_content_data = convertir_a_bytearray_con_padding(ls_menu_file)

    lect_section_offset = 0x496DD0
    file_pointer = overwrite_section(output_file, lect_content_data, lect_section_offset)

    padding = 8
    padding_necesario = padding - (file_pointer % padding)
    ls_menu_section_offset = file_pointer + padding_necesario + 128
    overwrite_section(output_file, ls_menu_content_data, ls_menu_section_offset)

    lectdat_rva = 0x5B87FC  # 0x5A87FC + 0x10000 (64k)
    lectdat_entry_size = 0x50
    lect_section_vma = lect_section_offset + 0x8000
    updates_symbols_references(output_file, lect_section_vma, lect_content_data, lectdat_rva, lectdat_entry_size)

    magic_bytes_off = find_magic_bytes(output_file, "01000000 C8AF4200")
    if magic_bytes_off > -1:
        # 0x5C8B78 = 0x5B8B78 + 0x10000 (64k)
        ls_menu_rva = magic_bytes_off + 4
        print("Magic bytes 01000000 C8AF4200 found at", hex(magic_bytes_off), "Starts at", hex(ls_menu_rva))
        ls_menu_entry_size = 0xc
        ls_menu_section_vma = ls_menu_section_offset + 0x8000
        updates_symbols_references(output_file, ls_menu_section_vma, ls_menu_content_data, ls_menu_rva, ls_menu_entry_size)


if __name__ == "__main__":
    sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf8', buffering=1)
    if len(sys.argv) != 5:
        print("Usage: python ddg-pnp-text-inject.py <elf_source> <eld_patched> <lect_path> <menu_path>")
    else:
        text_inject(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
        print("Text patched OK. Result in", sys.argv[2])
