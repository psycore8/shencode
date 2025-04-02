import struct

def get_coff_section(file_name=str, section_name=str):
    with open(file_name, 'rb') as f:
        data = f.read()
    num_sections = struct.unpack_from("<H", data, 2)[0]
    section_offset = 0x14 
    # if has_optional_header:
    #     section_offset = section_offset + 20
    section_size = 40 
    for i in range(num_sections):
        section_data = data[section_offset + i * section_size : section_offset + (i + 1) * section_size]
        name = section_data[:8].strip(b"\x00").decode()
        if name == section_name:
            raw_data_offset = struct.unpack_from("<I", section_data, 20)[0]
            raw_data_size = struct.unpack_from("<I", section_data, 16)[0]
            text_data = data[raw_data_offset : raw_data_offset + raw_data_size]
            return text_data
    print(f'{section_name} not found!')
    return None

def replace_bytes_at_offset(data, offset, new_bytes):
    data = bytearray(data)
    data[offset] = int(new_bytes.encode('utf-8'))
    data.append(int(new_bytes))
    return bytes(data)