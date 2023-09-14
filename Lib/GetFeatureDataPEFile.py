import csv
import pandas as pd
import lief
import os
import re

dos_header = [
    "addressof_new_exeheader",
    "addressof_relocation_table",
    "checksum",
    "file_size_in_pages",
    "header_size_in_paragraphs",
    "initial_ip",
    "initial_relative_cs",
    "initial_relative_ss",
    "initial_sp",
    "magic",
    "maximum_extra_paragraphs",
    "minimum_extra_paragraphs",
    "numberof_relocation",
    "oem_id",
    "oem_info",
    "overlay_number",
    "used_bytes_in_the_last_page",
]

header = [
    "numberof_sections",
    "numberof_symbols",
    "pointerto_symbol_table",
    "signature",
    "sizeof_optional_header",
    "time_date_stamps",
]

optional_header = [
    "addressof_entrypoint",
    "baseof_code",
    "baseof_data",
    "checksum",
    "computed_checksum",
    "dll_characteristics",
    "file_alignment",
    "imagebase",
    "loader_flags",
    "magic",
    "major_image_version",
    "major_linker_version",
    "major_operating_system_version",
    "major_subsystem_version",
    "minor_image_version",
    "minor_linker_version",
    "minor_operating_system_version",
    "minor_subsystem_version",
    "numberof_rva_and_size",
    "section_alignment",
    "sizeof_code",
    "sizeof_headers",
    "sizeof_heap_commit",
    "sizeof_heap_reserve",
    "sizeof_image",
    "sizeof_initialized_data",
    "sizeof_stack_commit",
    "sizeof_stack_reserve",
    "sizeof_uninitialized_data",
    "subsystem",
    "win32_version_value",
]

data_directory = [
    "has_section",
    "rva",
    "section",
    "size",
    "type",
]

data_directory_list = [
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
    "RESERVED"
]

data_directory_dict_value = {
    "EXPORT_TABLE": 0,
    "IMPORT_TABLE": 1,
    "RESOURCE_TABLE": 2,
    "EXCEPTION_TABLE": 3,
    "CERTIFICATE_TABLE": 4,
    "BASE_RELOCATION_TABLE": 5,
    "DEBUG": 6,
    "ARCHITECTURE": 7,
    "GLOBAL_PTR": 8,
    "TLS_TABLE": 9,
    "LOAD_CONFIG_TABLE": 10,
    "BOUND_IMPORT": 11,
    "IAT": 12,
    "DELAY_IMPORT_DESCRIPTOR": 13,
    "CLR_RUNTIME_HEADER": 14,
    "RESERVED": 15
}

Section = [
    "characteristics",
    # "characteristics_lists",
    "entropy",
    "name",
    "numberof_line_numbers",
    "numberof_relocations",
    "offset",
    "pointerto_line_numbers",
    "pointerto_raw_data",
    "pointerto_relocation",
    "size",
    "sizeof_raw_data",
    "virtual_address",
    "virtual_size"
]

section_characteristics_list = [
    "TYPE_NO_PAD",
    "CNT_CODE",
    "CNT_INITIALIZED_DATA",
    "CNT_UNINITIALIZED_DATA",
    "LNK_OTHER",
    "LNK_INFO",
    "LNK_REMOVE",
    "LNK_COMDAT",
    "GPREL",
    "MEM_PURGEABLE",
    "MEM_16BIT",
    "MEM_LOCKED",
    "MEM_PRELOAD",
    "ALIGN_1BYTES",
    "ALIGN_2BYTES",
    "ALIGN_4BYTES",
    "ALIGN_8BYTES",
    "ALIGN_16BYTES",
    "ALIGN_32BYTES",
    "ALIGN_64BYTES",
    "ALIGN_128BYTES",
    "ALIGN_256BYTES",
    "ALIGN_512BYTES",
    "ALIGN_1024BYTES",
    "ALIGN_2048BYTES",
    "ALIGN_4096BYTES",
    "ALIGN_8192BYTES",
    "LNK_NRELOC_OVFL",
    "MEM_DISCARDABLE",
    "MEM_NOT_CACHED",
    "MEM_NOT_PAGED",
    "MEM_SHARED",
    "MEM_EXECUTE",
    "MEM_READ",
    "MEM_WRITE"
]

section_characteristics_list_value = {
    "TYPE_NO_PAD": 8,
    "CNT_CODE": 32,
    "CNT_INITIALIZED_DATA": 64,
    "CNT_UNINITIALIZED_DATA": 128,
    "LNK_OTHER": 256,
    "LNK_INFO": 512,
    "LNK_REMOVE": 2048,
    "LNK_COMDAT": 4096,
    "GPREL": 32768,
    "MEM_PURGEABLE": 65536,
    "MEM_16BIT": 131072,
    "MEM_LOCKED": 262144,
    "MEM_PRELOAD": 524288,
    "ALIGN_1BYTES": 1048576,
    "ALIGN_2BYTES": 2097152,
    "ALIGN_4BYTES": 3145728,
    "ALIGN_8BYTES": 4194304,
    "ALIGN_16BYTES": 5242880,
    "ALIGN_32BYTES": 6291456,
    "ALIGN_64BYTES": 7340032,
    "ALIGN_128BYTES": 8388608,
    "ALIGN_256BYTES": 9437184,
    "ALIGN_512BYTES": 10485760,
    "ALIGN_1024BYTES": 11534336,
    "ALIGN_2048BYTES": 12582912,
    "ALIGN_4096BYTES": 13631488,
    "ALIGN_8192BYTES": 14680064,
    "LNK_NRELOC_OVFL": 16777216,
    "MEM_DISCARDABLE": 33554432,
    "MEM_NOT_CACHED": 67108864,
    "MEM_NOT_PAGED": 134217728,
    "MEM_SHARED": 268435456,
    "MEM_EXECUTE": 536870912,
    "MEM_READ": 1073741824,
    "MEM_WRITE": 2147483648
}

Import = ["name",
          "forwarder_chain",
          "timedatestamp",
          "import_address_table_rva",
          "import_lookup_table_rva", ]

Import_Entry = [
    "data",
    "hint",
    "iat_address",
    "iat_value",
    "is_ordinal",
    "name",
    "ordinal",
    "size",
    "value",
]

exportFunction = [
    "DeleteService",
    "GetFileAttributesW",
    "TerminateProcess",
    "CreateRemoteThread",
    "CreateThread",
    "WriteProcessMemory",
    "CryptExportKey",
    "CryptDecrypt",
    "CryptAcquireContext",
    "CryptGenKey",
    "RtlCreateUserThread",
    "NtUnmapViewOfSection",
    "IsDebuggerPresent",
    "OutputDebugStringA",
    "HttpSendRequestA",
    "InternetOpenA",
    "InternetConnectA",
    "HttpOpenRequestA",
    "InternetReadFile",
    "InternetCrackUrlA",
    "CreateServiceA",
    "StartServiceA",
    "HttpAddRequestHeadersA",
    "InternetSetOptionA",
    "ShellExecuteA",
    "RegSetValueExA",
    "RegCreateKeyExA",
    "GetSystemTimeAsFileTime",
    "GetTickCount",
    "QueryPerformanceCounter",
    "GetCurrentThreadId",
    "GetCommandLineA",
    "GetVersion",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "InternetWriteFile",
    "InternetCloseHandle",
    "LoadResource",
    "FindResourceA",
    "LockResource",
    "SizeofResource",
    "GlobalAlloc",
    "GlobalFree",
    "GetTempPathA",
    "GetTempFileNameA",
    "CreateFileA",
    "WriteFile",
    "CloseHandle",
    "VirtualAllocEx",
    "GetThreadContext",
    "SetThreadContext",
    "ResumeThread",
    "NtQueueApcThread",
    "NtTestAlert",
    "GetStartupInfoA",
    "InternetOpenUrlA",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "OpenProcess",
    "ReadProcessMemory",
    "CryptUnprotectData",
    "RegOpenKeyExA",
    "RegQueryValueExA",
    "RegCloseKey",
    "EnumWindows",
    "GetWindowTextA",
    "SendMessageA",
    "OpenWindowStationA",
    "OpenDesktopA",
    "EnumDesktopWindows",
    "FindWindowA",
    "VirtualAlloc",
    "VirtualProtect",
    "GetVersionExA",
    "HeapCreate",
    "HeapAlloc",
    "HeapFree",
    "HeapDestroy",
    "GetEnvironmentVariableA",
    "SetEnvironmentVariableA",
    "UnmapViewOfFile",
    "CreateNamedPipeA",
    "ConnectNamedPipe",
    "DisconnectNamedPipe",
    "CreateProcessA",
    "ExitProcess",
    "FreeLibrary",
    "Inject@4",
    "LoopInject@4",
    "IsPatched",
    "GetGlobalKey",
    "CheckUnblock"
]
# Read CSV data
df0 = pd.read_csv("csvdata/category_encoding.csv")
encoding_dict0 = dict(zip(df0.CategoryName, df0.Encoding))

df = pd.read_csv("csvdata/data_directory_section_name_encoding_dict.csv")
encoding_dict = dict(zip(df.SectionName, df.Encoding))

df1 = pd.read_csv("csvdata/library_name.csv")
encoding_dict1 = dict(zip(df1.LibraryName, df1.Encoding))

df2 = pd.read_csv("csvdata/importedfunction.csv")
encoding_dict2 = dict(zip(df2.ImportedFunction, df2.Encoding))

def extract_malware_family(file_path):
    # Lấy tên file từ đường dẫn
    file_name = os.path.basename(file_path)

    if "." not in file_name:
        # Tạo biểu thức chính quy để trích xuất tên họ mã độc
        pattern = r"Blacklist_(\w+)_"
    else:
        pattern = r"Blacklist_(\w+)."

    # Tìm kiếm tên họ mã độc trong tên file
    match = re.search(pattern, file_name)

    if match:
        # Lấy phần tên họ mã độc từ kết quả tìm kiếm
        malware_family = match.group(1)
    else:
        # Nếu không tìm thấy, gán giá trị là "benign"
        malware_family = "benign"

    return malware_family

def extract_malware_family_virusshare(file_path):
    # Lấy tên file từ đường dẫn
    file_name = os.path.basename(file_path)

    if "." not in file_name:
        # Tạo biểu thức chính quy để trích xuất tên họ mã độc
        pattern = r"VirusShare_\w+_(\w+)_"
    else:
        pattern = r"VirusShare_\w+_(\w+)."

    # Tìm kiếm tên họ mã độc trong tên file
    match = re.search(pattern, file_name)

    if match:
        # Lấy phần tên họ mã độc từ kết quả tìm kiếm
        malware_family = match.group(1)
    else:
        # Nếu không tìm thấy, gán giá trị là "benign"
        malware_family = "benign"

    return malware_family

def extract_malware_family_outfile(file_path):
    # Lấy tên file từ đường dẫn
    file_name = os.path.basename(file_path)

    pattern = r'_([^.]+)\.'

    # Tìm kiếm tên họ mã độc trong tên file
    match = re.search(pattern, file_name)

    if match:
        # Lấy phần tên họ mã độc từ kết quả tìm kiếm
        malware_family = match.group(1)
    else:
        # Nếu không tìm thấy, gán giá trị là "benign"
        malware_family = "benign"

    return malware_family

def getFileName(filepath):
    return os.path.basename(filepath)


def getLabel(filepath):
    label = 0 if "whitelist" in getFileName(filepath).lower() else 1
    return label

def getCategoryNameOutFiles(filepath):
    category_name = extract_malware_family_outfile(filepath)
    return category_name

def getCategoryNameVirusShare(filepath):
    category_name = extract_malware_family_virusshare(filepath)
    return category_name

def getCategoryEncodingOutFiles(filepath):
    new_data = []
    encoding_dict0 = dict(zip(df0.CategoryName, df0.Encoding))
    if getCategoryNameOutFiles(filepath) not in encoding_dict0:
        new_category_name = getCategoryNameOutFiles(filepath)
        new_encoding = max(encoding_dict0.values()) + 1
        encoding_dict0[new_category_name] = new_encoding
        # Lưu từ điển cập nhật vào tệp CSV
        df = pd.DataFrame(list(encoding_dict0.items()), columns=["CategoryName", "Encoding"])
        df.to_csv("csvdata/category_encoding.csv", index=False)
        new_data.append(encoding_dict0[getCategoryNameOutFiles(filepath)])
    else:
        new_data.append(encoding_dict0[getCategoryNameOutFiles(filepath)])
    return new_data

def getCategoryEncodingVirusShare(filepath):
    new_data = []
    encoding_dict0 = dict(zip(df0.CategoryName, df0.Encoding))
    if getCategoryNameVirusShare(filepath) not in encoding_dict0:
        new_category_name = getCategoryNameVirusShare(filepath)
        new_encoding = max(encoding_dict0.values()) + 1
        encoding_dict0[new_category_name] = new_encoding
        # Lưu từ điển cập nhật vào tệp CSV
        df = pd.DataFrame(list(encoding_dict0.items()), columns=["CategoryName", "Encoding"])
        df.to_csv("csvdata/category_encoding.csv", index=False)
        new_data.append(encoding_dict0[getCategoryNameVirusShare(filepath)])
    else:
        new_data.append(encoding_dict0[getCategoryNameVirusShare(filepath)])
    return new_data

def getCategoryName(filepath):
    category_name = extract_malware_family(filepath)
    return category_name


def getCategoryEncoding(filepath):
    new_data = []
    encoding_dict0 = dict(zip(df0.CategoryName, df0.Encoding))
    if getCategoryName(filepath) not in encoding_dict0:
        new_category_name = getCategoryName(filepath)
        new_encoding = max(encoding_dict0.values()) + 1
        encoding_dict0[new_category_name] = new_encoding
        # Lưu từ điển cập nhật vào tệp CSV
        df = pd.DataFrame(list(encoding_dict0.items()), columns=["CategoryName", "Encoding"])
        df.to_csv("csvdata/category_encoding.csv", index=False)
        new_data.append(encoding_dict0[getCategoryName(filepath)])
    else:
        new_data.append(encoding_dict0[getCategoryName(filepath)])

    return new_data


def getDosHeader(pe):
    new_data = []
    for feature in dos_header:
        value = getattr(pe.dos_header, feature, None)
        new_data.append(value)
    return new_data

def getHeaderCharacteristics(pe):
    sum = 0
    characteristics_list = pe.header.characteristics_list
    for characteristic in characteristics_list:
        sum = sum + characteristic.value
    return sum


def getHeader(pe):
    new_data = []
    value = pe.header.machine.value
    new_data.append(value)
    for feature in header:
        value = getattr(pe.header, feature, None)
        if feature == "signature":
            total = 0
            for item in value:
                total = total + item
            new_data.append(total)
        else:
            new_data.append(value)
    return new_data


def getOptionalHeader(pe):
    new_data = []
    for feature in optional_header:
        if feature == "magic":
            value = pe.optional_header.magic.value
            new_data.append(value)
        elif feature == "subsystem":
            value = pe.optional_header.subsystem.value
            new_data.append(value)
        else:
            value = getattr(pe.optional_header, feature, None)
            new_data.append(value)
    return new_data


def getDataDirectory(pe):
    new_data = []
    for i in range(0, 16):
        for feature in data_directory:
            if feature == "has_section":
                value = getattr(pe.data_directories[i], feature, None)
                if value is False:
                    new_data.append(0)
                else:
                    new_data.append(1)

            if feature == "rva":
                value = getattr(pe.data_directories[i], feature, None)
                new_data.append(value)

            if feature == "size":
                value = getattr(pe.data_directories[i], feature, None)
                new_data.append(value)

            if feature == "type":
                value = getattr(pe.data_directories[i], feature, None)
                new_data.append(value.value)

            if feature == "section":
                value = getattr(pe.data_directories[i], feature, None)
                for ft in Section:
                    if ft == "name":
                        valuex = getattr(pe.data_directories[i].section, ft, None)
                        if valuex is not None:
                            if valuex not in encoding_dict:
                                new_section_name = valuex
                                # Nếu không, thêm nó vào từ điển với một giá trị mới
                                new_encoding = max(encoding_dict.values()) + 1
                                encoding_dict[new_section_name] = new_encoding
                                # Lưu từ điển cập nhật vào tệp CSV
                                df = pd.DataFrame(list(encoding_dict.items()),
                                                  columns=["SectionName", "Encoding"])
                                df.to_csv("csvdata/data_directory_section_name_encoding_dict.csv", index=False)
                                new_data.append(encoding_dict[valuex])
                            else:
                                new_data.append(encoding_dict[valuex])
                        else:
                            new_data.append(0)
                    elif value is not None:
                        valuee = getattr(value, ft, None)
                        if valuee is None:
                            new_data.append(0)
                        else:
                            new_data.append(valuee)
                    else:
                        new_data.append(0)
    return new_data


def getSection(pe):
    new_data = []
    section_count = 0

    for section in pe.sections:
        section_count += 1
        if section_count > 5:
            break
        for feature in Section:
            try:
                value = getattr(section, feature, None)
            except Exception as e:
                print(e)
            if isinstance(value, str):
                if value in encoding_dict:
                    new_data.append(encoding_dict[value])
                else:
                    new_section_name = value
                    new_encoding = max(encoding_dict.values()) + 1
                    encoding_dict[new_section_name] = new_encoding
                    df = pd.DataFrame(list(encoding_dict.items()), columns=["SectionName", "Encoding"])
                    df.to_csv("csvdata/data_directory_section_name_encoding_dict.csv", index=False)
                    new_data.append(new_encoding)
            else:
                new_data.append(value)
    # Chèn các số 0 vào new_data nếu số lượng section không đủ 5
    if section_count < 5:
        remaining_sections = 5 - section_count
        remaining_features = remaining_sections * len(Section)
        new_data.extend([0] * remaining_features)

    if section_count >= 5:
        new_data.append(1)
    else:
        new_data.append(0)
    return new_data


def getImportSection(pe):
    new_data = []
    try:
        import_directory = pe.imports[0].directory
        for feature in data_directory:
            if feature == "has_section":
                value = getattr(import_directory, feature, None)
                if value is False:
                    new_data.append(0)
                else:
                    new_data.append(1)

            if feature == "rva":
                value = getattr(import_directory, feature, None)
                new_data.append(value)

            if feature == "size":
                value = getattr(import_directory, feature, None)
                new_data.append(value)

            if feature == "type":
                value = getattr(import_directory, feature, None)
                new_data.append(value.value)

            if feature == "section":
                value = getattr(import_directory, feature, None)
                for ft in Section:
                    if ft == "name":
                        valuex = getattr(import_directory.section, ft, None)
                        if valuex is not None:
                            if valuex not in encoding_dict:
                                new_section_name = valuex
                                # Nếu không, thêm nó vào từ điển với một giá trị mới
                                new_encoding = max(encoding_dict.values()) + 1
                                encoding_dict[new_section_name] = new_encoding
                                # Lưu từ điển cập nhật vào tệp CSV
                                df = pd.DataFrame(list(encoding_dict.items()),
                                                  columns=["SectionName", "Encoding"])
                                df.to_csv("csvdata/data_directory_section_name_encoding_dict.csv", index=False)
                                new_data.append(encoding_dict[valuex])
                            else:
                                new_data.append(encoding_dict[valuex])
                        else:
                            new_data.append(0)
                    elif value is not None:
                        valuee = getattr(value, ft, None)
                        if valuee is None:
                            new_data.append(0)
                        else:
                            new_data.append(valuee)
                    else:
                        new_data.append(0)
    except:
        for i in range(17):
            new_data.append(0)
    return new_data


def getImportEntry(pe):
    new_data = []
    imported_count = 0
    max_imported_libraries = 5
    max_imported_functions = 5

    for imported_library in pe.imports:
        if imported_count < max_imported_libraries:
            imported_count += 1

            # Add imported library features
            for feature in Import:
                value = getattr(imported_library, feature, None)
                if value is not None:
                    if feature == "name":
                        if value not in encoding_dict1:
                            new_section_name = value
                            new_encoding = max(encoding_dict1.values()) + 1
                            encoding_dict1[new_section_name] = new_encoding
                            df = pd.DataFrame(list(encoding_dict1.items()),
                                              columns=["LibraryName", "Encoding"])
                            df.to_csv("csvdata/library_name.csv", index=False)
                        new_data.append(encoding_dict1[value])
                    else:
                        new_data.append(value)
                else:
                    new_data.append(0)

            # Add imported functions features
            imported_func_count = 0
            for entry in imported_library.entries:
                if imported_func_count < max_imported_functions:
                    imported_func_count += 1
                    for ft in Import_Entry:
                        value = getattr(entry, ft, None)
                        if value is not None:
                            if ft == "is_ordinal":
                                new_data.append(1 if value else 0)
                            elif ft == "name":
                                if value not in encoding_dict2:
                                    new_section_name = value
                                    new_encoding = max(encoding_dict2.values()) + 1
                                    encoding_dict2[new_section_name] = new_encoding
                                    df = pd.DataFrame(list(encoding_dict2.items()),
                                                      columns=["ImportedFunction", "Encoding"])
                                    df.to_csv("csvdata/importedfunction.csv", index=False)
                                new_data.append(encoding_dict2[value])
                            else:
                                new_data.append(value)
                        else:
                            new_data.append(0)

            # Padding zeros for remaining functions in this library
            for _ in range(max_imported_functions - imported_func_count):
                new_data.extend([0] * len(Import_Entry))

    # Padding zeros for remaining libraries
    for _ in range(max_imported_libraries - imported_count):
        new_data.extend([0] * (len(Import) + max_imported_functions * len(Import_Entry)))
    return new_data


def getTLS(pe):
    new_data = []
    if pe.has_tls:
        tls = pe.tls
        raw_data_start, raw_data_end = tls.addressof_raw_data
        new_data.append(tls.addressof_callbacks)
        new_data.append(tls.addressof_index)
        new_data.append(raw_data_start)
        new_data.append(raw_data_end)
        new_data.append(tls.characteristics)
        if tls.has_data_directory:
            new_data.append(1)
            new_data.append(tls.directory.rva)
            new_data.append(tls.directory.size)
            new_data.append(tls.directory.type.value)
            value = getattr(tls.directory.section, 'name', None)
            if value is not None:
                if value not in encoding_dict:
                    new_section_name = value
                    # Nếu không, thêm nó vào từ điển với một giá trị mới
                    new_encoding = max(encoding_dict.values()) + 1
                    encoding_dict[new_section_name] = new_encoding
                    # Lưu từ điển cập nhật vào tệp CSV
                    df = pd.DataFrame(list(encoding_dict.items()), columns=["SectionName", "Encoding"])
                    df.to_csv("csvdata/data_directory_section_name_encoding_dict.csv", index=False)
                    new_data.append(encoding_dict[value])
                else:
                    new_data.append(encoding_dict[value])
            else:
                new_data.append(0)
        else:
            for i in range(5):
                new_data.append(0)

        if tls.has_section:
            for ft in Section:
                if ft == "name":
                    pass
                else:
                    value = getattr(tls.section, ft, None)
                    if value is not None:
                        new_data.append(value)
                    else:
                        new_data.append(0)
        else:
            for i in range(12):
                new_data.append(0)
    else:
        for i in range(22):
            new_data.append(0)
    return new_data

if __name__ == "__main__":
    file_path = r"D:\2023-08-07-labelled\2023-08-09\0b48936f907ab57d10dbb6f61da2d7430708cc8bfb2e3560b0284216c63ccaef.exe_trojan.darkcloud.zusy_labelled"
    print()
