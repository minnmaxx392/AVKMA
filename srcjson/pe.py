from os.path import join, basename
from re import search
from functools import reduce
from operator import add
from lief import parse
from lief._lief import Binary
from srcjson.file import get_content


def analyze(path: str):
    """
    Analyze PE file to analysis with our features
    """
    try:
        binary = parse(path)
    except:
        raise Exception("Invalid attachment! Only PE format is supported.")

    analysis = {}
    file_name = basename(path)
    label = __get_label(file_name)
    dos_header = __get_dos_header(binary=binary)
    header = get_header(binary=binary)
    optional_header = get_optional_header(binary=binary)
    data_directories = get_data_directories(binary=binary)
    sections = get_sections(binary=binary)
    _import = get_import(binary=binary)
    libraries = get_libraries(binary=binary)
    tls = get_tls(binary=binary)

    analysis["file_name"] = file_name
    analysis["label"] = label
    analysis["dos_header"] = dos_header
    analysis["header_characteristics"] = get_header_characteristics(binary=binary)
    analysis["header"] = header
    analysis["optional_header"] = optional_header
    analysis["data_directories"] = data_directories
    analysis["sections"] = sections
    analysis["import"] = _import
    analysis["libraries"] = libraries
    analysis["tls"] = tls
    return analysis


def __get_label(file_name: str):
    pattern = r"Blacklist_(\w+)_" if "." not in file_name else r"Blacklist_(\w+)."
    is_match = search(pattern, file_name)

    return is_match.group(1) if is_match else "benign"


def __get_dos_header(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "dos-header.txt"))
    dos_header = {}

    for field in fields:
        dos_header[field] = getattr(binary.dos_header, field, None)
    return dos_header


def get_header_characteristics(binary: Binary):
    characteristics = [characteristic.value for characteristic in binary.header.characteristics_list]
    header_characteristics = reduce(add, characteristics)

    return header_characteristics


def get_header(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "header.txt"))
    header = {}

    header["machine"] = binary.header.machine.value
    for field in fields:
        value = getattr(binary.header, field, None)
        header[field] = value if field != "signature" else reduce(add, value)
    return header


def get_optional_header(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "optional-header.txt"))
    optional_header = {}

    for field in fields:
        if field == "magic":
            value = binary.optional_header.magic.value
        elif field == "subsystem":
            value = binary.optional_header.magic.value
        else:
            value = getattr(binary.optional_header, field, None)
        optional_header[field] = value
    return optional_header


def get_data_directories(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "directory.txt"))
    data_directories = []

    size = len(binary.data_directories)
    size = min(16, size)

    for i in range(size):
        data_directory = {}

        for field in fields:
            if field == "section":
                value = _get_section(directory=binary.data_directories[i])
            elif field == "type":
                value = getattr(binary.data_directories[i], field, None).value
            else:
                value = getattr(binary.data_directories[i], field, None)
            data_directory[field] = value
        data_directories.append(data_directory)
    return data_directories


def _get_section(directory):
    fields = get_content(path=join("textjson", "lief", "section.txt"))
    directory_value = getattr(directory, "section", None)
    section = {}

    for field in fields:
        if field == "name":
            value = getattr(directory.section, field, None)
        elif directory_value is not None:
            value = getattr(directory_value, field, None)
            value = 0 if value is None else value
        else:
            value = 0
        section[field] = value
    return section


def get_sections(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "section.txt"))
    sections = []

    size = len(binary.sections)
    size = min(6, size)

    for i in range(size):
        _section = {}

        for field in fields:
            try:
                _section[field] = getattr(binary.sections[i], field, None)
            except:
                _section[field] = None if field == "Name" else 0
        sections.append(_section)
    return sections


def get_import(binary: Binary):
    if not binary.has_imports:
        return None

    import_directory = binary.imports[0].directory
    fields = get_content(path=join("textjson", "lief", "directory.txt"))
    _import = {}

    for field in fields:
        value = getattr(import_directory, field, None)

        if field == "section":
            value = _get_section(directory=import_directory)
        elif field == "type":
            value = value.value
        _import[field] = value
    return _import


def get_libraries(binary: Binary):
    if not binary.has_imports:
        return []

    fields = get_content(path=join("textjson", "lief", "library.txt"))
    libraries = []

    size = len(binary.imports)

    for i in range(size):
        library = {}

        # Get library's metadata
        for field in fields:
            value = getattr(binary.imports[i], field, None)
            value = 0 if value == None and field != "name" else value
            library[field] = value
        library["entries"] = _get_library_entries(_import=binary.imports[i])
        libraries.append(library)
        if i == 4:
            break
    return libraries


def _get_library_entries(_import, limit: int = 5):
    fields = get_content(path=join("textjson", "lief", "library-entry.txt"))
    library_entries = []

    size = len(_import.entries)
    size = min(size, limit)

    for i in range(size):
        library_entry = {}

        for field in fields:
            library_entry[field] = getattr(_import.entries[i], field, None)
        library_entries.append(library_entry)
    return library_entries


def get_tls(binary: Binary):
    if not binary.has_tls:
        return None

    tls = {}

    raw_data_start, raw_data_end = binary.tls.addressof_raw_data
    tls["addressof_callbacks"] = binary.tls.addressof_callbacks
    tls["addressof_index"] = binary.tls.addressof_index
    tls["raw_data_start"] = raw_data_start
    tls["raw_data_end"] = raw_data_end
    tls["characteristics"] = binary.tls.characteristics
    tls["data_directory"] = _get_tsl_data_directory(binary=binary)
    tls["section"] = _get_tsl_section(binary=binary)
    return tls


def _get_tsl_data_directory(binary: Binary):
    data_directory = {
        "has_section": False,
        "rva": 0,
        "size": 0,
        "type": 0,
        "name": None
    }

    if binary.tls.has_data_directory:
        data_directory["has_section"] = binary.tls.has_data_directory
        data_directory["rva"] = binary.tls.directory.rva
        data_directory["size"] = binary.tls.directory.size
        data_directory["type"] = binary.tls.directory.type.value
        data_directory["name"] = getattr(binary.tls.directory.section, 'name', None)
    return data_directory


def _get_tsl_section(binary: Binary):
    fields = get_content(path=join("textjson", "lief", "section.txt"))
    section = {}

    fields.remove("name")
    for field in fields:
        section[field] = getattr(binary.tls.section, field, 0)
    return section
