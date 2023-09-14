import pickle
import numpy as np
import pefile
from keras.models import load_model
import time

SIZE = 27
PADDING = 46
from Lib.GetFeatureDataPEFile import *

def create_raw_data():
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

    header_characteristics_list = [
        "header_characteristics_list"
    ]

    machine = [
        "machine"
    ]

    total_section_name = [
        "total_section_name"
    ]

    section_name = []
    data_directory = []
    import_data_directory = []
    import_entry = []
    tls_data = []
    file_name = [
        "file_name"
    ]

    len_data = [
        "len_data"
    ]
    label = [
        "label"
    ]
    category_name = [
        "category_name"
    ]

    category_encoding = [
        "category_encoding"
    ]
    for i in range(272):
        data_directory.append(f"data_directory_{i}")

    for i in range(65):
        section_name.append(f"section_name_{i}")

    for i in range(17):
        import_data_directory.append(f"import_data_directory{i}")

    for i in range(250):
        import_entry.append(f"import_entry{i}")

    for i in range(22):
        tls_data.append(f"tls_data{i}")

    csv_file = "csvdata/data_raw.csv"

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(
            file_name + label + category_name + category_encoding + dos_header + header_characteristics_list + machine + header + optional_header + data_directory + section_name + total_section_name + import_data_directory + import_entry + tls_data)


def add_raw_data(filepath):
    csv_file = "csvdata/data_raw.csv"

    filename = os.path.basename(filepath)
    new_data = []
    if os.path.isfile(filepath):
        if "nolabel" not in filename:
            pe = lief.PE.parse(filepath)
            if pe is not None:
                # File name
                new_data.append(getFileName(filepath))

                # Label
                new_data.append(getLabel(filepath))

                # Category name
                new_data.append(getCategoryName(filepath))

                # Category code
                new_data.extend(getCategoryEncoding(filepath))

                # Dos_header
                new_data.extend(getDosHeader(pe))

                # Header characteristics
                new_data.append(getHeaderCharacteristics(pe))

                # Header
                new_data.extend(getHeader(pe))

                # Optional header
                new_data.extend(getOptionalHeader(pe))

                # Data directory
                new_data.extend(getDataDirectory(pe))

                # Section
                new_data.extend(getSection(pe))

                # Import

                # Import Section
                new_data.extend(getImportSection(pe))

                # Import Entry
                new_data.extend(getImportEntry(pe))

                # TLS
                new_data.extend(getTLS(pe))

                # Add new data
                with open(csv_file, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(new_data)

            else:
                # File name
                new_data.append(getFileName(filepath))

                # Label
                new_data.append(getLabel(filepath))

                # Category name
                new_data.append(getCategoryName(filepath))

                # Category code
                new_data.append(0)

                for i in range(683):
                    new_data.append(0)
                with open(csv_file, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(new_data)


def load_and_predict_category_ML_RFC(model_path, data):
    # Tách biệt đặc trưng và nhãn
    X = data.drop(['file_name', 'label', 'category_name', 'category_encoding'], axis=1)
    y = data['category_encoding']

    # Tiêu chuẩn hóa dữ liệu
    max_values_df = pd.read_csv('csvdata/max_data_new.csv')
    max_values_dict = max_values_df.set_index('Feature')['Max Value'].to_dict()

    for feature in X.columns:
        max_value = max_values_dict.get(feature, 1)  # Lấy giá trị max từ dict, nếu không có thì mặc định là 1
        if max_value == 0:
            X[feature] = 0
        else:
            X[feature] = X[feature] / max_value

    # Load mô hình từ tệp và thực hiện dự đoán
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    family_mapping = {
        1: "benign",
        2: "trojan",
        3: "virus virut",
        4: "trojan fareit",
        5: "adware",
        6: "adware multiplug",
        7: "adware hotbar",
        8: "trojan vilsel",
        9: "adware megasearch",
        10: "virus ramnit",
        11: "adware domaiq",
        12: "trojan msil",
        13: "trojan startpage",
        14: "trojan loadmoney",
        15: "worm",
        16: "virus sality",
        17: "trojan zbot",
        18: "worm allaple",
        19: "trojan crcf",
        20: "adware browsefox",
        21: "virus",
        22: "adware mplug",
        23: "trojan ekstak",
        24: "trojan onlinegames",
        25: "trojan emotet",
        26: "virus parite",
        27: "ransomware gandcrab",
        28: "adware ibryte",
        29: "trojan zusy",
        30: "trojan graftor",
        31: "trojan ursnif",
        32: "trojan symmi",
        33: "trojan installmonster",
        34: "downloader",
        35: "trojan antifw",
        36: "adware installcore",
        37: "trojan mint",
        38: "trojan razy",
        39: "trojan kazy",
        40: "trojan vobfus",
        41: "trojan ramnit",
        42: "virus expiro",
        43: "trojan autoit",
        44: "trojan dreidel",
        45: "trojan lineage",
        46: "adware gamevance",
        47: "trojan installcore",
        48: "trojan vbkrypt",
        49: "trojan installrex",
        50: "virus alman",
        51: "worm mydoom",
        52: "trojan lamer",
        53: "trojan tepfer",
        54: "adware linkury",
        55: "trojan morstar",
        56: "adware softpulse",
        57: "trojan domaiq",
        58: "trojan rootkit",
        59: "downloader bundler",
        60: "trojan strictor",
        61: "worm vobfus",
        62: "trojan androm",
        63: "virus virlock",
        64: "trojan elzob",
        65: "trojan hupigon",
        66: "trojan ursu",
        67: "trojan sality",
        68: "trojan barys",
        69: "trojan bundler",
        70: "trojan deepscan",
        71: "trojan dialer",
        72: "trojan ponystealer",
        73: "adware outbrowse",
        74: "downloader adload",
        75: "trojan softpulse",
        76: "trojan installerex",
        77: "trojan gandcrab",
        78: "adware imali",
        79: "trojan ulise",
        80: "worm sytro",
        81: "trojan farfli",
        82: "trojan vbkryjetor",
        83: "trojan rimecud",
        84: "virus madangel",
        85: "trojan vundo",
        86: "trojan ircbot",
        87: "trojan zlob",
        88: "trojan bifrose",
        89: "trojan mikey",
        90: "trojan swizzor",
        91: "trojan noon",
        92: "miner",
        93: "trojan virut",
        94: "trojan archsms",
        95: "adware bundler",
        96: "trojan adload",
        97: "trojan genome",
        98: "trojan zegost",
        99: "trojan ibryte",
        100: "adware firseria",
        101: "trojan mira",
        102: "trojan darkkomet",
        103: "trojan doina",
        104: "worm autoit",
        105: "trojan buzus",
        106: "trojan loring",
        107: "trojan zaccess",
        108: "trojan midie",
        109: "trojan stone",
        110: "trojan flystudio",
        111: "trojan nsis",
        112: "trojan firseria",
        113: "trojan downloadadmin",
        114: "trojan sirefef",
        115: "trojan cerbu",
        116: "trojan bladabindi",
        117: "adware soft32downloader",
        118: "trojan forcestartpage",
        119: "adware bundlore",
        120: "trojan bdmj",
        121: "trojan upatre",
        122: "virus jadtre",
        123: "adware fiseria",
        124: "worm viking",
        125: "adware downloadware",
        126: "pua",
        127: "hacktool",
        128: "ransomware",
        129: "dropper",
        130: "banker",
        131: "spyware",
        132: "bundler",
        133: "fakeav",
        134: "creprote",
        135: "presenoker",
        136: "firseriainstaller",
        137: "slimware",
        138: "poison",
        139: "relevantknowledge",
        140: "hiderun",
        141: "rootkit",
        142: "netmedia",
        143: "autoit",
        144: "pwdump"
    }
    # Thực hiện dự đoán
    y_pred = model.predict(X)

    # Ánh xạ các kết quả dự đoán trở lại nhãn của danh mục
    y_pred_mapped = [family_mapping[pred] for pred in y_pred]

    return y_pred_mapped


def load_and_predict_category(model_path, data):
    # Load the trained model
    model = load_model(model_path)
    # Separate features and labels
    # Preprocess input file
    x_input = data.drop(['file_name', 'label', 'category_name', 'category_encoding'], axis=1)
    max_values_df = pd.read_csv('csvdata/max_data_new.csv')
    max_values_dict = max_values_df.set_index('Feature')['Max Value'].to_dict()

    for feature in x_input.columns:
        max_value = max_values_dict.get(feature, 1)  # Lấy giá trị max từ dict, nếu không có thì mặc định là 1
        if max_value == 0:
            x_input[feature] = 0
        else:
            x_input[feature] = x_input[feature] / max_value

    x_input = np.concatenate((x_input, np.zeros((x_input.shape[0], PADDING))), axis=1)
    x_input = x_input.reshape(x_input.shape[0], SIZE, SIZE, 1)

    # Make predictions
    predictions = model.predict(x_input)
    predicted_labels = np.argmax(predictions, axis=-1)
    # Map the predicted labels to category_names
    family_mapping = {
        1: "benign",
        2: "trojan",
        3: "virus virut",
        4: "trojan fareit",
        5: "adware",
        6: "adware multiplug",
        7: "adware hotbar",
        8: "trojan vilsel",
        9: "adware megasearch",
        10: "virus ramnit",
        11: "adware domaiq",
        12: "trojan msil",
        13: "trojan startpage",
        14: "trojan loadmoney",
        15: "worm",
        16: "virus sality",
        17: "trojan zbot",
        18: "worm allaple",
        19: "trojan crcf",
        20: "adware browsefox",
        21: "virus",
        22: "adware mplug",
        23: "trojan ekstak",
        24: "trojan onlinegames",
        25: "trojan emotet",
        26: "virus parite",
        27: "ransomware gandcrab",
        28: "adware ibryte",
        29: "trojan zusy",
        30: "trojan graftor",
        31: "trojan ursnif",
        32: "trojan symmi",
        33: "trojan installmonster",
        34: "downloader",
        35: "trojan antifw",
        36: "adware installcore",
        37: "trojan mint",
        38: "trojan razy",
        39: "trojan kazy",
        40: "trojan vobfus",
        41: "trojan ramnit",
        42: "virus expiro",
        43: "trojan autoit",
        44: "trojan dreidel",
        45: "trojan lineage",
        46: "adware gamevance",
        47: "trojan installcore",
        48: "trojan vbkrypt",
        49: "trojan installrex",
        50: "virus alman",
        51: "worm mydoom",
        52: "trojan lamer",
        53: "trojan tepfer",
        54: "adware linkury",
        55: "trojan morstar",
        56: "adware softpulse",
        57: "trojan domaiq",
        58: "trojan rootkit",
        59: "downloader bundler",
        60: "trojan strictor",
        61: "worm vobfus",
        62: "trojan androm",
        63: "virus virlock",
        64: "trojan elzob",
        65: "trojan hupigon",
        66: "trojan ursu",
        67: "trojan sality",
        68: "trojan barys",
        69: "trojan bundler",
        70: "trojan deepscan",
        71: "trojan dialer",
        72: "trojan ponystealer",
        73: "adware outbrowse",
        74: "downloader adload",
        75: "trojan softpulse",
        76: "trojan installerex",
        77: "trojan gandcrab",
        78: "adware imali",
        79: "trojan ulise",
        80: "worm sytro",
        81: "trojan farfli",
        82: "trojan vbkryjetor",
        83: "trojan rimecud",
        84: "virus madangel",
        85: "trojan vundo",
        86: "trojan ircbot",
        87: "trojan zlob",
        88: "trojan bifrose",
        89: "trojan mikey",
        90: "trojan swizzor",
        91: "trojan noon",
        92: "miner",
        93: "trojan virut",
        94: "trojan archsms",
        95: "adware bundler",
        96: "trojan adload",
        97: "trojan genome",
        98: "trojan zegost",
        99: "trojan ibryte",
        100: "adware firseria",
        101: "trojan mira",
        102: "trojan darkkomet",
        103: "trojan doina",
        104: "worm autoit",
        105: "trojan buzus",
        106: "trojan loring",
        107: "trojan zaccess",
        108: "trojan midie",
        109: "trojan stone",
        110: "trojan flystudio",
        111: "trojan nsis",
        112: "trojan firseria",
        113: "trojan downloadadmin",
        114: "trojan sirefef",
        115: "trojan cerbu",
        116: "trojan bladabindi",
        117: "adware soft32downloader",
        118: "trojan forcestartpage",
        119: "adware bundlore",
        120: "trojan bdmj",
        121: "trojan upatre",
        122: "virus jadtre",
        123: "adware fiseria",
        124: "worm viking",
        125: "adware downloadware",
        126: "pua",
        127: "hacktool",
        128: "ransomware",
        129: "dropper",
        130: "banker",
        131: "spyware",
        132: "bundler",
        133: "fakeav",
        134: "creprote",
        135: "presenoker",
        136: "firseriainstaller",
        137: "slimware",
        138: "poison",
        139: "relevantknowledge",
        140: "hiderun",
        141: "rootkit",
        142: "netmedia",
        143: "autoit",
        144: "pwdump"
    }
    predicted_categories = [family_mapping[label] for label in predicted_labels]

    return predicted_categories


def Detect_folder(folderpath):
    create_raw_data()
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    scanned_files = []
    for root, dirs, files in os.walk(folderpath):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                pefile.PE(file_path)
                add_raw_data(file_path)
                scanned_files.append(file_path)  # Thêm tên file vào danh sách đã quét
            except:
                pass

    model_path = r"model/ModelFamilyDL/DL_Family.h5"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)

    return predicted_categories, elapsed_time, scanned_files


def Detect_file(filepath):
    create_raw_data()
    add_raw_data(filepath)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    model_path = r"model/ModelFamilyDL/DL_Family.h5"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)
    return predicted_categories, elapsed_time


def Classifier_file(filepath):
    create_raw_data()
    add_raw_data(filepath)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    model_path = r"model/ModelFamilyML/ML_Family.pickle"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category_ML_RFC(model_path, data)
    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)
    return predicted_categories, elapsed_time


def Classifier_folder(folderpath):
    create_raw_data()
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    scanned_files = []
    for root, dirs, files in os.walk(folderpath):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                pefile.PE(file_path)
                add_raw_data(file_path)
                scanned_files.append(file_path)  # Thêm tên file vào danh sách đã quét
            except:
                pass

    model_path = r"model/ModelFamilyML/ML_Family.pickle"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category_ML_RFC(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)

    return predicted_categories, elapsed_time, scanned_files

