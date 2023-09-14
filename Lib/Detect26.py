import pickle
import numpy as np
import pefile
from keras.models import load_model
import time
from os.path import join
from json import dump
import sklearn
SIZE = 27
PADDING = 46
from Lib.GetFeatureDataPEFile import *
from srcjson.pe import analyze

csv_file = "csvdata/data_raw.csv"

def create_raw_data(csv_file):
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

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(
            file_name + label + category_name + category_encoding + dos_header + header_characteristics_list + machine + header + optional_header + data_directory + section_name + total_section_name + import_data_directory + import_entry + tls_data)

def add_raw_data_virusshare(filepath, csv_file):
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
                new_data.append(getCategoryNameOutFiles(filepath))

                # Category code
                new_data.extend(getCategoryEncodingOutFiles(filepath))

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
                new_data.append(getCategoryEncoding(filepath))

                for i in range(683):
                    new_data.append(0)
                with open(csv_file, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(new_data)

def add_raw_data(filepath, csv_file):
    # lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)
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
    category_mapping = {
        0: "benign",
        1: "virus",
        2: "worm",
        3: "trojan",
        4: "adware",
        5: "pua",
        6: "downloader",
        7: "hacktool",
        8: "fakeav",
        9: "banker",
        10: "dropper",
        11: "miner",
        12: "spyware",
        13: "ransomware",
        14: "slimware",
        15: "firseriainstaller",
        16: "bundler",
        17: "poison",
        18: "relevantknowledge",
        19: "hiderun",
        20: "rootkit",
        21: "netmedia",
        22: "autoit",
        23: "creprote",
        24: "presenoker",
        25: "pwdump",
    }

    # ...

    # Thực hiện dự đoán
    y_pred = model.predict(X)

    # Ánh xạ các kết quả dự đoán trở lại nhãn của danh mục
    y_pred_mapped = [category_mapping[pred] for pred in y_pred]

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

    # with open("out.txt", "w") as file:
    #     for feature in x_input.columns:
    #         data = map(str, x_input[feature].tolist())
    #         file.write("\n".join(data))

    x_input = np.concatenate((x_input, np.zeros((x_input.shape[0], PADDING))), axis=1)
    x_input = x_input.reshape(x_input.shape[0], SIZE, SIZE, 1)

    # Make predictions
    predictions = model.predict(x_input)
    predicted_labels = np.argmax(predictions, axis=-1)
    # Map the predicted labels to category_names
    category_mapping = {
        0: "benign",
        1: "virus",
        2: "worm",
        3: "trojan",
        4: "adware",
        5: "pua",
        6: "downloader",
        7: "hacktool",
        8: "fakeav",
        9: "banker",
        10: "dropper",
        11: "miner",
        12: "spyware",
        13: "ransomware",
        14: "slimware",
        15: "firseriainstaller",
        16: "bundler",
        17: "poison",
        18: "relevantknowledge",
        19: "hiderun",
        20: "rootkit",
        21: "netmedia",
        22: "autoit",
        23: "creprote",
        24: "presenoker",
        25: "pwdump",
    }
    predicted_categories = [category_mapping[label] for label in predicted_labels]

    return predicted_categories


def Detect_folder(folderpath):
    create_raw_data(csv_file)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    scanned_files = []  # Danh sách lưu trữ các tên file đã quét

    for root, dirs, files in os.walk(folderpath):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                pefile.PE(file_path)
                add_raw_data(file_path, csv_file)
                scanned_files.append(file_path)  # Thêm tên file vào danh sách đã quét
            except:
                pass

    model_path = r"model/ModelCategoryDL/DL_Category.h5"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)

    return predicted_categories, elapsed_time, scanned_files



def Detect_file(filepath):
    create_raw_data(csv_file)
    add_raw_data(filepath, csv_file)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    model_path = r"model/ModelCategoryDL/DL_Category.h5"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)
    return predicted_categories, elapsed_time

def Classifier_file(filepath):
    create_raw_data(csv_file)
    add_raw_data(filepath, csv_file)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    model_path = r"model/ModelCategoryML/ML_Category.pickle"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category_ML_RFC(model_path, data)
    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)
    return predicted_categories, elapsed_time


def Classifier_folder(folderpath):
    create_raw_data(csv_file)
    start_time = time.time()  # Ghi nhận thời điểm bắt đầu
    scanned_files = []
    for root, dirs, files in os.walk(folderpath):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                pefile.PE(file_path)
                add_raw_data(file_path, csv_file)
                scanned_files.append(file_path)  # Thêm tên file vào danh sách đã quét
            except:
                pass

    model_path = r"model/ModelCategoryML/ML_Category.pickle"
    data = pd.read_csv(r'csvdata/data_raw.csv')
    predicted_categories = load_and_predict_category_ML_RFC(model_path, data)

    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time  # Tính thời gian chạy (đơn vị: giây)

    return predicted_categories, elapsed_time, scanned_files


def trichxuatJson(file_path):
    analyze(file_path)
    with open(file=join("out", "data_trich_xuat.json"), mode="w") as file:
        dump(analyze(file_path), fp=file)

if __name__ == "__main__":
    file_path = r"C:\Users\minh3\Downloads\tool\TeamViewer_Setup_x64.exe"
    create_raw_data(csv_file)
    add_raw_data(file_path, csv_file)