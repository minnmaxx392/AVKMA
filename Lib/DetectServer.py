import pefile
import requests
import time
import os
host = "42.112.213.93"
port = "8000"

def get_data_server_file(file_path):
    print("Loading . . .")
    start_time = time.time()
    url = f"http://{host}:{port}/api/v1/windows/applications"
    files = {"file": open(file_path, "rb")}
    response = requests.post(url, files=files)
    if 300 >= response.status_code >= 200:
        result = response.json()
        end_time = time.time()  # Ghi nhận thời điểm kết thúc
        elapsed_time = end_time - start_time
        analysis_id = result['data']['analysis_id']
        url_id = f"http://{host}:{port}/api/v1/windows/applications/{analysis_id}"
        response_id = requests.get(url_id)
        res = response_id.json()
        return res['data']['malware_type'], elapsed_time
    else:
        print("Có lỗi xảy ra khi tải lên.")
        print("Mã trạng thái phản hồi:", response.status_code)
        return None


def get_data_server_folder(folder_path):
    malware_types = []
    scanned_files = []
    start_time = time.time()
    print("Loading . . .")
    # Lặp qua từng tệp trong thư mục
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        try:
            pefile.PE(file_path)
            # Gửi từng tệp PE lên máy chủ
            result, _ = get_data_server_file(file_path)
            malware_types.append(result)
            scanned_files.append(file_path)
        except:
            pass
    print("Done!")
    end_time = time.time()  # Ghi nhận thời điểm kết thúc
    elapsed_time = end_time - start_time
    return malware_types, elapsed_time, scanned_files

if __name__ == "__main__":
    print(get_data_server_file(r"D:\Data_test\Benign\191564_Whitelist"))