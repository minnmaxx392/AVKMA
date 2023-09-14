from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItemModel, QStandardItem
from PyQt6.QtWidgets import QApplication, QDialog, QWidget, QVBoxLayout, QTableView, QSplitter
import pandas as pd

class SubWindow(object):
    def setup_ui(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 202)
        layout = QVBoxLayout(Dialog)

        # Bảng 1
        self.table_model = QStandardItemModel(Dialog)
        self.table_model.setHorizontalHeaderLabels(["File name", "Category", "Family"])

        self.table_view = QTableView(Dialog)
        self.table_view.setModel(self.table_model)
        self.table_view.setColumnWidth(0, 320)  # Cột tên file
        self.table_view.setColumnWidth(1, 120)  # Cột phân loại
        self.table_view.setColumnWidth(2, 120)  # Cột Family

        # Bảng 2
        self.table_model_2 = QStandardItemModel(Dialog)
        self.table_model_2.setHorizontalHeaderLabels(["Category", "Quantity"])

        self.table_view_2 = QTableView(Dialog)
        self.table_view_2.setModel(self.table_model_2)
        self.table_view_2.setColumnWidth(0, 150)
        self.table_view_2.setColumnWidth(1, 100)

        self.setup_data(self.table_model, self.table_model_2)

        # Kết hợp hai bảng bằng QSplitter
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.table_view)
        self.splitter.addWidget(self.table_view_2)

        layout.addWidget(self.splitter)
        self.splitter.setSizes([460, 230])
        Dialog.resize(900, 600)
        Dialog.setWindowTitle("Kết quả chi tiết")

    def setup_data(self, table_model, table_model_2):
        self.data1 = []

        # Đọc dữ liệu từ tệp CSV và thêm vào data1
        self.df = pd.read_csv('csvdata/dulieuchitiet.csv')
        for index, row in self.df.iterrows():
            self.filename = row['File name']
            self.category = row['Category']
            self.data1.append((self.filename, self.category))

        data2 = []

        # Đếm số lượng mỗi loại và thêm vào data2
        self.category_counts = self.df['Category'].value_counts()
        for category, count in self.category_counts.items():
            data2.append((category, count))

        for row, (filename, category) in enumerate(self.data1):
            self.filename_item = QStandardItem(filename)
            self.category_item = QStandardItem(category.split()[0])

            table_model.setItem(row, 0, self.filename_item)
            table_model.setItem(row, 1, self.category_item)

            if len(category.split()) > 1:
                family = ' '.join(category.split()[1:])
                family_item = QStandardItem(family)
                table_model.setItem(row, 2, family_item)

        for row, (category, count) in enumerate(data2):
            self.category_item = QStandardItem(category)
            self.count_item = QStandardItem(str(count))

            table_model_2.setItem(row, 0, self.category_item)
            table_model_2.setItem(row, 1, self.count_item)


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    Dialog = QDialog()
    ui = SubWindow()
    ui.setup_ui(Dialog)
    Dialog.show()
    sys.exit(app.exec())
