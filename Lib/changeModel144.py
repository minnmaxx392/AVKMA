# Form implementation generated from reading ui file 'UI/changeModel.ui'
#
# Created by: PyQt6 UI code generator 6.5.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.

import time
import os
import shutil
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QFileDialog, QMessageBox

class Ui_Form(object):

    def changeModelML(self):
        new_folder_path = r"new_model/Model Machine Learning Family"
        # Bước 1: Chọn file
        file_path, _ = QFileDialog.getOpenFileName(None, "Chọn file", new_folder_path,
                                                   "Pickle files (*.pickle);;All files (*.*)")
        if file_path:
            # Bước 2: Đổi tên file pickle trong thư mục "model\ModelFamilyML"
            current_time = time.strftime("%Y%m%d%H%M%S")
            new_file_name = f"ML_Family_{current_time}.pickle"
            old_file_path = os.path.join("model", "ModelFamilyML", "ML_Family.pickle")
            new_file_path = os.path.join("model", "ModelFamilyML", new_file_name)
            os.rename(old_file_path, new_file_path)

            # Bước 3: Di chuyển file đã đổi tên từ bước 2 đến thư mục "old_model/Model Machine Learning Family"
            destination_path = os.path.join("old_model", "Model Machine Learning Family", new_file_name)
            shutil.move(new_file_path, destination_path)

            # Bước 4: Di chuyển file được chọn từ bước 1 đến thư mục "model\ModelFamilyML" và đổi tên thành "ML_Family.pickle"
            new_file_path = os.path.join("model", "ModelFamilyML", "ML_Family.pickle")
            shutil.copy2(file_path, new_file_path)
            # Hiển thị thông báo thành công
            QMessageBox.information(None, "Thông báo", "Thay đổi model thành công.")

    def changeModelDL(self):
        new_folder_path = r"new_model/Model Deep Learning Family"
        # Bước 1: Chọn file
        file_path, _ = QFileDialog.getOpenFileName(None, "Chọn file", new_folder_path,
                                                   "H5 files (*.h5);;All files (*.*)")
        if file_path:
            # Bước 2: Đổi tên file pickle trong thư mục "model\ModelFamilyDL"
            current_time = time.strftime("%Y%m%d%H%M%S")
            new_file_name = f"DL_Family_{current_time}.h5"
            old_file_path = os.path.join("model", "ModelFamilyDL", "DL_Family.h5")
            new_file_path = os.path.join("model", "ModelFamilyDL", new_file_name)
            os.rename(old_file_path, new_file_path)

            # Bước 3: Di chuyển file đã đổi tên từ bước 2 đến thư mục "old_model/Model Deep Learning Family"
            destination_path = os.path.join("old_model", "Model Deep Learning Family", new_file_name)
            shutil.move(new_file_path, destination_path)

            # Bước 4: Di chuyển file được chọn từ bước 1 đến thư mục "model\ModelFamilyDL" và đổi tên thành "DL_Family.h5"
            new_file_path = os.path.join("model", "ModelFamilyDL", "DL_Family.h5")
            shutil.copy2(file_path, new_file_path)

            # Hiển thị thông báo thành công
            QMessageBox.information(None, "Thông báo", "Thay đổi model thành công.")

    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(554, 250)
        self.label = QtWidgets.QLabel(parent=Form)
        self.label.setGeometry(QtCore.QRect(10, 10, 501, 81))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(parent=Form)
        self.pushButton.setGeometry(QtCore.QRect(40, 100, 211, 101))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(parent=Form)
        self.pushButton_2.setGeometry(QtCore.QRect(290, 100, 211, 101))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "Thay đổi mô hình phân lớp (families) mã độc:"))
        self.pushButton.setText(_translate("Form", "CNN Model"))
        self.pushButton.clicked.connect(self.changeModelDL)
        self.pushButton_2.setText(_translate("Form", "Machine Learning Model"))
        self.pushButton_2.clicked.connect(self.changeModelML)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec())
