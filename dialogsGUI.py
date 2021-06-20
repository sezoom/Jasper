
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QLineEdit, QFileDialog

class dialogsGUI(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Choose File'
        self.left = 10
        self.top = 10
        self.width = 640
        self.height = 480
        self.initUI()


    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Open File", "",
                                                  "PCAP (*.pcap);;PCAPNG (*.pcapng)", options=options)
        self.hide()
        return fileName,_


    def saveFileDialog(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Save As", "",
                                                  "PCAP (*.pcap);;PCAPNG (*.pcapng)", options=options)
        self.hide()
        return fileName,_


