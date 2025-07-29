import sys
import serial
import struct
import serial.tools.list_ports
import time
from PyQt5 import uic
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QComboBox, QTextEdit, QMessageBox, QLineEdit, QFormLayout, QDialog
)
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIntValidator, QRegExpValidator
from PyQt5.QtCore import QRegExp


MESSAGE_ID_STORAGE = 0x20
CONTROL_CHAR_STX = 0x02
CONTROL_CHAR_ENQ = 0x05
CONTROL_CHAR_ACK = 0x06
CONTROL_CHAR_ETX = 0x03


class StorageMessage:
    LENGTH = 100  # bytes

    def __init__(self):
        self.product = 0
        self.type = 0
        self.version = "16.0.0"
        self.diagnostic_code = 0
        self.open_date = 0
        self.customer = 0
        self.device_id = 0
        self.sn_product = ""
        self.sn_board = ""

    def from_bytes(self, data: bytes):
        if len(data) < self.LENGTH:
            raise ValueError("Payload too short")

        fields = struct.unpack_from('<'  # little endian
            'B'     # eProduct
            'B'     # eType
            '3B'    # tVersion
            'B'     # eDiagnosticCode
            'I'     # u32OpenDate
            'B'     # u8Customer
            'B'     # u8Id
            '16s'   # u8Product
            '16s'   # u8Board
            , data[:self.LENGTH]
        )

        self.product = fields[0]
        self.type = fields[1]
        self.version = f"{fields[2]}.{fields[3]}.{fields[4]}"
        self.diagnostic_code = fields[5]
        self.open_date = fields[6]
        self.customer = fields[7]
        self.device_id = fields[8]
        self.sn_product = fields[9].decode('ascii', errors='ignore').strip('\0')
        self.sn_board = fields[10].decode('ascii', errors='ignore').strip('\0')

    def to_bytes(self):
        data = struct.pack('<BB3BBIBB16s16s',
            self.product,
            self.type,
            *map(int, self.version.split('.')),
            self.diagnostic_code,
            self.open_date,
            self.customer,
            self.device_id,
            self.sn_product.encode().ljust(16, b'\0'),
            self.sn_board.encode().ljust(16, b'\0'),
        )
        return data + b'\0' * (100 - len(data))


class SERIALTool(QDialog):
    def __init__(self):
        super().__init__()             
        self.setWindowTitle("SERIAL TOOL")
        self.resize(600, 400)

        self.serial = None
        self.seq = 1
        self.timer = QTimer(self)
        self.storage = StorageMessage()

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Serial 설정
        serial_row = QHBoxLayout()
        self.port_combo = QComboBox()
        self.refresh_ports()
        serial_row.addWidget(QLabel("Serial Port:"))
        serial_row.addWidget(self.port_combo)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.toggle_connection)
        serial_row.addWidget(self.connect_btn)
        layout.addLayout(serial_row)

        # Form 입력
        form = QFormLayout()
        self.inputs = {
            'sn_product': QLineEdit(),
            'sn_board': QLineEdit(),
            'open_date': QLineEdit()
        }
        form.addRow("Product SN:", self.inputs['sn_product'])
        form.addRow("Board SN:", self.inputs['sn_board'])
        form.addRow("Open Date (YYYYMMDD):", self.inputs['open_date'])
        layout.addLayout(form)


        # open_date: 8자리 숫자만 허용
        self.inputs['open_date'].setValidator(QIntValidator(10000000, 99999999, self))
        self.inputs['open_date'].setMaxLength(8)

        # sn_product, sn_board: 10자리 숫자만 허용
        regex = QRegExp(r"\d{10}")
        sn_validator = QRegExpValidator(regex, self)

        self.inputs['sn_product'].setValidator(sn_validator)
        self.inputs['sn_product'].setMaxLength(10)

        self.inputs['sn_board'].setValidator(sn_validator)
        self.inputs['sn_board'].setMaxLength(10)

        self.labels = {
            'version': QLabel(""),
            'open_date': QLabel(""),
            'sn_product': QLabel(""),
            'sn_board': QLabel("")
        }
        label_form = QFormLayout()
        label_form.addRow("Version (읽기):", self.labels['version'])
        label_form.addRow("Open Date (읽기):", self.labels['open_date'])
        label_form.addRow("Product SN (읽기):", self.labels['sn_product'])
        label_form.addRow("Board SN (읽기):", self.labels['sn_board'])
        layout.addLayout(label_form)

        # 버튼들
        button_row = QHBoxLayout()
        self.read_btn = QPushButton("Read")
        self.read_btn.clicked.connect(self.send_enq)        
        self.read_btn.setEnabled(False)
        button_row.addWidget(self.read_btn)


        self.write_btn = QPushButton("Write")
        self.write_btn.clicked.connect(self.send_storage)
        self.write_btn.setEnabled(False)
        button_row.addWidget(self.write_btn)

        layout.addLayout(button_row)

        # 로그 출력
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        self.setLayout(layout)

    def refresh_ports(self):
        ports = serial.tools.list_ports.comports()
        self.port_combo.clear()
        self.port_combo.addItems([port.device for port in ports])

    def toggle_connection(self):
        if self.serial and self.serial.is_open:
            self.serial.close()
            self.connect_btn.setText("Connect")
            self.read_btn.setEnabled(False)
            self.write_btn.setEnabled(False)
            self.timer.stop()
        else:
            port = self.port_combo.currentText()
            try:
                self.serial = serial.Serial(port, baudrate=115200, timeout=1)
                self.connect_btn.setText("Disconnect")
                self.read_btn.setEnabled(True)             
                self.write_btn.setEnabled(True)
                self.timer.start(50)
            except Exception as e:
                QMessageBox.critical(self, "Connection Error", str(e))

    def update_ui_fields(self):
        self.inputs['sn_product'].setText(self.storage.sn_product)
        self.inputs['sn_board'].setText(self.storage.sn_board)
        self.inputs['open_date'].setText(str(self.storage.open_date))

        self.labels['version'].setText(f"(최신) {self.storage.version}")
        self.labels['open_date'].setText(f"(최신) {self.storage.open_date}")
        self.labels['sn_product'].setText(f"(최신) {self.storage.sn_product}")
        self.labels['sn_board'].setText(f"(최신) {self.storage.sn_board}")

        for label in self.labels.values():
            label.setStyleSheet("color: green; font-weight: bold")

        # 1.5초 뒤에 스타일 초기화
        QTimer.singleShot(1500, self.clear_label_highlight)        

    def clear_label_highlight(self):
        self.labels['version'].setText(self.storage.version)
        self.labels['open_date'].setText(str(self.storage.open_date))
        self.labels['sn_product'].setText(self.storage.sn_product)
        self.labels['sn_board'].setText(self.storage.sn_board)

        for label in self.labels.values():
            label.setStyleSheet("color: black; font-weight: normal")



    def send_enq(self):
        self.seq = (self.seq % 200) + 1
        frame = struct.pack("BBBBBBB", CONTROL_CHAR_ENQ, MESSAGE_ID_STORAGE, 0x01, 0x01, 0x01, 0x00, 0x80)
        frame += bytes([CONTROL_CHAR_ETX])
        self.output.append(f"[DEBUG] ENQ TX: {' '.join([f'{b:02X}' for b in frame])}")
        self.serial.write(frame)
        self.serial.flush()
        self.output.append(f"→ ENQ sent (seq={self.seq})")

        time.sleep(0.2)

        if not self.serial:
            self.output.append("[DEBUG] serial is None")
            return
        data = self.serial.read(256)


        

        self.output.append(f"RAW RX: {' '.join([f'{b:02X}' for b in data])}")




        if not data or len(data) < 7:
            self.output.append("[WARN] No response or too short")
            return

        try:
            ctrl_char = data[0]
            message_id = data[1]
            payload_len = data[2]
            device_id = data[3]
            seq = data[4]


            if ctrl_char not in [CONTROL_CHAR_STX, CONTROL_CHAR_ACK]:
                self.output.append(f"[DEBUG] Ignored non-STX/ACK frame: ctrl=0x{ctrl_char:02X}")
                return

            expected_len = 5 + payload_len + 1 + 1  # header + payload + checksum + etx
            if len(data) < expected_len:
                self.output.append(f"[WARN] Incomplete frame (got {len(data)} bytes, expected {expected_len})")
                return

            if device_id != 0x01:
                self.output.append(f"[WARN] Device ID mismatch: expected 0x01, got {device_id:02X}")

            if seq != self.seq:
                self.output.append(f"[WARN] Sequence number mismatch: sent {self.seq}, got {seq}")

            payload = data[5:5+payload_len]
            checksum = data[5+payload_len]
            etx = data[6+payload_len]

            if etx != CONTROL_CHAR_ETX:
                self.output.append(f"[WARN] ETX mismatch: expected 0x03, got {etx:02X}")
                return

            calc = 0
            for b in payload:
                calc ^= b
            calc |= 0x80

            if checksum != calc:
                self.output.append(f"[ERROR] Checksum mismatch: got {checksum:02X}, expected {calc:02X}")
                return

            if message_id == MESSAGE_ID_STORAGE:
                self.storage.from_bytes(payload)
                self.output.append(f"← STORAGE {('ACK' if ctrl_char == CONTROL_CHAR_ACK else 'STX')} received and parsed")
                self.update_ui_fields()

                if ctrl_char == CONTROL_CHAR_STX:
                    self.send_ack(message_id, seq)


            else:
                self.output.append(f"[INFO] Received {('ACK' if ctrl_char == CONTROL_CHAR_ACK else 'STX')} message: ID=0x{message_id:02X}, payload ignored")
        except Exception as e:
            self.output.append(f"[ERROR] {str(e)}")


    def send_ack(self, message_id, seq):
        payload = bytes([0x01])  # dummy 1-byte payload
        checksum = 0
        for b in payload:
            checksum ^= b
        checksum |= 0x80

        frame = struct.pack('BBBBB',
            CONTROL_CHAR_ACK,  # ACK = 0x06
            message_id,        # echo back message_id (e.g., 0x20)
            len(payload),             # payload length = 1 (no real payload)
            0x01,              # device id
            seq,          # sequence number
        ) + bytes([checksum, CONTROL_CHAR_ETX])

        self.output.append(f"[DEBUG] ACK TX: {' '.join([f'{b:02X}' for b in frame])}")
        self.serial.write(frame)
        self.serial.flush()
        self.output.append(f"→ ACK sent (msg_id=0x{message_id:02X}, seq={seq})")


    def send_storage(self):
        try:
            self.storage.sn_product = self.inputs['sn_product'].text().strip().zfill(16)
            self.storage.sn_board = self.inputs['sn_board'].text().strip().zfill(16)
            self.storage.open_date = int(self.inputs['open_date'].text().strip())
            self.storage.diagnostic_code = 2

            payload = self.storage.to_bytes()

            if len(payload) != 100:
                self.output.append(f"[ERROR] Payload length mismatch: got {len(payload)}, expected 100")
                return

            length = len(payload)

            checksum = 0
            for b in payload:
                checksum ^= b
            checksum |= 0x80

            self.seq = (self.seq % 200) + 1
            header = struct.pack('BBBBB', CONTROL_CHAR_STX, MESSAGE_ID_STORAGE, length, 0x01, self.seq)
            tail = struct.pack('BB', checksum, CONTROL_CHAR_ETX)
            frame = header + payload + tail
            self.output.append(f"[DEBUG] STORAGE TX: {' '.join([f'{b:02X}' for b in frame])}") 
            self.serial.write(frame)
            self.output.append("→ STORAGE write frame sent")

        except Exception as e:
            self.output.append(f"[ERROR] {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SERIALTool()
    window.show()
    sys.exit(app.exec_())
