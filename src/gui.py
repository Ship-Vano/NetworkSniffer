"""#TODO:
    ++ выбор интерфейса
    - выбор кол-ва пакетов
    - выбор типов пакетов
    ++ график распределения tcp и udp протоколов 
    ++ кнопка очистки
    - статистика пакетов
    - hex/ASCII dump в нижнем окне
    - форматирование таблицы (по ширине, мб цвета)
    + сортировка таблицы (по колонкам)
    ++ запись в csv файл
    - запись в pcap файл
    - панель верхнего меню
    - определение страны открытого ip 
    - стилевые файлы (мб свой дезигн кнопок, фона)
    - сборка в .exe
    - AsyncSniffer???
    - try catch и безопасность
"""

from PyQt6.QtWidgets import (
    QMainWindow, 
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QApplication, 
    QSplitter,
    QTextEdit,
    QTableView,
    QHeaderView,
    QFileDialog, 
    QMessageBox,
    QComboBox
)
from PyQt6.QtCore import ( 
    Qt, 
    QAbstractTableModel, 
    QModelIndex, 
    pyqtSignal,
    QSortFilterProxyModel
)
from PyQt6.QtGui import QColor
from core.NetworkSniffer import NetworkSniffer
from core.fileIO import export_packets_to_csv
import pyqtgraph as pg

class PacketTable(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data

        self._headers = [
            '№',
            'Source',
            'Destination',
            'Protocol',
            'Length',
            'Time'
        ]

    def add_packet(self, packet):
        self.beginInsertRows(QModelIndex(), len(self._data), len(self._data))
        self._data.append(packet)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._data = []
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)
    
    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)
    
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        
        row = index.row()
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            packet = self._data[row]

            #TODO (для корректности сортировки)
            #было так (красиво, но при изменении порядка - гг)
            #keys = list(packet.keys())
            #return str(packet[keys[column]])
            
            match column:
                case 0:
                    #безопасно получаем нужное значение (при отсутствии - пустая строка)
                    return packet.get('no', '')
                case 1:
                    return str(packet.get('source', '-')) #или прочерк
                case 2:
                    return str(packet.get('destination', '-'))
                case 3:
                    return str(packet.get('protocol', '-'))
                case 4:
                    return str(packet.get('length', '-'))
                case 5:
                    return str(packet.get('time', '-'))
                case _: #дефолтыч
                    return ""
        
        elif role == Qt.ItemDataRole.BackgroundRole:
            packet = self._data[row]

            if packet['protocol'] == 'TCP':
                return QColor(235, 52, 225) #филалетовый
            elif packet['protocol'] == 'UDP':
                return QColor(52, 235, 95) #зелёный
        return None

    def headerData(self, section, orientation, role = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._headers[section]
        return None


class MainWindow(QMainWindow):
    update_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.sniffer = NetworkSniffer()
        self.init_ui()
        self.setup_connections()
        
    
    def init_ui(self):
        self.setWindowTitle("Network Sniffer App")
        self.setGeometry(100, 100, 1200, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        control_layout = QHBoxLayout()

        self.interface_combo = QComboBox()
        self.interface_combo.addItems(
            ["Все интерфейсы"] + 
            [iface for iface in self.sniffer.get_available_interface() if iface != 'lo']
        )

        self.start_btn = QPushButton("Запуск")
        self.stop_btn = QPushButton("Стоп")
        self.stop_btn.setEnabled(False)
        self.clear_button = QPushButton("Очистить")
        self.export_btn = QPushButton("Экспорт в CSV")

        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.export_btn)
        control_layout.addWidget(self.clear_button)

        # Таблица пакетов
        #1) создаём сам виджет таблицы
        self.packet_table = QTableView()

        #2) создаём модель данных для таблицы
        self.table_model = PacketTable([])

        #3) для сортировки нужна модель-"обёртка",
        #   которая будет отвечать за сортировку в основной модели
        self.proxy_table_model = QSortFilterProxyModel()
        self.proxy_table_model.setSourceModel(self.table_model)
            #ещё можно поднастроить сортировку (например, чувствтвительность к капсу)
        self.proxy_table_model.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        #4) наконец, задаём модель в сам виджет таблицы (именно обёртку, т.е. proxy)
        self.packet_table.setModel(self.proxy_table_model)
        
        #5) настраиваем сам виджет таблицы
        self.packet_table.setSortingEnabled(True) #разрешаем сортировать
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)


        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.packet_table)
        splitter.addWidget(self.packet_details)

        layout.addLayout(control_layout)
        layout.addWidget(splitter)

        # TODO: График распределение (статистика)
        self.stats_plot = pg.PlotWidget(title="Распределение по протоколам")
        self.stats_plot.setBackground('w')
        layout.addWidget(self.stats_plot)


    def setup_connections(self):
        self.start_btn.clicked.connect(self.start_sniffer)
        self.stop_btn.clicked.connect(self.stop_sniffer)

        self.clear_button.clicked.connect(self.clear_capture)
        self.export_btn.clicked.connect(self.export_csv)

        self.packet_table.clicked.connect(self.show_packet_details)

        # Связывание сигнала обновления с обработчиком
        self.update_signal.connect(self.add_packet_to_table)
        self.sniffer.set_new_packet_callback(lambda pkt: self.update_signal.emit(pkt))

    def add_packet_to_table(self, packet_info):
        """Добавление пакета в таблицу"""
        self.table_model.add_packet(packet_info)

    def show_packet_details(self, index):
        """Отображение деталей выбранного пакета"""
        if not index.isValid():
            return
            
        row = index.row()
        packet = self.table_model._data[row]
        
        details = f"""
        Packet №{packet['no']}
        Time: {packet['time']}
        Source: {packet['source']}
        Destination: {packet['destination']}
        Protocol: {packet['protocol']}
        Length: {packet['length']} bytes
        """
        
        self.packet_details.setText(details)

    def start_sniffer(self):
        selected_interface = self.interface_combo.currentText()
        if selected_interface == "Все интерфейсы":
            selected_interface = None

        self.sniffer.start(interface=selected_interface)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
    
    def stop_sniffer(self):
        self.sniffer.stop()
        #TODO
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.update_statistics()

    def clear_capture(self):
        """Очистка захваченных пакетов"""
        self.sniffer.clear_capture()
        self.table_model.clear()
        self.packet_details.clear()
        self.update_statistics()

    def update_statistics(self):
        """Обновление графиков статистики"""
        stats = self.sniffer.get_statistics()
        
        # Очистка предыдущего графика
        self.stats_plot.clear()
        
        # Подготовка данных для графика
        protocols = list(stats['protocols'].keys())
        counts = list(stats['protocols'].values())
        
        # Создание столбчатой диаграммы
        if counts:
            bg = pg.BarGraphItem(x=range(len(protocols)), height=counts, width=0.6, brush='b')
            self.stats_plot.addItem(bg)
            
            # Настройка осей
            self.stats_plot.getAxis('bottom').setTicks(
                [[(i, protocol) for i, protocol in enumerate(protocols)]]
            )
            self.stats_plot.setLabel('left', 'Количество пакетов')
            self.stats_plot.setLabel('bottom', 'Протоколы')
         
    def export_csv(self):
        if not self.sniffer.packets:
            QMessageBox.warning(self, "Нет данных", "Нет пакетов для экспорта.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить CSV", #подпсись
            "packets.csv", #название файла
            "CSV Files (*.csv)" # расширеение шаблон
        )
        
        if path:
            try:
                export_packets_to_csv(self.sniffer.packets, path)
                QMessageBox.information(self, "Готово", "Экспорт успешно выполнен!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV:\n{e}")

if __name__=="__main__":
    app = QApplication([])

    window = MainWindow()
    window.show()

    app.exec()
