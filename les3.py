### Les. 3: sniffer class

"""
Напишем базовый класс для сниффера (скелет), 
чтобы удобно запускать, работать с данными  

Получение сетевых интерфейсов
"""
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional
import platform
#from scapy.all import get_windows_if_list
from scapy.all import get_if_list


class NetworkSniffer:
    
    # опишем "конструктор" класса 
    def __init__(self):
        # Состояние сниффера (флаг на запуск или остановку работы)
        self.is_sniffing = False
        
        # Место для хранения полученных пакетов 
        self.packets = []
        self.packet_count = 0
        
        # Статистика
        self.protocol_stats = {}
        self.ip_stats = {}
        
        # Callback-функции (функции, которые будут вызываться при определённых условиях)
        self.new_packet_callback = None
        self.error_callback = None
    
    def start_sniffing(self, interface=None, filter_text="") -> bool:
        """Запуск перехвата пакетов"""

        # защита от повторного запуска
        if self.is_sniffing:
            print("Сниффер уже запущен!")
            return False
        
        # ставим флаг на запуск работы
        self.is_sniffing = True
        print(f"Сниффер работает на сетевом интерфейсе: {interface or 'авто'}")
        print(f"Фильтр сниффера: {filter_text or 'все пакеты'}")
        return True
    
    def stop_sniffing(self):
        """Остановка перехвата"""
        if self.is_sniffing:
            self.is_sniffing = False
            print("Останавливаю перехват...")
        else:
            print("Сниффер не был запущен!")
    
    def get_available_interfaces(self) -> List[Dict]:
        """Получаем список доступных сетевых интерфейсов"""
        interfaces = []
        
        try:
            system = platform.system()
            print(f"Определяем ОС: {system}")
            
            if system == "Windows":
                # Windows использует другой API
                for iface in get_windows_if_list():
                    interfaces.append({
                        'name': iface['name'],
                        'description': iface.get('description', 'No description'),
                        'ip': iface.get('ips', ['No IP'])[0]
                    })
            else:
                # Linux и macOS
                for iface_name in get_if_list():
                    # Пропускаем виртуальные интерфейсы
                    if iface_name != 'lo' and not iface_name.startswith(('bluetooth', 'awdl')):
                        interfaces.append({
                            'name': iface_name,
                            'description': iface_name,
                            'ip': 'Определяется автоматически'
                        })
                        
        except Exception as e:
            print(f"Ошибка получения интерфейсов: {e}")
            
        return interfaces

# Тестирование 
if __name__ == "__main__": # код ниже будет запущен только в случае запуска самого исходного файла (т.е. при импорте не будет запускаться)
    sniffer = NetworkSniffer()
    interfaces = sniffer.get_available_interfaces()
    
    print("Найденные интерфейсы:")
    for i, iface in enumerate(interfaces):
        print(f"  {i+1}. {iface['name']}")
        print(f"     Описание: {iface['description']}")
        print(f"     IP: {iface['ip']}")