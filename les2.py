### Les. 2: sniffer class

"""
Напишем базовый класс для сниффера (скелет), 
чтобы удобно запускать, работать с данными  
"""
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional


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

# Тестирование 
if __name__ == "__main__": # код ниже будет запущен только в случае запуска самого исходного файла (т.е. при импорте не будет запускаться)
    sniffer = NetworkSniffer()
    
    print("Тестируем базовый функционал:")
    sniffer.start_sniffing()
    sniffer.stop_sniffing()