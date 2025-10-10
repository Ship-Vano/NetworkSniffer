### Les. 4: sniffer class

"""
Напишем базовый класс для сниффера (скелет), 
чтобы удобно запускать, работать с данными  

Обработка пакетов и разбор протоколов
"""
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional
import platform
#from scapy.all import get_windows_if_list
from scapy.all import get_if_list
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sniff


class NetworkSniffer:
    
    # опишем "конструктор" класса 
    def __init__(self):
        # Состояние сниффера (флаг на запуск или остановку работы)
        self.is_sniffing = False
        
        # Место для хранения полученных пакетов 
        self.packets = []
        self.packet_count = 0
        
        # Статистика
        self.protocol_stats = {'TCP': 0,
                               'UDP': 0
                               }
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
    
    def _process_packet(self, packet):
        """Обрабатываем каждый перехваченный пакет"""
        if not self.is_sniffing:
            return
        self.packet_count += 1
        print(f"\nПакет #{self.packet_count}")
        
        # Базовая информация
        packet_info = {
            'no': self.packet_count,
            'time': time.strftime('%H:%M:%S'),
            'source': 'Unknown',
            'destination': 'Unknown', 
            'protocol': 'Unknown',
            'length': len(packet),
            'info': ''
        }
        
        try:
            # Анализируем Ethernet фрейм
            if packet.haslayer(Ether):
                eth = packet[Ether]
                print(f"   MAC: {eth.src} -> {eth.dst}")
            
            # Анализируем IP пакеты
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['source'] = ip.src
                packet_info['destination'] = ip.dst
                
                print(f"   IP: {ip.src} -> {ip.dst}")
                print(f"   TTL: {ip.ttl}") #wiki: Time to Live, is a network parameter that limits the lifespan of data packets or records on a network by setting an expiration time or hop count before they are discarded or revalidated
                
                # Определяем протокол транспортного уровня
                if packet.haslayer(TCP):
                    self._process_tcp(packet, packet_info)
                elif packet.haslayer(UDP):
                    self._process_udp(packet, packet_info)
                else:
                    print(f" Другой IP протокол: {ip.proto}")
                
        except Exception as e:
            print(f" Ошибка разбора: {e}")
        
        # Сохраняем пакет
        self.packets.append(packet_info)
        
    def _process_tcp(self, packet, packet_info):
        """Обрабатываем TCP пакеты"""
        tcp = packet[TCP]
        packet_info['protocol'] = 'TCP'
        packet_info['info'] = f"{tcp.sport} → {tcp.dport}"
        
        print(f"Протокол: TCP")
        print(f"Порт: {tcp.sport} → {tcp.dport}")
        print(f"Размер: {len(packet)} байт")
        
        self.protocol_stats['TCP'] += 1
    
    def _process_udp(self, packet, packet_info):
        """Обрабатываем UDP пакеты"""
        udp = packet[UDP]
        packet_info['protocol'] = 'UDP' 
        packet_info['info'] = f"{udp.sport} → {udp.dport}"
        
        print(f"Протокол: UDP")
        print(f"Порт: {udp.sport} → {udp.dport}")
        
        self.protocol_stats['UDP'] += 1

# Тестирование 
if __name__ == "__main__": # код ниже будет запущен только в случае запуска самого исходного файла (т.е. при импорте не будет запускаться)
    sniffer = NetworkSniffer()

    # Захватываем 2 пакета для демонстрации
    sniffer.start_sniffing()
    sniff(prn=sniffer._process_packet, count=100)