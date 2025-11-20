from scapy.all import sniff, get_if_list, IP, TCP, UDP, AsyncSniffer
import time
import threading
from collections import defaultdict

#todo: сделать снифф асинхронным, чтобы убрать блокирвоку ui

class NetworkSniffer:
    def __init__(self):
        self.packets = []
        self.is_running = False
        self.packet_count = 1
        self.oshibka = False
        #self.sniffer_thread = None # - больше не понадобится
        self.async_sniffer = None 
        self._watcher_thread = None # нить для запуска сниффера с кол-вом

        self.protocol_stats = defaultdict(int)

        #нормально инициализируем
        self.new_packet_callback = None

        # lock для безопасности (исключить data race)
        self._lock = threading.Lock()

    def set_new_packet_callback(self, callback):
        """Установка callback-функции для уведомления о новых пакетах"""
        self.new_packet_callback = callback

    def _process_packet(self, packet):
        if not self.is_running:
            return None
        
        packet_info = {
            'no': self.packet_count,
            'source': 'Unknown',
            'destination': 'Unknown',
            'protocol': 'Unknown',
            'length': len(packet),
            'time': time.strftime("%H:%M:%S", time.localtime())
        }

        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info["source"] = ip.src
            packet_info["destination"] = ip.dst
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'

                #TODO
                with self._lock:
                    packet_info['no'] = self.packet_count
                    self.packet_count += 1
                    
                self.packets.append(packet_info)
                self.protocol_stats['TCP'] += 1
                # Уведомление GUI о новом пакете
                #TODO: поменять на callable
                if callable(self.new_packet_callback):
                    try:
                        self.new_packet_callback(packet_info)
                    except Exception as e:
                        print(f"Error: {e}")
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                with self._lock:
                    packet_info['no'] = self.packet_count
                    self.packet_count += 1
                self.packets.append(packet_info)
                self.protocol_stats['UDP'] += 1
                # Уведомление GUI о новом пакете
                if callable(self.new_packet_callback):
                    try:
                        self.new_packet_callback(packet_info)
                    except Exception as e:
                        print(f"Error: {e}")   
        
        return packet_info
        
    def _watch_sniffer(self, sniffer: AsyncSniffer):
        #функция-воркер для оожидания окончания сниффера
        try:
            sniffer.join() #остановка сниффера
        except:
            pass #или выводить ошибку в консоль
        finally:
            #захват окончен, обновляем состояние
            self.is_running = False
            self.async_sniffer = None

    def start(self, packet_count=0, interface=None):
        if self.is_running:
            return False
        if not self.check_interface(interface) and interface != None: 
            print(f"\nche ta ne rabotaet, problema tyt {interface}\n")
            return False
        try:
            self.is_running = True

            self.async_sniffer = AsyncSniffer(
                iface=interface,
                prn=self._process_packet,
                count=packet_count,
                store=False
            )
            self.async_sniffer.start()

            #если уже запущен был, то очищаем предыдущую сессию
            if self.packet_count is not None:
                self._watcher_thread = threading.Thread(
                    target=self._watch_sniffer,
                    args=(self.async_sniffer,),
                    daemon=True
                )
                self._watcher_thread.start()

            # if packet_count != None:
            #     sniff(
            #         iface = interface,
            #         count = packet_count, 
            #         prn = self._process_packet)
            # else:
            #     self.sniffer_thread = threading.Thread(
            #         target=self._sniff_packets,
            #         args=(interface, self._process_packet),
            #         daemon=True
            #     )
            #     self.sniffer_thread.start()

            print("zapusk") 
            return True
        except Exception as e:
            self.is_running = False
            print(f"hfhfhhf{e}")
            return False

    def _sniff_packets(self, iface, prn):
        sniff(iface = iface,
            prn = prn)

    def check_interface(self, iface):
        if iface in self.get_available_interface():
            return True
        return False

    def get_available_interface(self):
        try: 
            available_interfaces = get_if_list()
            return available_interfaces
        except Exception as e:
            print(f"gfgff{e}")
        return []


    def stop(self):
        self.is_running = False
        # if self.sniffer_thread != None:
        #     self.sniffer_thread.join(timeout=2.0)

        try:

            #останавливанм asyncsnoffer, если он есть
            if self.async_sniffer is not None and getattr(self.async_sniffer, "running", False):
                self.async_sniffer.stop()
            
            #дожидаемся watcher-нити
            if self._watcher_thread is not None and self._watcher_thread.is_alive():
                self._watcher_thread.join(timeout=1.0)
        except Exception as e:
            print(f"error while stopping sniffer: {e}")

        finally:
            # сброс значений
            self.async_sniffer = None
            self._watcher_thread = None
        print("tutu")
    
    def get_statistics(self):
        """Получение статистики по пакетам"""
        return {
            'total_packets': self.packet_count,
            'protocols': dict(self.protocol_stats)
        }

    def clear_capture(self):
        """Очистка захваченных пакетов"""
        self.packets = []
        self.packet_count = 0
        self.protocol_stats.clear()

if __name__ == "__main__":
    a = NetworkSniffer()
    a.start(packet_count=None)
    time.sleep(5.0)
    a.stop()
    print(a.packets)




    





   
    
        