import nmap
import json
import ipaddress
import pandas as pd
from tqdm import tqdm
import logging
import paramiko
from timeout_decorator import timeout  # Добавляем библиотеку timeout_decorator

logging.basicConfig(filename='1NEW_scan_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s: %(message)s')


class IPScanner:
    def __init__(self, start_ip, end_ip, output_file):
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.output_file = output_file
        self.results = []

    def scan_ip(self, ip_address):
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments="-T4 -F")

        result = {
            'ip_address': ip_address,
            'open_ports': [],
            'services': {}
        }

        try:
            for host in nm.all_hosts():
                open_ports = list(nm[host]['tcp'].keys())
                result['open_ports'] = open_ports

                for port, port_info in nm[host]['tcp'].items():
                    service_name = port_info['name']
                    service_product = port_info['product']
                    service_version = port_info['version']

                    result['services'][port] = {
                        'name': service_name,
                        'product': service_product,
                        'version': service_version
                    }
        except KeyError:
            pass

        logging.info(
            f"Открытые порты для IP-адреса {ip_address}: {', '.join(map(str, result['open_ports']))}")

        return result

    def scan_ip_range(self):
        start_ip_int = int(ipaddress.IPv4Address(self.start_ip))
        end_ip_int = int(ipaddress.IPv4Address(self.end_ip))

        for ip_int in tqdm(range(start_ip_int, end_ip_int + 1), desc="Сканирование IP"):
            ip = str(ipaddress.IPv4Address(ip_int))

            logging.info(f"Сканирование IP-адреса: {ip}")

            result = self.scan_ip(ip)
            self.results.append(result)

        with open(self.output_file + '.json', 'w') as json_file:
            json.dump(self.results, json_file, indent=4)

        logging.info("Сканирование завершено")

        df = pd.DataFrame(self.results)
        excel_file = self.output_file + '.xlsx'
        df.to_excel(excel_file, index=False)

        print(
            f"Сканирование завершено. Результаты сохранены в {self.output_file}.json и {excel_file}")


@timeout(10)  # Установим тайм-аут в 10 секунд для авторизации
def ssh_login(ip_address, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, port=22, username=username, password=password)
        ssh.close()
        logging.info(
            f"Успешная авторизация SSH на {ip_address} с логином '{username}' и паролем '{password}'")
        return True
    except Exception as e:
        logging.info(
            f"Не удалось авторизоваться SSH на {ip_address} с логином '{username}' и паролем '{password}': {str(e)}")
        return False


@timeout(10)  # Установим тайм-аут в 10 секунд для авторизации
def rdp_login(ip_address, username, password):
    try:
        rdp = FreeRDP()
        rdp.set_hostname(ip_address)
        rdp.set_username(username)
        rdp.set_password(password)
        rdp.set_domain("")
        rdp.set_security(True)
        rdp.set_ignore_certificate()
        rdp.set_bpp(32)
        rdp.set_console_audio(True)
        rdp.set_redirect_microphone(True)
        rdp.set_redirect_usb(True)
        rdp.set_redirect_printer(True)
        rdp.set_multimon(True)
        rdp.set_resolution("1920x1080")
        rdp.set_shell("explorer.exe")
        rdp.set_port(3389)
        rdp.set_debug(True)

        if not rdp.connect():
            logging.info(
                f"Не удалось авторизоваться RDP на {ip_address} с логином '{username}' и паролем '{password}'")
            return False

        rdp.disconnect()
        logging.info(
            f"Успешная авторизация RDP на {ip_address} с логином '{username}' и паролем '{password}'")
        return True
    except Exception as e:
        logging.info(
            f"Не удалось авторизоваться RDP на {ip_address} с логином '{username}' и паролем '{password}': {str(e)}")
        return False


if __name__ == "__main__":
    logging.info("Начало работы программы")

    start_ip, end_ip = input(
        "Введите начальный IP-адрес: "), input("Введите конечный IP-адрес: ")
    output_file = 'scan_results'

    scanner = IPScanner(start_ip, end_ip, output_file)
    scanner.scan_ip_range()

    for result in scanner.results:
        ip_address = result['ip_address']
        open_ports = result['open_ports']
        if 22 in open_ports:
            if ssh_login(ip_address, 'admin', 'admin'):
                print(
                    f"Успешная авторизация SSH на {ip_address} с логином 'admin' и паролем 'admin'")
        if 3389 in open_ports:
            if rdp_login(ip_address, 'admin', 'admin'):
                print(
                    f"Успешная авторизация RDP на {ip_address} с логином 'admin' и паролем 'admin'")

    logging.info("Завершение работы программы")
