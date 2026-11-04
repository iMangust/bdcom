import re
import time
import logging
from typing import List, Dict, Any, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import (
NetmikoTimeoutException, NetmikoAuthenticationException
)


# Централизованная настройка логирования — в app.setup_logging().
# basicConfig() на уровне модуля убран: он менял глобальное состояние
# корневого логгера при каждом импорте ssh_client. Файловый handler для
# SSH-команд добавляется ниже точечно, только для этого логгера.
logger = logging.getLogger('BDCOM_SSH')


def _attach_file_handler(log_file='bdcom.log'):
    """Добавляет файловый handler к логгеру BDCOM_SSH (идемпотентно)."""
    for h in logger.handlers:
        if isinstance(h, logging.FileHandler):
            return
    try:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(fh)
    except OSError:
        pass  # файловое логирование SSH необязательно


_attach_file_handler()


# Строгий формат имени PON-интерфейса для подстановки в команды OLT.
# Именно fullmatch: re.match/r'^...$' пропускают завершающий '\n', что
# позволяло инъекцию второй строки команд ('EPON1/1:1\nconfig terminal').
INTERFACE_RE = re.compile(r'^(?:EPON|GPON)\d+/\d+:\d+$', re.I)

# Отдельный паттерн для разбора интерфейса на составные части
# (тип, слот, порт, номер ONU) — используется в delete_onu.
INTERFACE_PARTS_RE = re.compile(
    r'^(EPON|GPON)(\d+)/(\d+):(\d+)$', re.I
)

# Имя PON-интерфейса без номера ONU ('GPON0/13') — используется в
# update_onu_description: UI передаёт полное имя ONU 'GPON0/13:68', а
# batch-синк описаний — уже усечённое 'GPON0/13'. Строгие якоря +
# fullmatch запрещают переводы строк (защита от инъекций команд).
IFACE_NAME_RE = re.compile(r'^(EPON|GPON)\d+/\d+$', re.I)


def is_valid_interface(interface) -> bool:
    """Проверка формата интерфейса перед отправкой в команду SSH."""
    return bool(interface) and bool(INTERFACE_RE.fullmatch(str(interface)))


class BDCOMSSHClient:
    DEVICE_TYPE_MAP = {
'3310': 'cisco_ios',
'GP3600': 'cisco_ios',
}


    MAX_MORE_PAGES = 500
    MORE_PAGE_DELAY = 0.3
    COMMAND_DELAY = 0.5
    EMPTY_READ_DELAY = 0.8
    MAX_EMPTY_READS = 15

    def __init__(self, hostname: str, username: str, password: str,
enable_password: str, port: int = 22, model: str = '3310'):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.port = port
        self.model = model
        self.connection = None
        self.connected = False
        self.device_params = {
'device_type': self.DEVICE_TYPE_MAP.get(model, 'cisco_ios'),
'host': hostname,
'username': username,
'password': password,
'secret': enable_password,
'port': port,
'timeout': 30,
'session_timeout': 120,
'blocking_timeout': 15,
'auth_timeout': 30,
'banner_timeout': 60,
'global_delay_factor': 3,
'fast_cli': False,
}

    def connect(self) -> bool:
        try:
            logger.info(f"Connecting to {self.hostname} (model={self.model})")
            if self.connection:
                try:
                    self.connection.disconnect()
                except Exception as e:
                    logger.debug("Disconnecting stale connection to %s failed (ignored): %s", self.hostname, e)
                self.connection = None
            # Netmiko наследует default_host_keys_policy из Paramiko, которая
            # по умолчанию "auto": первый ключ молча принимается и запоминается,
            # но при изменении хоста соединение падает с HostKeysException —
            # для сетевых устройств с регулярной переустановкой это source of
            # false alerts. Явно фиксируем политику "reject" только если
            # пользователь сам её задал; по умолчанию оставляем поведение
            # netmiko, но прокидываем значение из config, если задан env.
            try:
                from config import SSH_CONFIG
                policy = SSH_CONFIG.get('host_keys_policy')
                if policy:
                    self.device_params['host_keys_check'] = policy
            except Exception as e:
                logger.debug("SSH host-keys policy not taken from config (backward compat): %s", e)
            self.connection = ConnectHandler(**self.device_params)
            self.connection.enable()


            try:
                self.connection.send_command_timing("terminal length 0", strip_prompt=False)
                time.sleep(0.8)
            except Exception as e:
                logger.warning(f"Failed to set terminal length 0: {e}")
            self.connected = True
            logger.info(f"✅ Connected to {self.hostname}")
            return True
        except NetmikoAuthenticationException as e:
            logger.error(f"Auth failed for {self.hostname}: {e}", exc_info=True)
            return False
        except NetmikoTimeoutException as e:
            logger.error(f"Timeout connecting to {self.hostname}: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Connection error {self.hostname}: {type(e).__name__}: {e}", exc_info=True)
            return False

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None
                self.connected = False

    def _ensure_connected(self) -> bool:
        if not self.connected or not self.connection:
            return self.connect()
        try:
            self.connection.write_channel('\n')
            time.sleep(0.5)
            output = self.connection.read_channel()
            if output is None and not self.connection.is_alive():
                logger.warning(f"Connection to {self.hostname} is dead, reconnecting...")
                return self.connect()
            return True
        except Exception as e:
            logger.warning(f"Connection check failed: {e}, reconnecting...")
            return self.connect()

    def _send(self, command: str, timeout: int = 300) -> str:
        if not self._ensure_connected():
            return ""
        try:
            output = self.connection.send_command_timing(
command,
strip_prompt=False,
strip_command=False,
delay_factor=3,
read_timeout=timeout,
)
            more_count = 0
            start_time = time.time()
            empty_reads = 0
            while time.time() - start_time < timeout:

                has_more = (
'--More--' in output or
'\x08' in output or
output.rstrip().endswith('--')
)
                if has_more:
                    more_count += 1
                    if more_count > self.MAX_MORE_PAGES:
                        logger.warning(f"Too many --More-- pages ({more_count}) for '{command}', breaking")
                        break
                    self.connection.write_channel(' ')
                    time.sleep(self.MORE_PAGE_DELAY)
                    new_data = self.connection.read_channel()
                    if new_data:
                        output += new_data
                        empty_reads = 0

                        output = output.replace('--More--', '')
                        output = output.replace('--More', '')
                        output = re.sub(r'\x08+', '', output)
                        output = re.sub(r'\s+--\s*$', '', output)
                else:
                    last_line = output.split('\n')[-1] if output else ''
                    if re.search(r'[#>]\s*$', last_line) and len(last_line.strip()) < 30:
                        break
                    time.sleep(self.COMMAND_DELAY)
                    new_data = self.connection.read_channel()
                    if new_data:
                        output += new_data
                        empty_reads = 0
                    else:
                        empty_reads += 1
                        if empty_reads > self.MAX_EMPTY_READS:
                            logger.debug(f"Max empty reads ({self.MAX_EMPTY_READS}) reached for '{command}'")
                            break
                        time.sleep(self.EMPTY_READ_DELAY)
                        new_data = self.connection.read_channel()
                        if not new_data:
                            if empty_reads > 8:
                                break
                        else:
                            output += new_data
                            empty_reads = 0

            output = re.sub(r'\x1b\[[0-9;]*[mK]', '', output)
            output = re.sub(r'\x08+', '', output)
            output = output.replace('--More--', '')
            output = output.replace('--More', '')
            output = re.sub(r'\s+--\s*$', '', output)
            logger.info(f"Command '{command}' returned {len(output)} chars, {more_count} --More-- pages")
            return output
        except Exception as e:
            logger.error(f"Command error '{command}': {type(e).__name__}: {e}", exc_info=True)
            self.connected = False
            return ""

    def _send_config(self, command: str, wait: float = 1.5) -> str:
        if not self._ensure_connected():
            return ""
        try:
            output = self.connection.send_command_timing(
command,
strip_prompt=False,
strip_command=False,
delay_factor=2,
max_loops=50,
)
            time.sleep(wait)
            try:
                extra = self.connection.read_channel()
                if extra:
                    output += extra
            except Exception:
                pass
            output = re.sub(r'\x1b\[[0-9;]*[mK]', '', output)
            output = re.sub(r'\x08+', '', output)
            output = output.replace('--More--', '')
            return output
        except Exception as e:
            logger.error(f"Config command error '{command}': {type(e).__name__}: {e}", exc_info=True)
            self.connected = False
            return ""


    def get_onu_information(self) -> Optional[List[Dict[str, Any]]]:
        if not self.connect():
            logger.error(f"get_onu_information: failed to connect to {self.hostname}")
            return None
        try:
            if self.model == 'GP3600':
                result = self._get_gp3600_onu_information_comprehensive()
            else:
                result = self._get_3310_onu_information_comprehensive()
            if result is None:
                logger.error(f"get_onu_information: internal method returned None for {self.hostname}")
                return None
            logger.info(f"get_onu_information: got {len(result)} ONUs from {self.hostname}")
            return result
        except Exception as e:
            logger.error(f"Error getting ONU info from {self.hostname}: {type(e).__name__}: {e}", exc_info=True)
            return None
        finally:
            self.close()

    def refresh_single_onu(self, interface: str) -> Dict[str, Any]:
        if not self.connect():
            return {'error': 'Connection failed'}
        try:
            if self.model == '3310':
                optical = self._get_3310_optical_power_comprehensive([interface])
                macs = self._get_3310_mac_addresses_comprehensive()
            else:
                optical = self._get_gp3600_optical_power_comprehensive([interface])
                macs = self._get_gp3600_mac_addresses_comprehensive()
            optical_power = optical.get(interface.lower())
            client_macs = macs.get(interface, [])
            onu_data = {
'interface': interface,
'vendor': 'N/A',
'model': 'N/A',
'mac': 'N/A',
'description': 'N/A',
'bind_type': 'static',
'optical_power': optical_power,
'client_macs': client_macs,
}
            if optical_power is not None:
                onu_data['status'] = 'active'
                onu_data['dereg_reason'] = 'N/A'
            else:
                onu_data['status'] = 'off-line'
                onu_data['dereg_reason'] = 'No Optical Power'
            return onu_data
        except Exception as e:
            logger.error(f"Refresh error: {e}", exc_info=True)
            return {'error': str(e)}
        finally:
            self.close()

    def _ensure_live_session(self) -> bool:
        """Гарантирует живое SSH-соединение, НЕ пересоздавая активное.

        В отличие от connect(), который всегда рвёт старый session и создаёт
        новый (см. начало connect()), этот метод переиспользует уже открытое
        соединение — важно для write-операций, которые вызываются сразу после
        ssh_client.connect() в app.py: раньше получалось два TCP/SSH-сессии
        на одну операцию. Если соединение протухло, _ensure_connected()
        выполнит reconnect сам.
        """
        return self._ensure_connected()

    @staticmethod
    def _onu_interface_name(interface) -> str:
        """Возвращает имя PON-интерфейса для команды 'interface ...' или ''.

        Принимает как полное имя ONU ('GPON0/13:68'), так и имя интерфейса
        ('GPON0/13'); обе формы проверяются строгими fullmatch-паттернами,
        поэтому переводы строк и прочие инъекции отсекаются.
        """
        s = str(interface or '').strip()
        if IFACE_NAME_RE.fullmatch(s):
            return s
        m = INTERFACE_PARTS_RE.fullmatch(s)
        if m:
            itype, slot, port, _onu = m.groups()
            return f'{itype}{slot}/{port}'
        return ''

    def update_onu_description(self, interface: str, description: str) -> bool:
        logger.info(f"Updating description for {interface} to: '{description}'")
        # Принимаем как полное имя ONU ('GPON0/13:68' — приходит из UI/onu_detail),
        # так и имя интерфейса без ':N' ('GPON0/13' — из batch-синка описаний).
        iface_name = self._onu_interface_name(interface)
        if not iface_name:
            logger.error(f"Rejected invalid interface format: {interface!r}")
            return False
        if not self._ensure_live_session():
            logger.error("Failed to connect to OLT")
            return False
        try:
            config_res = self._send_config('config', wait=2.0)
            if self._is_error_reply(config_res):
                logger.error(f"Failed to enter config mode for update_onu_description({interface}): {config_res!r}")
                return False
            result = self._send_config(f'interface {iface_name}', wait=1.5)
            if not result or self._is_error_reply(result):
                logger.error(f"Failed to enter interface {iface_name}: {result!r}")
                self._send_config('exit', wait=1.0)
                return False
            if description and description.strip():
                # Defense-in-depth (этап 25): вырезаем ВСЕ управляющие символы
                # C0/C1, включая U+0085 NEL — Cisco/Comware-парсеры OLT режут
                # ввод по NEL так же, как по \n, что позволяло инъекцию второй
                # строки команд. Whitlist в sanitize_description (app.py) тоже
                # их отсекает, но ssh_client должен быть безопасен и сам по себе.
                description = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', description)
                safe_desc = description.strip()[:100]
                safe_desc = ' '.join(safe_desc.split())
                cmd = f'description {safe_desc}'
            else:
                cmd = 'no description'
            desc_res = self._send_config(cmd, wait=1.5)
            self._send_config('exit', wait=1.0)
            self._send_config('exit', wait=1.0)
            if not desc_res or self._is_error_reply(desc_res):
                logger.error(f"OLT rejected '{cmd}' on {interface}: {desc_res!r}")
                return False
            self._send_config('write', wait=3.0)
            return True
        except Exception as e:
            logger.error(f"Error updating description for {interface}: {e}", exc_info=True)
            return False
        finally:
            self.close()

    def sync_onu_descriptions(self, sync_list: List[Dict[str, str]]) -> int:
        if not sync_list:
            return 0
        if not self._ensure_live_session():
            logger.error("Failed to connect for description sync")
            return 0
        synced_count = 0
        try:
            config_res = self._send_config('config', wait=2.0)
            if self._is_error_reply(config_res):
                logger.error(f"Failed to enter config mode for desc sync: {config_res!r}")
                return 0
            for item in sync_list:
                interface = item.get('interface')
                description = item.get('description', '').strip()
                if not interface or not description:
                    continue
                # Защита от инъекции команд через имя интерфейса (см. _onu_interface_name).
                # Принимаем и полное ONU-имя 'GPON0/13:68', и имя интерфейса 'GPON0/13'.
                iface_name = self._onu_interface_name(interface)
                if not iface_name:
                    logger.warning(f"Skipping invalid interface in sync: {interface!r}")
                    continue
                result = self._send_config(f'interface {iface_name}', wait=1.0)
                if not result or self._is_error_reply(result):
                    logger.warning(f"Failed to enter interface {iface_name} for desc sync: {result!r}")
                    self._send_config('exit', wait=0.5)
                    continue
                # Defense-in-depth (этап 25): вырезаем ВСЕ управляющие символы
                # C0/C1, включая U+0085 NEL — Cisco/Comware-парсеры OLT режут
                # ввод по NEL так же, как по \n, что позволяло инъекцию второй
                # строки команд. Тот же приём, что в update_onu_description.
                safe_desc = ' '.join(re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', description).split())[:100]
                cmd = f'description {safe_desc}'
                desc_res = self._send_config(cmd, wait=1.0)
                self._send_config('exit', wait=0.5)
                if not desc_res or self._is_error_reply(desc_res):
                    logger.warning(f"OLT rejected description on {interface}: {desc_res!r}")
                    continue
                synced_count += 1
                logger.info(f"✅ Synced description for {interface}: '{safe_desc}'")
            self._send_config('exit', wait=1.0)
            self._send_config('write', wait=3.0)
            logger.info(f"Successfully synced {synced_count}/{len(sync_list)} descriptions")
        except Exception as e:
            logger.error(f"Error during batch description sync: {e}", exc_info=True)
        finally:
            self.close()
        return synced_count

    @staticmethod
    def _is_error_reply(output: str) -> bool:
        """Признаки отказа BDCOM/Cisco-подобного CLI на ответ команды.

        Ответы вида '% Invalid input', '% Unknown command', '^' в маркере
        позиции ошибки говорят о том, что команда НЕ выполнена. Пустой
        ответ сюда не входит — его обрабатывает вызывающий код отдельно.
        """
        if not output:
            return False
        low = output.lower()
        markers = ('% err', '% invalid', '% unknown', '% unrecogniz',
                   'error:', 'invalid input', 'unknown command')
        return any(m in low for m in markers)

    def delete_onu(self, interface: str) -> bool:
        """Удаляет ONU с OLT по имени интерфейса вида 'GPON0/13:68' / 'EPON1/2:7'.

        Возвращает True только если команда `no ... bind-onu seq N` реально
        применена. Ответ OLT проверяется на маркеры ошибки ('%', 'error',
        'invalid', 'unknown') — раньше True возвращался unconditional, и
        UI считал ONU удалённой даже при отказе конфигурирования.
        """
        logger.info(f"Deleting ONU {interface}")
        # Валидация формата ДО подключения (защита от инъекций — см. INTERFACE_PARTS_RE)
        match = INTERFACE_PARTS_RE.fullmatch((interface or '').strip())
        if not match:
            logger.error(f"Invalid interface format: {interface!r}")
            return False
        itype, slot, port, onu_num = match.groups()
        iface_name = f'{itype}{slot}/{port}'
        if not self._ensure_live_session():
            return False
        try:
            config_res = self._send_config('config', wait=2.0)
            if self._is_error_reply(config_res):
                logger.error(f"Failed to enter config mode for delete_onu({interface}): {config_res!r}")
                return False
            result = self._send_config(f'interface {iface_name}', wait=1.5)
            if not result or self._is_error_reply(result):
                logger.error(f"Failed to enter interface {iface_name}: {result!r}")
                self._send_config('exit', wait=1.0)
                return False
            cmd = f'no epon bind-onu seq {onu_num}' if itype.upper() == 'EPON' else f'no gpon bind-onu seq {onu_num}'
            del_res = self._send_config(cmd, wait=2.0)
            self._send_config('exit', wait=1.0)   # из interface-режима
            self._send_config('exit', wait=1.0)   # из config-режима
            if self._is_error_reply(del_res):
                logger.error(f"OLT rejected '{cmd}' on {self.hostname}: {del_res!r}")
                return False
            self._send_config('write', wait=3.0)
            logger.info(f"✅ Deleted ONU {interface} ({cmd})")
            return True
        except Exception as e:
            logger.error(f"Error deleting ONU {interface}: {e}", exc_info=True)
            return False
        finally:
            self.close()

    def save_running_config(self) -> str:
        if not self.connect():
            return ""
        try:
            return self._send("show running-config", timeout=600)
        finally:
            self.close()


    def _get_gp3600_onu_information_comprehensive(self) -> Optional[List[Dict[str, Any]]]:
        try:
            all_out = self._send("show gpon onu-information", timeout=600)
            if all_out is None:
                return None
            inactive_out = self._send("show gpon inactive-onu", timeout=180)
            desc_out = self._send("show gpon onu-description", timeout=180)
            expected_ifaces = set(re.findall(r'GPON\d+/\d+:\d+', all_out, re.I))
            optical = self._get_gp3600_optical_power_comprehensive(expected_ifaces)
            macs = self._get_gp3600_mac_addresses_comprehensive()
            descriptions = self._parse_gp3600_descriptions(desc_out)
            inactive = self._parse_gp3600_inactive(inactive_out)
            return self._parse_gp3600_all_onu(all_out, descriptions, optical, macs, inactive)
        except Exception as e:
            logger.error(f"GP3600 comprehensive error: {e}", exc_info=True)
            return None

    def _get_3310_onu_information_comprehensive(self) -> Optional[List[Dict[str, Any]]]:
        try:
            onu_out = self._send("show epon onu-information", timeout=600)
            if onu_out is None:
                return None
            inactive_out = self._send("show epon inactive-onu", timeout=180)
            expected_ifaces = set(re.findall(r'EPON\d+/\d+:\d+', onu_out, re.I))
            optical = self._get_3310_optical_power_comprehensive(expected_ifaces)
            macs = self._get_3310_mac_addresses_comprehensive()
            inactive = self._parse_3310_inactive(inactive_out)
            return self._parse_3310_onu_info(onu_out, optical, macs, inactive)
        except Exception as e:
            logger.error(f"3310 comprehensive error: {e}", exc_info=True)
            return None

    def _get_gp3600_optical_power_comprehensive(self, expected_interfaces=None) -> Dict[str, float]:
        data = {}
        out = self._send("show gpon onu-optical-transceiver-diagnosis", timeout=180)
        if out:
            data.update(self._parse_optical_bulk(out, 'gpon'))
        missing_ifaces = set()
        if expected_interfaces:
            for iface in expected_interfaces:
                if iface.lower() not in data:
                    missing_ifaces.add(iface)
        if len(data) < 10 or missing_ifaces:
            ifaces_out = self._send("show interface brief", timeout=60)
            if ifaces_out:
                if missing_ifaces:
                    ports_to_query = set()
                    for iface in missing_ifaces:
                        m = re.match(r'(GPON\d+/\d+):\d+', iface, re.I)
                        if m:
                            ports_to_query.add(m.group(1).lower())
                else:
                    ports_to_query = set(re.findall(r'GPON\d+/\d+', ifaces_out, re.I))
                for iface in ports_to_query:
                    for attempt in range(2):
                        try:
                            o = self._send(f"show gpon onu-optical-transceiver-diagnosis interface {iface}", timeout=180)
                            if o:
                                for line in o.splitlines():
                                    line = line.strip()
                                    if line.lower().startswith('gpon') and ':' in line:
                                        parts = line.split()
                                        if len(parts) >= 5:
                                            try:
                                                v = float(parts[4])
                                                if -50 <= v <= 0:
                                                    data[parts[0].lower()] = v
                                            except ValueError:
                                                pass
                                break
                        except Exception as e:
                            logger.warning(f"Retry {attempt+1}/2 for gpon optical {iface}: {e}")
                            time.sleep(1)
                            if not self._ensure_connected():
                                break
        return data

    def _get_3310_optical_power_comprehensive(self, expected_interfaces=None) -> Dict[str, float]:
        data = {}


        ifaces_out = self._send("show interface brief", timeout=60)
        if not ifaces_out:
            return data
        ports_to_query = set()
        if expected_interfaces:
            for iface in expected_interfaces:
                m = re.match(r'(EPON\d+/\d+):\d+', iface, re.I)
                if m:
                    ports_to_query.add(m.group(1).lower())
        else:
            ports_to_query = set(re.findall(r'EPON\d+/\d+', ifaces_out, re.I))

        ports_to_query = {p.lower() for p in ports_to_query}
        logger.info(f"Querying optical power for {len(ports_to_query)} ports (per-interface mode)")
        for iface in ports_to_query:
            for attempt in range(3):
                try:

                    o = self._send(f"show epon onu-ctc-optical-transceiver-diagnosis interface {iface.lower()}", timeout=180)
                    if o:
                        for line in o.splitlines():
                            line = line.strip()
                            if line.lower().startswith('epon') and ':' in line:
                                parts = line.split()

                                if len(parts) >= 6:
                                    try:
                                        v = float(parts[5])
                                        if -50 <= v <= 0:
                                            data[parts[0].lower()] = v
                                    except ValueError:
                                        pass
                        break
                except Exception as e:
                    logger.warning(f"Retry {attempt+1}/3 for epon optical {iface}: {e}")
                    time.sleep(1)
                    if not self._ensure_connected():
                        break
        logger.info(f"Got optical power for {len(data)} ONUs")
        return data

    def _parse_optical_bulk(self, output: str, onu_type: str) -> Dict[str, float]:
        data = {}
        current = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('Interface'):
                m = re.search(f'{onu_type.upper()}\\d+/\\d+', line, re.I)
                if m:
                    current = m.group(0)
                continue
            if current and line.lower().startswith(onu_type) and ':' in line:
                parts = line.split()
                if len(parts) >= 5:
                    idx = 4 if onu_type == 'gpon' else 5
                    if len(parts) > idx:
                        try:
                            v = float(parts[idx])
                            if -50 <= v <= 0:
                                data[parts[0].lower()] = v
                        except ValueError:
                            pass
        return data

    def _get_gp3600_mac_addresses_comprehensive(self) -> Dict[str, List[Dict[str, str]]]:
        return self._get_mac_addresses_comprehensive('gpon')

    def _get_3310_mac_addresses_comprehensive(self) -> Dict[str, List[Dict[str, str]]]:
        return self._get_mac_addresses_comprehensive('epon')

    def _get_mac_addresses_comprehensive(self, onu_type: str) -> Dict[str, List[Dict[str, str]]]:
        mac_data = {}
        out = self._send("show mac address-table", timeout=600)
        if not out:
            return mac_data
        onu_macs = self._get_onu_macs(onu_type)
        for line in out.splitlines():
            line = line.strip()
            if not line or any(x in line for x in ['Mac Address Table', 'Vlan', '----', 'Total', '-----']):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            vlan, mac, mtype = parts[0], parts[1], parts[2]
            port = ' '.join(parts[3:])
            if self._should_skip_mac(mac) or self._is_onu_mac(mac, onu_macs):
                continue
            onu_iface = self._extract_onu_interface(port, onu_type)
            if onu_iface:
                mac_data.setdefault(onu_iface, []).append({
'vlan': vlan,
'mac_address': mac,
'type': mtype,
'port': port,
})
        logger.info(f"Got {sum(len(v) for v in mac_data.values())} client MACs for {len(mac_data)} ONUs")
        return mac_data

    def _get_onu_macs(self, onu_type: str) -> Dict[str, str]:
        cmd = "show gpon onu-information" if onu_type == 'gpon' else "show epon onu-information"
        out = self._send(cmd, timeout=90)
        onu_macs = {}
        if not out:
            return onu_macs
        pattern = r'^[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}$'
        for line in out.splitlines():
            if line.strip().upper().startswith(onu_type.upper()) and ':' in line:
                parts = line.split()
                for part in parts:
                    if re.match(pattern, part) and not part.startswith('0x'):
                        onu_macs[part] = parts[0]
                        break
        return onu_macs

    def _should_skip_mac(self, mac: str) -> bool:
        if not mac or len(mac) < 12:
            return True
        clean = mac.replace('.', '').replace(':', '').lower()
        skip = ('ffff', '0180c2', '01000c', '01005e', '3333', '00000c')
        if any(clean.startswith(p) for p in skip):
            return True
        try:
            if int(clean[0:2], 16) & 0x01:
                return True
        except ValueError:
            pass
        return False

    def _is_onu_mac(self, mac: str, onu_macs: Dict[str, str]) -> bool:
        if not mac or not onu_macs:
            return False
        clean = mac.replace('.', '').replace(':', '').lower()
        return any(clean == onu.replace('.', '').replace(':', '').lower() for onu in onu_macs)

    def _extract_onu_interface(self, port: str, onu_type: str) -> Optional[str]:
        port = port.strip().lower()
        if onu_type in port and ':' in port:
            if onu_type == 'gpon':
                parts = port.split(':')
                if len(parts) == 2:
                    return f"{parts[0].replace('gpon', 'GPON')}:{parts[1].split('-')[0]}"
            else:
                return port.replace('epon', 'EPON')
        return None


    def _parse_gp3600_descriptions(self, output: str) -> Dict[str, str]:
        descriptions = {}
        if not output:
            return descriptions
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('IntfName') or '------' in line:
                continue
            if line.startswith('GPON') and ':' in line:
                parts = line.split()
                if len(parts) < 3:
                    continue
                iface = parts[0]
                desc_parts = []
                for p in parts[1:]:
                    if ':' in p:
                        break
                    desc_parts.append(p)
                desc = ' '.join(desc_parts).strip() or 'N/A'
                if not desc or desc == iface:
                    desc = 'N/A'
                descriptions[iface] = desc
        return descriptions

    def _parse_gp3600_inactive(self, output: str) -> Dict[str, Dict[str, str]]:
        data = {}
        if not output:
            return data
        current = None
        for i, line in enumerate(output.splitlines()):
            line = line.strip()
            if line.startswith('Interface GPON') and 'has bound' in line:
                m = re.search(r'GPON\d+/\d+', line)
                if m:
                    current = m.group(0)
                continue
            if current and line.startswith('GPON') and ':' in line:
                onu_lines = [line]
                j = i + 1
                lines = output.splitlines()
                while j < len(lines):
                    nl = lines[j].strip()
                    if not nl or nl.startswith(('GPON', 'Interface')):
                        break
                    onu_lines.append(nl)
                    j += 1
                full = ' '.join(onu_lines).lower()
                parts = re.split(r'\s+', onu_lines[0])
                if len(parts) >= 4:
                    iface, sn = parts[0], parts[1] if len(parts) > 1 else 'N/A'
                    reason = 'Unknown'
                    for kw, r in [('dying gasp', 'Dying Gasp'), ('losi', 'LOSi'), ('lob', 'LOB'),
('power-off', 'Power Off'), ('wire-down', 'Wire Down'),
('disconnect', 'Disconnect'), ('deactivate', 'Deactivate'),
('deregister', 'Deregister'), ('offline', 'Offline')]:
                        if kw in full:
                            reason = r
                            break
                    data[iface] = {'sn': sn, 'status': 'off-line', 'dereg_reason': reason, 'interface': current}
        return data

    def _parse_gp3600_all_onu(self, output, descriptions, optical, mac_data, inactive):
        onus = []
        if not output:
            return onus
        current = None
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if 'has bound' in line and 'ONUs' in line:
                m = re.search(r'GPON\d+/\d+', line)
                if m:
                    current = m.group(0)
                continue
            if current and line.startswith('GPON') and ':' in line:
                try:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    iface, vendor = parts[0], parts[1]
                    model, sn = 'N/A', 'N/A'
                    for i in range(2, len(parts)):
                        if ':' in parts[i] and len(parts[i]) > 4:
                            sn = parts[i]
                            if i > 2:
                                model = parts[i - 1]
                            break
                    if sn == 'N/A' and len(parts) >= 4 and ':' in parts[3]:
                        sn, model = parts[3], parts[2] if len(parts) > 2 else 'N/A'
                    desc = descriptions.get(iface, 'N/A')
                    if desc == iface or not desc.strip():
                        desc = 'N/A'
                    optical_p = optical.get(iface.lower())
                    status, reason = 'active', 'N/A'
                    if iface in inactive:
                        status = inactive[iface].get('status', 'off-line')
                        reason = inactive[iface].get('dereg_reason', 'Unknown')
                    elif optical_p is None:
                        status, reason = 'off-line', 'No Optical Power'
                    onus.append({
'interface': iface,
'vendor': vendor,
'model': model,
'mac': sn,
'description': desc,
'bind_type': 'static',
'status': status,
'dereg_reason': reason,
'optical_power': optical_p,
'client_macs': mac_data.get(iface, []),
})
                except Exception as e:
                    logger.error(f"Parse GPON line error: {e}", exc_info=True)
        return self._sort_onus(onus)

    def _parse_3310_inactive(self, output: str) -> Dict[str, Dict[str, str]]:
        data = {}
        if not output:
            return data
        current = None
        header_passed = False
        buffer = []
        collecting = False
        lines = output.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('Interface EPON') and 'has bound' in line:
                if buffer and current:
                    self._process_3310_buffer(buffer, current, data)
                    buffer = []
                m = re.search(r'EPON\d+/\d+', line)
                if m:
                    current = m.group(0)
                    header_passed = False
                i += 1
                continue
            if line.startswith('IntfName') and 'MAC Address' in line:
                header_passed = True
                i += 1
                continue
            if '---------------- -------------- ----------------' in line:
                i += 1
                continue
            if current and header_passed and line.startswith('EPON') and ':' in line:
                buffer = [line]
                collecting = True
                i += 1
                while i < len(lines):
                    nl = lines[i].strip()
                    if (nl.startswith('EPON') and ':' in nl) or nl.startswith('Interface EPON'):
                        break
                    if not nl and i + 1 < len(lines) and lines[i + 1].strip().startswith('EPON'):
                        break
                    buffer.append(nl)
                    i += 1
                self._process_3310_buffer(buffer, current, data)
                buffer = []
                collecting = False
                continue
            if collecting and current:
                buffer.append(line)
            i += 1
        if buffer and current:
            self._process_3310_buffer(buffer, current, data)
        return data

    def _process_3310_buffer(self, buffer, current, data):
        try:
            full = ' '.join(ln for ln in buffer if ln)
            full = re.sub(r'\s+', ' ', full).strip()
            if not full:
                return
            parts = full.split()
            if not parts or len(parts) < 2:
                return
            iface = parts[0]
            low = full.lower()

            reason = 'unknown'
            for kw, r in [('power-off', 'power-off'), ('wire-down', 'wire-down'),
('llid-admin-down', 'llid-admin-down'), ('dying-gasp', 'dying-gasp'),
('unknow', 'unknown')]:
                if kw in low:
                    reason = r
                    break
            data[iface] = {'status': 'off-line', 'dereg_reason': reason, 'interface': current}
        except Exception as e:
            logger.error(f"Process 3310 buffer error: {e}", exc_info=True)

    def _parse_3310_onu_info(self, onu_out, optical, mac_data, inactive):
        onus = []
        if not onu_out:
            return onus
        lines = onu_out.splitlines()
        current = None
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith('Interface EPON') and 'has registered' in line:
                m = re.search(r'EPON\d+/\d+', line)
                if m:
                    current = m.group(0)
                continue
            if current and line.startswith('EPON') and ':' in line:
                try:
                    full = line

                    for j in range(i + 1, min(i + 3, len(lines))):
                        nl = lines[j].strip()
                        if not nl or nl.startswith(('EPON', 'Interface')):
                            break
                        if not re.match(r'^(EPON|Interface)', nl, re.I):
                            full += "  " + nl
                        else:
                            break
                    parts = full.split()
                    if len(parts) < 4:
                        continue
                    iface = parts[0]

                    vendor = parts[1] if parts[1] not in ('----', 'N/A') else 'N/A'

                    model_raw = parts[2] if len(parts) > 2 else 'N/A'
                    model = model_raw if model_raw not in ('0x00000000', 'N/A') else 'N/A'
                    mac = 'N/A'
                    desc = 'N/A'
                    if vendor != 'N/A':
                        mac = parts[3] if len(parts) > 3 else 'N/A'
                        if len(parts) > 4:
                            desc = self._extract_description_3310(parts[4:])
                    else:

                        for j in range(2, len(parts)):
                            if re.match(r'^[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}$', parts[j]):
                                mac = parts[j]
                                if j > 2 and model == 'N/A' and not re.match(r'^0x[0-9a-fA-F]+$', parts[j - 1]):
                                    model = parts[j - 1]
                                desc = self._extract_description_3310(parts[j + 1:])
                                break
                    if not desc or desc == iface:
                        desc = 'N/A'
                    optical_p = optical.get(iface.lower())
                    status, reason = 'active', 'N/A'
                    if iface in inactive:
                        status = inactive[iface].get('status', 'off-line')
                        reason = inactive[iface].get('dereg_reason', 'Unknown')
                    else:
                        low = full.lower()
                        if any(w in low for w in ['lost', 'deregistered']):
                            status = 'off-line'
                            if 'power-off' in low:
                                reason = 'power-off'
                            elif 'wire-down' in low:
                                reason = 'wire-down'
                            elif 'llid-admin-down' in low:
                                reason = 'llid-admin-down'
                            elif 'unknow' in low:
                                reason = 'unknown'
                            else:
                                reason = 'unknown'
                        elif status == 'active' and optical_p is None:
                            status, reason = 'off-line', 'No Optical Power'
                    onus.append({
'interface': iface,
'vendor': vendor,
'model': model,
'mac': mac,
'description': desc,
'bind_type': 'static',
'status': status,
'dereg_reason': reason,
'optical_power': optical_p,
'client_macs': mac_data.get(iface, []),
})
                except Exception as e:
                    logger.error(f"Parse 3310 line error: {e}", exc_info=True)
        return self._sort_onus(onus)

    def _extract_description_3310(self, parts: List[str]) -> str:
        if not parts:
            return 'N/A'
        bind_keywords = {'static', 'lost', 'deregistered', 'auto-configured', 'dynamic'}
        mac_pattern = re.compile(r'^[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}$')
        desc_parts = []
        for part in parts:
            if part.lower() in bind_keywords:
                break
            if mac_pattern.match(part):
                break
            desc_parts.append(part)
        desc = ' '.join(desc_parts).strip()
        return desc if desc else 'N/A'

    def _sort_onus(self, onus):
        def key(o):
            try:
                if ':' in o['interface']:
                    main, num = o['interface'].split(':', 1)
                    main = main.replace('GPON', '').replace('EPON', '')
                    if '/' in main:
                        s, p = main.split('/')
                        return (int(s), int(p), int(num))
            except (ValueError, IndexError):
                pass
            return (999, 999, 999)
        return sorted(onus, key=key)
