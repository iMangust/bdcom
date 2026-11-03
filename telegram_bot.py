import re
import time
import logging
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List
from sqlalchemy.orm import Session
from config import TELEGRAM_CONFIG, DEVICES, UPDATE_CONFIG
from database import (
init_db, ONU, DeviceStatus,
TelegramNotification, is_mcd
)


logger = logging.getLogger('TelegramBot')


class TelegramMonitorBot:

    # Ограничения повторной отправки при flood-control (429 / "retry after"):
    # не более MAX_SEND_ATTEMPTS повторов, каждая пауза — не дольше
    # MAX_RETRY_WAIT секунд (раньше рекурсия была безусловной и с неограниченной
    # паузой: поток мог зависнуть навсегда).
    MAX_SEND_ATTEMPTS = 3
    MAX_RETRY_WAIT = 60

    def __init__(self):
        self.bot_token = TELEGRAM_CONFIG['bot_token']
        self.chat_id = TELEGRAM_CONFIG['chat_id']
        self.critical_chat_id = TELEGRAM_CONFIG.get('critical_chat_id', '')
        self.notify_mcd_separately = TELEGRAM_CONFIG.get('notify_mcd_separately', True)
        self.mcd_always_notify = TELEGRAM_CONFIG.get('mcd_always_notify', True)
        self.mcd_marker = TELEGRAM_CONFIG.get('mcd_marker', '+')
        self.enabled = TELEGRAM_CONFIG['enabled']
        self.monitoring_enabled = TELEGRAM_CONFIG['monitoring_enabled']
        self.notify_on_offline = TELEGRAM_CONFIG['notify_on_offline']
        self.notify_on_recovery = TELEGRAM_CONFIG['notify_on_recovery']

        self.critical_statuses = set()
        self.recovery_statuses = set()

        if 'critical_statuses' in TELEGRAM_CONFIG:
            for status in TELEGRAM_CONFIG['critical_statuses']:
                self.critical_statuses.add(status.lower().strip())

        if 'recovery_statuses' in TELEGRAM_CONFIG:
            for status in TELEGRAM_CONFIG['recovery_statuses']:
                self.recovery_statuses.add(status.lower().strip())

        additional_recovery = {'up', 'operational', 'working', 'normal'}
        self.recovery_statuses.update(additional_recovery)


        self.check_interval = TELEGRAM_CONFIG['check_interval']
        self.background_update_interval = UPDATE_CONFIG.get('background_update_interval', 300)

        if self.check_interval < self.background_update_interval:
            logger.warning(
f"⚠️ check_interval ({self.check_interval}s) < background_update_interval "
f"({self.background_update_interval}s). Adjusting check_interval to match."
)
            self.check_interval = self.background_update_interval

        self.notification_session = None
        self._init_notification_tables()

        self.monitoring_thread = None
        self.running = False
        self.last_check_time = None
        self.last_onu_statuses = {}
        self.bot_initialized = False

        self.session = requests.Session()
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.last_send_time = None
        self.send_delay = 2.0
        self.batch_delay = 5

        logger.info(f"Telegram Bot initialized. Enabled: {self.enabled}, Monitoring: {self.monitoring_enabled}")
        logger.info(f"Critical statuses to notify: {self.critical_statuses}")
        logger.info(f"Recovery statuses: {self.recovery_statuses}")
        logger.info(f"Check interval: {self.check_interval}s (synced with background_update_interval)")
        logger.info(f"🏢 MCD support: critical_chat_id={'SET' if self.critical_chat_id else 'NOT SET'}, "
f"notify_mcd_separately={self.notify_mcd_separately}, mcd_always_notify={self.mcd_always_notify}")

    def check_all_onus_on_startup(self, db_session: Session) -> List[Dict]:
        logger.info("Performing initial check of all ONUs...")
        try:
            current_onus = db_session.query(ONU).filter(ONU.is_active.is_(True)).all()
            problems = []

            for onu in current_onus:
                try:
                    current_status = onu.status if onu.status else ''
                    current_dereg_reason = onu.dereg_reason if onu.dereg_reason else ''

                    if self._should_notify_status(current_status, current_dereg_reason, 'failure'):
                        onu_number = self._extract_onu_number(onu.interface)
                        already_sent = self._is_notification_sent(
onu.device_id, onu.interface, onu_number,
'failure', f"{current_status}:{current_dereg_reason}"
)

                        if not already_sent:
                            problem_data = {
'device_id': onu.device_id,
'device_name': onu.device_name,
'interface': onu.interface,
'onu_number': onu_number,
'mac': onu.mac,
'description': onu.description if onu.description and onu.description != 'N/A' else 'N/A',
'old_status': '',
'new_status': current_status,
'old_dereg_reason': '',
'dereg_reason': current_dereg_reason,
'optical_power': onu.optical_power,
'event_type': 'failure',
'timestamp': datetime.now(),
'is_mcd': is_mcd(onu.description),
}
                            problems.append(problem_data)
                            logger.info(f"Found existing problem ONU: {onu.device_name}:{onu.interface} - "
f"{current_status} - {current_dereg_reason} "
f"{'[МКД]' if is_mcd(onu.description) else ''}")
                except Exception as e:
                    logger.error(f"Error processing ONU {onu.device_id}:{onu.interface} in startup check: {e}", exc_info=True)
                    continue

            logger.info(f"Initial check completed. Found {len(problems)} problematic ONUs to notify.")
            return problems
        except Exception as e:
            logger.error(f"Error in startup ONU check: {e}", exc_info=True)
            return []

    def _init_notification_tables(self):
        try:
            # Единый engine/session-factory из database.py (см. init_db):
            # раньше здесь создавался отдельный create_engine с f-string URL —
            # второй пул соединений + поломка при спецсимволах в пароле и
            # полная неработоспособность на DB_TYPE=sqlite.
            session_factory = init_db()
            self.notification_session = session_factory
            logger.info("Telegram notifications tables initialized via shared DB pool")
        except Exception as e:
            logger.error(f"Error initializing notification tables: {e}", exc_info=True)
            self.notification_session = None

    def _get_notification_session(self):
        if not self.notification_session:
            self._init_notification_tables()
        return self.notification_session()

    def _get_message_hash(self, device_id: str, interface: str, onu_number: int,
status_type: str, status_text: str) -> str:
        content = f"{device_id}:{interface}:{onu_number}:{status_type}:{status_text}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _is_notification_sent(self, device_id: str, interface: str,
onu_number: int, status_type: str, status_text: str) -> bool:
        session = self._get_notification_session()
        if not session:
            return False
        try:
            message_hash = self._get_message_hash(device_id, interface, onu_number, status_type, status_text)
            count = session.query(TelegramNotification).filter(
TelegramNotification.message_hash == message_hash,
TelegramNotification.is_active.is_(True)
).count()
            return count > 0
        except Exception as e:
            logger.error(f"Error checking notification: {e}", exc_info=True)
            return False
        finally:
            session.close()

    def _save_notification(self, device_id: str, interface: str, onu_number: int,
status_type: str, status_text: str, description: str | None = None):
        session = self._get_notification_session()
        if not session:
            return
        try:
            message_hash = self._get_message_hash(device_id, interface, onu_number, status_type, status_text)

            old_notifications = session.query(TelegramNotification).filter(
TelegramNotification.device_id == device_id,
TelegramNotification.interface == interface,
TelegramNotification.onu_number == onu_number,
TelegramNotification.status_type == status_type,
TelegramNotification.is_active.is_(True)
).all()

            for notification in old_notifications:
                notification.is_active = False

            new_notification = TelegramNotification(
device_id=device_id,
interface=interface,
onu_number=onu_number,
status_type=status_type,
message_hash=message_hash,
status_text=status_text,
description=description,
sent_at=datetime.now(),
is_active=True
)
            session.add(new_notification)
            session.commit()
            logger.debug(f"Saved notification for {device_id}:{interface}:{onu_number} ({status_type})")
        except Exception as e:
            logger.error(f"Error saving notification: {e}", exc_info=True)
            session.rollback()
        finally:
            session.close()

    def _deactivate_notification(self, device_id: str, interface: str,
onu_number: int, status_type: str):
        session = self._get_notification_session()
        if not session:
            return
        try:
            notifications = session.query(TelegramNotification).filter(
TelegramNotification.device_id == device_id,
TelegramNotification.interface == interface,
TelegramNotification.onu_number == onu_number,
TelegramNotification.status_type == status_type,
TelegramNotification.is_active.is_(True)
).all()

            updated = 0
            for notification in notifications:
                notification.is_active = False
                updated += 1

            session.commit()
            if updated > 0:
                logger.debug(f"Deactivated {status_type} notification for {device_id}:{interface}:{onu_number}")
        except Exception as e:
            logger.error(f"Error deactivating notification: {e}", exc_info=True)
            session.rollback()
        finally:
            session.close()

    def _cleanup_old_notifications(self):
        session = self._get_notification_session()
        if not session:
            return
        try:
            cutoff_date = datetime.now() - timedelta(days=7)
            deleted_count = session.query(TelegramNotification).filter(
TelegramNotification.sent_at < cutoff_date
).delete(synchronize_session=False)
            session.commit()
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old notification records")
        except Exception as e:
            logger.error(f"Error cleaning up old notifications: {e}", exc_info=True)
            session.rollback()
        finally:
            session.close()

    def initialize_bot(self) -> bool:
        if not self.enabled or not self.bot_token:
            logger.warning("Telegram bot disabled or token not configured")
            return False

        try:
            response = self.session.get(f"{self.base_url}/getMe", timeout=10)
            if response.status_code == 200:
                info = response.json()
                if info.get('ok'):
                    bot_info = info['result']
                    logger.info(f"Telegram Bot connected: @{bot_info['username']} ({bot_info['first_name']})")

                    self._cleanup_old_notifications()

                    critical_chat_info = ""
                    if self.critical_chat_id:
                        critical_chat_info = f"\n🚨 <b>Критический чат (МКД):</b> <code>{self.critical_chat_id}</code>"

                    start_message = f"""
🤖 <b>EPON Monitor Telegram Bot</b>

✅ <b>Мониторинг запущен</b>
🕐 Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
📊 Отслеживание ВСЕХ статусов ONU: ВКЛ
🔔 Уведомления только для: {', '.join(TELEGRAM_CONFIG.get('critical_statuses', []))}
🏢 <b>МКД-ONU:</b> {'🟢 ВКЛ' if self.notify_mcd_separately else '⚪ ВЫКЛ'}
🔄 Проверка каждые: {self.check_interval} сек
📡 Устройств в мониторинге: {len(DEVICES)}{critical_chat_info}
"""
                    success = self.send_message(start_message)
                    if success:
                        logger.info("Startup message sent successfully")
                        self.bot_initialized = True
                        return True
                    else:
                        logger.error("Failed to send startup message")
                        return False
                else:
                    logger.error(f"Telegram API error: {info.get('description')}")
                    return False
            else:
                logger.error(f"Failed to connect to Telegram API: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to initialize Telegram bot: {e}", exc_info=True)
            return False

    def _send_to_chat(self, chat_id: str, message: str, parse_mode: str = 'HTML',
disable_notification: bool = False, _attempt: int = 0) -> bool:
        """Отправка сообщения с ограниченным числом повторов при flood-control.

        Раньше рекурсия была безусловной: Telegram, стабильно отвечающий 429,
        зацикливал поток навсегда. MAX_SEND_ATTEMPTS ограничивает глубину.
        """
        if not chat_id:
            logger.warning("Chat ID is empty, message not sent")
            return False

        if self.last_send_time:
            elapsed = time.time() - self.last_send_time
            if elapsed < self.send_delay:
                time.sleep(self.send_delay - elapsed)

        try:
            if len(message) > 4096:
                message = message[:4000] + "\n...[Сообщение обрезано]"

            params = {
'chat_id': chat_id,
'text': message,
'parse_mode': parse_mode,
'disable_notification': disable_notification
}

            logger.debug(f"Sending Telegram message to chat {chat_id}")
            response = self.session.post(
f"{self.base_url}/sendMessage",
json=params,
timeout=30
)
            self.last_send_time = time.time()

            if response.status_code == 200:
                result = response.json()
                if result.get('ok'):
                    logger.debug(f"Telegram message sent successfully to chat {chat_id}")
                    return True
                else:
                    error_msg = result.get('description', 'Unknown error')
                    if "Too Many Requests" in error_msg or "retry after" in error_msg.lower():
                        if _attempt >= self.MAX_SEND_ATTEMPTS:
                            logger.error(
                                f"Flood control: max attempts ({self.MAX_SEND_ATTEMPTS}) "
                                f"exceeded for chat {chat_id}, giving up")
                            return False
                        retry_match = re.search(r'retry after (\d+)', error_msg.lower())
                        retry_after = min(int(retry_match.group(1)) if retry_match else 30,
                                          self.MAX_RETRY_WAIT)
                        logger.warning(f"Flood control: waiting {retry_after} seconds "
                                       f"(attempt {_attempt + 1}/{self.MAX_SEND_ATTEMPTS})")
                        time.sleep(retry_after + 1)
                        return self._send_to_chat(chat_id, message, parse_mode,
                                                  disable_notification, _attempt + 1)
                    logger.error(f"Telegram API error (chat {chat_id}): {error_msg}")
                    return False
            elif response.status_code == 429:
                if _attempt >= self.MAX_SEND_ATTEMPTS:
                    logger.error(
                        f"Flood control: max attempts ({self.MAX_SEND_ATTEMPTS}) "
                        f"exceeded for chat {chat_id}, giving up")
                    return False
                try:
                    retry_after = min(int(response.headers.get('Retry-After', 30)),
                                      self.MAX_RETRY_WAIT)
                except (TypeError, ValueError):
                    retry_after = 30
                logger.warning(f"Flood control exceeded. Retry in {retry_after} seconds "
                               f"(attempt {_attempt + 1}/{self.MAX_SEND_ATTEMPTS})")
                time.sleep(retry_after + 1)
                return self._send_to_chat(chat_id, message, parse_mode,
                                          disable_notification, _attempt + 1)
            else:
                logger.error(f"HTTP error {response.status_code} (chat {chat_id}): {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to send Telegram message to chat {chat_id}: {e}", exc_info=True)
            return False

    def send_message(self, message: str, parse_mode: str = 'HTML',
disable_notification: bool = False) -> bool:
        if not self.enabled or not self.bot_token or not self.chat_id:
            logger.warning("Telegram bot not configured or disabled")
            return False
        return self._send_to_chat(self.chat_id, message, parse_mode, disable_notification)

    def send_to_critical_chat(self, message: str, parse_mode: str = 'HTML',
disable_notification: bool = False) -> bool:
        if not self.critical_chat_id:
            logger.debug("Critical chat ID not configured, skipping")
            return False
        return self._send_to_chat(self.critical_chat_id, message, parse_mode, disable_notification)

    def format_onu_message(self, onu_data: Dict, event_type: str) -> str:
        try:
            device_name = onu_data.get('device_name', 'Unknown')
            interface = onu_data.get('interface', 'Unknown')
            mac = onu_data.get('mac', 'N/A')
            description = onu_data.get('description', 'N/A')
            old_status = onu_data.get('old_status', 'N/A')
            new_status = onu_data.get('new_status', 'N/A')
            dereg_reason = onu_data.get('dereg_reason', 'N/A')
            optical_power = onu_data.get('optical_power')
            is_mcd_flag = onu_data.get('is_mcd', False)

            if is_mcd_flag:
                if event_type == 'failure':
                    emoji = "🏢🔴"
                    title = "🚨🚨🚨 КРИТИЧЕСКИЙ ОБРЫВ — МКД 🚨🚨🚨"
                elif event_type == 'recovery':
                    emoji = "🏢🟢"
                    title = "✅ ВОССТАНОВЛЕНИЕ — МКД"
                else:
                    emoji = "🏢ℹ️"
                    title = "ИНФОРМАЦИЯ — МКД"
            else:
                if event_type == 'failure':
                    emoji = "🔴"
                    title = "🚨 ОБРЫВ ОПТИКИ / ПРОБЛЕМА С ONU"
                elif event_type == 'recovery':
                    emoji = "🟢"
                    title = "✅ ВОССТАНОВЛЕНИЕ ONU"
                else:
                    emoji = "ℹ️"
                    title = "ИНФОРМАЦИЯ ОБ ONU"

            optical_info = ""
            if optical_power is not None:
                if optical_power > -25:
                    signal_emoji = "🟢"
                    signal_status = "ХОРОШИЙ"
                elif optical_power >= -27:
                    signal_emoji = "🟡"
                    signal_status = "ПРЕДУПРЕЖДЕНИЕ"
                else:
                    signal_emoji = "🔴"
                    signal_status = "ПЛОХОЙ"
                optical_info = f"\n📶 Оптический сигнал: {signal_emoji} {optical_power} dBm ({signal_status})"
            else:
                optical_info = "\n📶 Оптический сигнал: ❓ НЕТ ДАННЫХ"

            device_id = onu_data.get('device_id', '')
            device_ip = ""
            if device_id and device_id in DEVICES:
                device_ip = DEVICES[device_id].get('hostname', '')
                optical_info += f"\n🌐 IP устройства: http://{device_ip}"

            mcd_badge = ""
            if is_mcd_flag:
                mcd_badge = "\n🏢 <b>ТИП:</b> <b>МКД (Многоквартирный дом)</b>"

            message = f"""
{emoji} <b>{title}</b>

📡 <b>Устройство:</b> {device_name}
🔌 <b>Порт:</b> {interface}
📝 <b>Описание:</b> {description}{mcd_badge}
📟 <b>MAC:</b> <code>{mac}</code>

🔄 <b>Изменение статуса:</b>
<b>Было:</b> {old_status}
<b>Стало:</b> {new_status}

📊 <b>Причина:</b> {dereg_reason}{optical_info}

⏰ <b>Время:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
"""
            return message.strip()
        except Exception as e:
            logger.error(f"Error formatting ONU message: {e}", exc_info=True)
            return f"Ошибка форматирования сообщения об ONU: {str(e)}"

    def _extract_onu_number(self, interface: str) -> int:
        try:
            match = re.search(r':(\d+)$', interface)
            if match:
                return int(match.group(1))
            match = re.search(r'(\d+)$', interface)
            if match:
                return int(match.group(1))
            return 0
        except Exception:
            logger.debug("Не удалось извлечь номер ONU из интерфейса %r", interface, exc_info=True)
            return 0

    def _should_notify_status(self, status: str, dereg_reason: str, event_type: str) -> bool:
        if not status and not dereg_reason:
            return False

        status_lower = status.lower() if status else ''
        reason_lower = dereg_reason.lower() if dereg_reason else ''

        # Отладочную строку пишем только для ONU, которые реально могут дать
        # уведомление (off-line и т.п.). Раньше logger.debug вызывался для
        # каждой ONU на каждом цикле проверки — при LOG_LEVEL=DEBUG в app.log
        # летел поток из сотен одинаковых "Checking if should notify:
        # status='active'..." за миллисекунды.
        may_notify = (
            'off-line' in status_lower or 'offline' in status_lower or 'down' in status_lower
            or any(c in status_lower or c in reason_lower for c in self.critical_statuses)
        )
        if may_notify:
            logger.debug(f"Checking if should notify: status='{status_lower}', reason='{reason_lower}', type={event_type}")

        if event_type == 'failure':
            if 'off-line' in status_lower or 'offline' in status_lower or 'down' in status_lower:
                for critical_status in self.critical_statuses:
                    if critical_status in reason_lower:
                        logger.info(f"Will notify: off-line with critical reason '{reason_lower}' matches '{critical_status}'")
                        return True
                logger.debug(f"Will NOT notify: off-line with non-critical reason '{reason_lower}'")
                return False

            for critical_status in self.critical_statuses:
                if critical_status in status_lower or critical_status in reason_lower:
                    logger.info(f"Will notify: status/reason '{status_lower}'/'{reason_lower}' matches '{critical_status}'")
                    return True
            return False

        elif event_type == 'recovery':
            for recovery_status in self.recovery_statuses:
                if recovery_status in status_lower:
                    logger.info(f"Will notify recovery: status '{status_lower}' matches '{recovery_status}'")
                    return True
            return False

        return False

    def _is_recovery_status(self, status: str, dereg_reason: str) -> bool:
        if not status:
            return False
        status_lower = status.lower() if status else ''
        return any(recovery in status_lower for recovery in self.recovery_statuses)

    def _is_data_fresh(self, db_session: Session) -> bool:
        try:
            cutoff_time = datetime.now() - timedelta(seconds=self.check_interval * 2)
            fresh_devices = db_session.query(DeviceStatus).filter(
DeviceStatus.is_online.is_(True),
DeviceStatus.last_successful_update >= cutoff_time
).count()

            if fresh_devices == 0:
                logger.warning(
f"⚠️ No fresh device data found. Last update older than {self.check_interval * 2}s. "
f"Skipping ONU status check to avoid false notifications."
)
                return False

            logger.debug(f"Found {fresh_devices} devices with fresh data")
            return True
        except Exception as e:
            logger.error(f"Error checking data freshness: {e}", exc_info=True)
            return False

    def check_onu_status_changes(self, db_session: Session) -> List[Dict]:
        try:

            if not self._is_data_fresh(db_session):
                return []

            if not self.last_onu_statuses:
                logger.info("Initializing ONU status cache...")
                self._initialize_status_cache(db_session)
                return []

            logger.debug(f"Checking ONU status changes. Cache size: {len(self.last_onu_statuses)}")

            current_onus = db_session.query(ONU).filter(ONU.is_active.is_(True)).all()
            changes = []
            total_checked = 0

            for onu in current_onus:
                try:
                    total_checked += 1
                    key = (onu.device_id, onu.interface)
                    current_status = onu.status if onu.status else ''
                    current_dereg_reason = onu.dereg_reason if onu.dereg_reason else ''


                    onu_is_mcd = is_mcd(onu.description)

                    previous_data = self.last_onu_statuses.get(key, {})
                    previous_status = previous_data.get('status', '')
                    previous_dereg_reason = previous_data.get('dereg_reason', '')

                    status_changed = previous_status != current_status
                    dereg_reason_changed = previous_dereg_reason != current_dereg_reason

                    if status_changed or dereg_reason_changed:
                        logger.info(f"ONU {onu.device_name}:{onu.interface} changed: "
f"status '{previous_status}'->'{current_status}', "
f"reason '{previous_dereg_reason}'->'{current_dereg_reason}' "
f"{'[МКД]' if onu_is_mcd else ''}")

                        event_type = None
                        should_notify_failure = self._should_notify_status(current_status, current_dereg_reason, 'failure')
                        should_notify_recovery = self._should_notify_status(current_status, current_dereg_reason, 'recovery')
                        previous_was_critical = self._should_notify_status(previous_status, previous_dereg_reason, 'failure')


                        if onu_is_mcd and self.mcd_always_notify and 'off-line' in current_status.lower():
                            should_notify_failure = True
                            logger.info(f"🏢 MCD-ONU forced notification: {onu.device_name}:{onu.interface}")

                        logger.debug(f"Notification checks: failure={should_notify_failure}, recovery={should_notify_recovery}, prev_critical={previous_was_critical}")

                        if should_notify_failure:
                            event_type = 'failure'
                        elif previous_was_critical and should_notify_recovery:
                            event_type = 'recovery'

                        if event_type:
                            onu_number = self._extract_onu_number(onu.interface)
                            already_sent = self._is_notification_sent(
onu.device_id, onu.interface, onu_number,
event_type, f"{current_status}:{current_dereg_reason}"
)

                            if not already_sent:
                                change_data = {
'device_id': onu.device_id,
'device_name': onu.device_name,
'interface': onu.interface,
'onu_number': onu_number,
'mac': onu.mac,
'description': onu.description if onu.description and onu.description != 'N/A' else 'N/A',
'old_status': previous_status,
'new_status': current_status,
'old_dereg_reason': previous_dereg_reason,
'dereg_reason': current_dereg_reason,
'optical_power': onu.optical_power,
'event_type': event_type,
'timestamp': datetime.now(),
'is_mcd': onu_is_mcd,
}
                                changes.append(change_data)
                                logger.info(f"Will send {event_type} notification for {onu.device_name}:{onu.interface} "
f"{'[МКД]' if onu_is_mcd else ''}")

                                if event_type == 'recovery':
                                    self._deactivate_notification(
onu.device_id, onu.interface, onu_number, 'failure'
)


                    self.last_onu_statuses[key] = {
'status': current_status,
'dereg_reason': current_dereg_reason,
'timestamp': datetime.now(),
'optical_power': onu.optical_power,
'is_mcd': onu_is_mcd,
}
                except Exception as e:
                    logger.error(f"Error processing ONU {onu.device_id}:{onu.interface}: {e}", exc_info=True)
                    continue

            logger.info(f"Checked {total_checked} ONUs. Found {len(changes)} changes to notify.")
            return changes
        except Exception as e:
            logger.error(f"Error checking ONU status changes: {e}", exc_info=True)
            return []

    def check_and_notify(self):
        if not self.monitoring_enabled or not self.running:
            return

        try:
            db_session = init_db()
            session = db_session()
            try:
                changes = self.check_onu_status_changes(session)
                if not changes:
                    logger.debug("No ONU status changes to notify")
                    return

                changes.sort(key=lambda x: (0 if x.get('is_mcd') else 1, 0 if x['event_type'] == 'failure' else 1))

                failures = len([c for c in changes if c['event_type'] == 'failure'])
                recoveries = len([c for c in changes if c['event_type'] == 'recovery'])
                mcd_count = len([c for c in changes if c.get('is_mcd')])

                logger.info(f"Processing {len(changes)} notifications: {failures} failures, {recoveries} recoveries, {mcd_count} MCD")

                sent_count = 0
                skipped_count = 0
                mcd_critical_sent = 0

                for i, change in enumerate(changes):
                    try:
                        event_type = change['event_type']
                        onu_is_mcd = change.get('is_mcd', False)

                        if onu_is_mcd and event_type == 'failure' and self.mcd_always_notify:
                            should_notify = True
                        else:
                            should_notify = (
(event_type == 'failure' and self.notify_on_offline) or
(event_type == 'recovery' and self.notify_on_recovery)
)

                        if not should_notify:
                            skipped_count += 1
                            continue

                        message = self.format_onu_message(change, event_type)
                        disable_notification = (event_type != 'failure')

                        if self.send_message(message, disable_notification=disable_notification):
                            self._save_notification(
change['device_id'],
change['interface'],
change['onu_number'],
event_type,
f"{change['new_status']}:{change['dereg_reason']}",
change['description']
)
                            sent_count += 1
                            logger.info(f"✅ Sent {event_type} notification for {change['device_name']}:{change['interface']} "
f"{'[МКД]' if onu_is_mcd else ''}")

                            if (onu_is_mcd and event_type == 'failure' and
self.notify_mcd_separately and self.critical_chat_id):
                                critical_message = (
f"🚨🚨🚨 <b>КРИТИЧЕСКОЕ УВЕДОМЛЕНИЕ — МКД</b> 🚨🚨🚨\n"
f"<i>Дублирование из основного чата</i>\n"
f"{message}"
)
                                if self.send_to_critical_chat(critical_message, disable_notification=False):
                                    mcd_critical_sent += 1
                                    logger.info(f"🏢🚨 MCD notification duplicated to critical chat for "
f"{change['device_name']}:{change['interface']}")
                                else:
                                    logger.warning("❌ Failed to duplicate MCD notification to critical chat")
                        else:
                            logger.error(f"❌ Failed to send {event_type} notification for {change['device_name']}:{change['interface']}")

                        if sent_count % 3 == 0 and i < len(changes) - 1:
                            logger.debug(f"Batch of 3 messages sent, waiting {self.batch_delay} seconds")
                            time.sleep(self.batch_delay)

                        time.sleep(0.5)
                    except Exception as e:
                        logger.error(f"Error processing change {i}: {e}", exc_info=True)
                        continue

                if sent_count > 0:
                    logger.info(f"✅ Successfully sent {sent_count} notifications "
f"{f', {mcd_critical_sent} duplicated to critical chat (MCD)' if mcd_critical_sent > 0 else ''}")

                if skipped_count > 0:
                    logger.debug(f"Skipped {skipped_count} notifications (disabled in settings)")
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Error in check_and_notify: {e}", exc_info=True)

    def start_monitoring(self):
        if not self.monitoring_enabled or self.running:
            return

        self.running = True

        def monitoring_loop():
            logger.info("Starting Telegram monitoring loop")

            if not self.bot_initialized:
                logger.warning("Bot not initialized yet, trying to initialize now...")
                if not self.initialize_bot():
                    logger.error("Failed to initialize Telegram bot, monitoring disabled")
                    self.running = False
                    return

            try:
                db_session = init_db()
                session = db_session()

                startup_problems = self.check_all_onus_on_startup(session)
                if startup_problems:
                    logger.info(f"Sending notifications for {len(startup_problems)} problematic ONUs found on startup")

                    mcd_problems = [p for p in startup_problems if p.get('is_mcd')]

                    summary_message = f"""
📋 <b>НАЧАЛЬНАЯ ПРОВЕРКА EPON MONITOR</b>

🔍 Проверено всех ONU при запуске
🚨 <b>Найдено проблемных ONU для уведомления:</b> {len(startup_problems)}
🏢 <b>Из них МКД:</b> {len(mcd_problems)}

<b>Отслеживаемые статусы:</b> {', '.join(TELEGRAM_CONFIG.get('critical_statuses', []))}
"""
                    for i, problem in enumerate(startup_problems[:10], 1):
                        mcd_mark = " 🏢" if problem.get('is_mcd') else ""
                        summary_message += f"{i}. {problem['device_name']}:{problem['interface']} - {problem['new_status']} - {problem['dereg_reason']}{mcd_mark}\n"

                    if len(startup_problems) > 10:
                        summary_message += f"... и еще {len(startup_problems) - 10}\n"

                    summary_message += f"\n⏰ Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"

                    self.send_message(summary_message)

                    if mcd_problems and self.notify_mcd_separately and self.critical_chat_id:
                        critical_summary = (
f"🚨🚨🚨 <b>КРИТИЧЕСКИЕ МКД-ONU ПРИ ЗАПУСКЕ</b> 🚨🚨🚨\n"
f"🏢 Найдено <b>{len(mcd_problems)}</b> проблемных МКД-ONU:\n"
)
                        for i, problem in enumerate(mcd_problems, 1):
                            critical_summary += (
f"{i}. <b>{problem['device_name']}</b>:{problem['interface']}\n"
f"   Статус: {problem['new_status']} | Причина: {problem['dereg_reason']}\n"
)
                        critical_summary += f"\n⏰ {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
                        self.send_to_critical_chat(critical_summary, disable_notification=False)

                    for problem in startup_problems:
                        message = self.format_onu_message(problem, 'failure')
                        if self.send_message(message):
                            self._save_notification(
problem['device_id'],
problem['interface'],
problem['onu_number'],
'failure',
f"{problem['new_status']}:{problem['dereg_reason']}",
problem['description']
)

                            if (problem.get('is_mcd') and self.notify_mcd_separately
and self.critical_chat_id):
                                critical_message = (
f"🚨🚨🚨 <b>КРИТИЧЕСКОЕ УВЕДОМЛЕНИЕ — МКД</b> 🚨🚨🚨\n"
f"{message}"
)
                                self.send_to_critical_chat(critical_message, disable_notification=False)

                        time.sleep(self.send_delay)

                session.close()
            except Exception as e:
                logger.error(f"Error in startup check: {e}", exc_info=True)
                time.sleep(5)

            iteration = 0
            while self.running:
                try:
                    iteration += 1
                    logger.debug(f"Monitoring iteration #{iteration}")

                    self.check_and_notify()

                    for _i in range(self.check_interval):
                        if not self.running:
                            break
                        time.sleep(1)
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                    time.sleep(60)

        self.monitoring_thread = threading.Thread(
target=monitoring_loop,
daemon=True,
name="TelegramMonitorThread"
)
        self.monitoring_thread.start()
        logger.info("Telegram monitoring started")

    def _initialize_status_cache(self, db_session: Session = None):
        try:
            if db_session is None:
                db_session = init_db()
                session = db_session()
                close_session = True
            else:
                session = db_session
                close_session = False

            try:
                current_onus = session.query(ONU).filter(ONU.is_active.is_(True)).all()
                cache_size = 0

                for onu in current_onus:
                    key = (onu.device_id, onu.interface)
                    self.last_onu_statuses[key] = {
'status': onu.status if onu.status else '',
'dereg_reason': onu.dereg_reason if onu.dereg_reason else '',
'timestamp': datetime.now(),
'optical_power': onu.optical_power,
'is_mcd': is_mcd(onu.description),
}
                    cache_size += 1

                logger.info(f"✅ Initialized status cache with {cache_size} ONUs")
            finally:
                if close_session:
                    session.close()
        except Exception as e:
            logger.error(f"Error initializing status cache: {e}", exc_info=True)

    def stop_monitoring(self):
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
            logger.info("Telegram monitoring thread stopped")

        if self.enabled and self.chat_id:
            stop_message = f"""
🛑 <b>EPON Monitor Telegram Bot</b>

⏹️ <b>Мониторинг остановлен</b>
🕐 Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
"""
            try:
                self.send_message(stop_message, disable_notification=True)
            except Exception:
                logger.warning("Не удалось отправить сообщение об остановке мониторинга", exc_info=True)

        if self.session:
            self.session.close()

        self.last_onu_statuses.clear()
        logger.info("Telegram monitoring stopped")

    def send_test_message(self):
        test_message = f"""
🧪 <b>Тестовое сообщение EPON Monitor</b>

✅ Telegram Bot работает нормально
🕐 Время: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

📡 Система мониторинга EPON
📊 Мониторинг: {'ВКЛ' if self.monitoring_enabled else 'ВЫКЛ'}
🔔 Уведомления: {'ВКЛ' if self.notify_on_offline else 'ВЫКЛ'}
🏢 МКД-уведомления: {'ВКЛ' if self.notify_mcd_separately else 'ВЫКЛ'}
🚨 Критический чат: {'<code>' + self.critical_chat_id + '</code>' if self.critical_chat_id else 'НЕ НАСТРОЕН'}

<b>Конфигурация уведомлений:</b>
🚨 Уведомления только для: {', '.join(TELEGRAM_CONFIG.get('critical_statuses', []))}
✅ Восстановление: {', '.join(TELEGRAM_CONFIG.get('recovery_statuses', []))}

<b>Все остальные статусы отслеживаются, но уведомления не отправляются!</b>

<code>Это тестовое сообщение для проверки связи.</code>
"""
        return self.send_message(test_message)

    def get_status(self) -> Dict:
        try:
            session = self._get_notification_session()
            if not session:
                return {
'enabled': self.enabled,
'monitoring_enabled': self.monitoring_enabled,
'running': self.running,
'last_check_time': self.last_check_time,
'tracking_onus': len(self.last_onu_statuses),
'active_notifications': 0,
'bot_initialized': self.bot_initialized,
'critical_chat_id': self.critical_chat_id,
'notify_mcd_separately': self.notify_mcd_separately,
'mcd_always_notify': self.mcd_always_notify,
'mcd_tracking': sum(1 for v in self.last_onu_statuses.values() if v.get('is_mcd')),
}

            try:
                active_notifications = session.query(TelegramNotification).filter(
TelegramNotification.is_active.is_(True)
).count()

                return {
'enabled': self.enabled,
'monitoring_enabled': self.monitoring_enabled,
'running': self.running,
'last_check_time': self.last_check_time,
'tracking_onus': len(self.last_onu_statuses),
'active_notifications': active_notifications,
'bot_initialized': self.bot_initialized,
'check_interval': self.check_interval,
'notify_on_offline': self.notify_on_offline,
'notify_on_recovery': self.notify_on_recovery,
'critical_statuses': list(self.critical_statuses),
'recovery_statuses': list(self.recovery_statuses),
'critical_chat_id': self.critical_chat_id,
'notify_mcd_separately': self.notify_mcd_separately,
'mcd_always_notify': self.mcd_always_notify,
'mcd_tracking': sum(1 for v in self.last_onu_statuses.values() if v.get('is_mcd')),
}
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Error getting bot status: {e}", exc_info=True)
            return {
'enabled': self.enabled,
'monitoring_enabled': self.monitoring_enabled,
'running': self.running,
'last_check_time': self.last_check_time,
'tracking_onus': len(self.last_onu_statuses),
'active_notifications': 0,
'bot_initialized': self.bot_initialized,
'critical_chat_id': self.critical_chat_id,
'notify_mcd_separately': self.notify_mcd_separately,
'mcd_always_notify': self.mcd_always_notify,
'mcd_tracking': 0,
}

    def test_notification(self, device_id: str = "1", interface: str = "EPON0/1:1",
is_mcd_test: bool = False):
        if not self.enabled:
            return False

        description = "+ Тестовый МКД дом" if is_mcd_test else 'Тестовая ONU'

        test_data = {
'device_id': device_id,
'device_name': 'Тестовое устройство',
'interface': interface,
'onu_number': 1,
'mac': 'AA:BB:CC:DD:EE:FF',
'description': description,
'old_status': 'active',
'new_status': 'off-line',
'old_dereg_reason': 'N/A',
'dereg_reason': 'wire-down',
'optical_power': -30.5,
'event_type': 'failure',
'timestamp': datetime.now(),
'is_mcd': is_mcd_test,
}

        message = self.format_onu_message(test_data, 'failure')
        result = self.send_message(message)

        if result and is_mcd_test and self.critical_chat_id and self.notify_mcd_separately:
            critical_message = (
f"🚨🚨🚨 <b>КРИТИЧЕСКОЕ УВЕДОМЛЕНИЕ — МКД</b> 🚨🚨🚨\n"
f"<i>Тестовое дублирование</i>\n"
f"{message}"
)
            self.send_to_critical_chat(critical_message, disable_notification=False)

        return result


telegram_bot = TelegramMonitorBot()

def _rebuild_status_sets():
    """Пересобирает множества статусов из TELEGRAM_CONFIG.

    Копирует логику __init__ (lower+strip + дополнительные recovery-статусы),
    чтобы hot-reload настроек через UI не требовал перезапуска приложения.
    """
    telegram_bot.critical_statuses = {
        s.lower().strip() for s in TELEGRAM_CONFIG.get('critical_statuses', []) if s.strip()
    }
    telegram_bot.recovery_statuses = {
        s.lower().strip() for s in TELEGRAM_CONFIG.get('recovery_statuses', []) if s.strip()
    }
    telegram_bot.recovery_statuses.update({'up', 'operational', 'working', 'normal'})


def apply_telegram_settings(config_updates: dict):
    """Применяет изменения TELEGRAM_CONFIG к живому экземпляру бота.

    Единая точка hot-reload: раньше app.py точечно присваивал отдельные
    атрибуты, из-за чего часть настроек (check_interval, списки статусов,
    mcd_marker) применялась только после рестарта. Мутация самого
    TELEGRAM_CONFIG остаётся ответственностью вызывающего (API-эндпоинта).
    """
    for key in ('bot_token', 'chat_id', 'critical_chat_id', 'enabled',
                'monitoring_enabled', 'notify_on_offline', 'notify_on_recovery',
                'notify_mcd_separately', 'mcd_always_notify', 'mcd_marker'):
        if key in config_updates:
            setattr(telegram_bot, key, config_updates[key])

    # base_url кэшируется — пересобираем при смене токена.
    telegram_bot.base_url = f"https://api.telegram.org/bot{telegram_bot.bot_token}"

    if 'critical_statuses' in config_updates or 'recovery_statuses' in config_updates:
        _rebuild_status_sets()

    if 'check_interval' in config_updates:
        interval = int(config_updates['check_interval'])
        background = UPDATE_CONFIG.get('background_update_interval', 300)
        if interval < background:
            logger.warning(
                "check_interval (%ss) < background_update_interval (%ss); adjusting",
                interval, background)
            interval = background
        telegram_bot.check_interval = interval


def initialize_telegram_bot():
    return telegram_bot.initialize_bot()

def start_telegram_monitoring():
    telegram_bot.start_monitoring()

def stop_telegram_monitoring():
    telegram_bot.stop_monitoring()

def send_telegram_message(message: str, parse_mode: str = 'HTML'):
    return telegram_bot.send_message(message, parse_mode)

def send_test_telegram_message():
    return telegram_bot.send_test_message()

def get_telegram_bot_status():
    return telegram_bot.get_status()

def cleanup_telegram_notifications():
    telegram_bot._cleanup_old_notifications()

def test_telegram_notification(device_id: str = "1", interface: str = "EPON0/1:1", is_mcd: bool = False):
    return telegram_bot.test_notification(device_id, interface, is_mcd)
