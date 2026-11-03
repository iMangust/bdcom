"""Смоук-тесты для BDCOMSSHClient.delete_onu (без реального SSH).

Запуск:  python test_delete_onu.py   (или pytest test_delete_onu.py)

Покрывает регрессию из лога:
    Error deleting ONU GPON0/13:68: not enough values to unpack (expected 4, got 0)
и последующие улучшения: проверка ответа OLT, защита от инъекций.
"""
import sys
import types

# Мок netmiko до импорта ssh_client (в тестовой среде он может отсутствовать)
try:
    import netmiko  # noqa: F401
    HAVE_NETMIKO = True
except ImportError:
    HAVE_NETMIKO = False
if not HAVE_NETMIKO:
    netmiko = types.ModuleType('netmiko')
    exceptions = types.ModuleType('netmiko.exceptions')

    class _FakeConn:
        def __init__(self, *a, **k):
            pass
        def send_command_timing(self, cmd, **k):
            return f'fake-reply-to:{cmd}'
        def read_channel(self):
            return ''
        def disconnect(self):
            pass

    class _SSHConnect(_FakeConn):
        pass

    netmiko.SSHDevice = _FakeConn
    netmiko.ConnectHandler = _SSHConnect
    netmiko.ssh_exception = exceptions
    for _n in ('NetmikoTimeoutException', 'NetMikoTimeoutException'):
        setattr(exceptions, _n, TimeoutError)
    for _n in ('NetmikoAuthenticationException', 'NetMikoAuthenticationException'):
        setattr(exceptions, _n, PermissionError)
    sys.modules['netmiko'] = netmiko
    sys.modules['netmiko.exceptions'] = exceptions

from ssh_client import BDCOMSSHClient, INTERFACE_PARTS_RE, is_valid_interface


def make_client(reply_map=None, default_reply=''):
    """Клиент с заглушками connect/close/_send_config; собирает отправленные команды."""
    c = BDCOMSSHClient.__new__(BDCOMSSHClient)
    c.hostname = '10.0.0.1'
    sent = []

    def fake_send_config(command, wait=1.5):
        sent.append(command)
        if reply_map and command in reply_map:
            return reply_map[command]
        return default_reply

    c.connect = lambda: True
    c.close = lambda: None
    c._send_config = fake_send_config
    return c, sent


def test_gpon_ok():
    c, sent = make_client(default_reply='GPON-OLT(config-if-GPON0/13)# ')
    assert c.delete_onu('GPON0/13:68') is True
    assert sent == ['config', 'interface GPON0/13',
                    'no gpon bind-onu seq 68', 'exit', 'exit', 'write'], sent
    print('PASS test_gpon_ok (интерфейс из сообщения об ошибке в логе)')


def test_epon_ok():
    c, sent = make_client(default_reply='ok')
    assert c.delete_onu('EPON1/2:7') is True
    assert 'no epon bind-onu seq 7' in sent
    assert not any('gpon' in s for s in sent)
    print('PASS test_epon_ok')


def test_invalid_rejected_before_connect():
    c, sent = make_client()
    for bad in ('', None, 'bad name', 'GPON0/13:68\nconfig terminal',
               'GPON0/13:', 'ETH1/1', 'GPON999//1:2'):
        assert c.delete_onu(bad) is False, bad
    assert sent == [], f'команды не должны отправляться: {sent}'
    print('PASS test_invalid_rejected_before_connect (включая command injection)')


def test_olt_error_reply_returns_false():
    c, sent = make_client(reply_map={
        'no gpon bind-onu seq 68': "% Invalid input detected at '^' marker.",
    }, default_reply='ok')
    assert c.delete_onu('GPON0/13:68') is False
    assert 'write' not in sent, 'конфиг не должен сохраняться при отказе OLT'
    print('PASS test_olt_error_reply_returns_false')


def test_empty_reply_returns_false():
    c, sent = make_client(default_reply='')
    assert c.delete_onu('GPON0/13:68') is False
    assert 'write' not in sent
    print('PASS test_empty_reply_returns_false')


def test_whitespace_tolerated():
    c, sent = make_client(default_reply='ok')
    assert c.delete_onu('  GPON0/13:68  ') is True
    assert 'interface GPON0/13' in sent
    print('PASS test_whitespace_tolerated')


def test_parts_regex_groups():
    m = INTERFACE_PARTS_RE.fullmatch('GPON0/13:68')
    assert m and m.groups() == ('GPON', '0', '13', '68')
    # старый валидатор по-прежнему строго запрещает \n (fullmatch + якоря)
    assert not is_valid_interface('GPON0/13:68\nconfig terminal')
    print('PASS test_parts_regex_groups / INTERFACE_RE intact')


if __name__ == '__main__':
    test_gpon_ok()
    test_epon_ok()
    test_invalid_rejected_before_connect()
    test_olt_error_reply_returns_false()
    test_empty_reply_returns_false()
    test_whitespace_tolerated()
    test_parts_regex_groups()
    print('\nВсе тесты пройдены ✅')
