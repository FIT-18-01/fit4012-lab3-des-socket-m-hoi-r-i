import os
import subprocess
import sys
import time

from des_socket_utils import encrypt_des_cbc, decrypt_des_cbc, parse_header

cwd = os.path.dirname(os.path.abspath(__file__))
logs_dir = os.path.join(cwd, 'logs')
os.makedirs(logs_dir, exist_ok=True)

PYTHON_COMMON = {
    'PYTHONUNBUFFERED': '1',
    'PYTHONIOENCODING': 'utf-8',
}


def run_demo(session_name: str, message: str, sender_log: str, receiver_log: str, port: int = 6000) -> None:
    receiver_env = os.environ.copy()
    receiver_env.update(PYTHON_COMMON)
    receiver_env.update({
        'RECEIVER_HOST': '127.0.0.1',
        'RECEIVER_PORT': str(port),
        'SOCKET_TIMEOUT': '10',
        'RECEIVER_LOG_FILE': receiver_log,
    })
    receiver = subprocess.Popen(
        [sys.executable, 'receiver.py'],
        cwd=cwd,
        env=receiver_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='replace',
    )

    started = False
    start_time = time.time()
    collected = []
    while time.time() - start_time < 5:
        line = receiver.stdout.readline()
        if line:
            sys.stdout.write(line)
            collected.append(line)
            if 'Listening on' in line:
                started = True
                break

    if not started:
        receiver.kill()
        raise SystemExit(f'Receiver for {session_name} did not start correctly. Output:\n' + ''.join(collected))

    sender_env = os.environ.copy()
    sender_env.update(PYTHON_COMMON)
    sender_env.update({
        'SERVER_IP': '127.0.0.1',
        'SERVER_PORT': str(port),
        'MESSAGE': message,
        'SENDER_LOG_FILE': sender_log,
    })
    sender = subprocess.run(
        [sys.executable, 'sender.py'],
        cwd=cwd,
        env=sender_env,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=10,
        check=True,
    )

    print(f'--- {session_name} SENDER OUTPUT ---')
    print(sender.stdout)
    receiver_out, _ = receiver.communicate(timeout=10)
    print(f'--- {session_name} RECEIVER OUTPUT ---')
    print(receiver_out)

    if receiver.poll() is None:
        receiver.kill()


def write_log(path: str, content: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def create_negative_test_logs() -> None:
    # Tamper test evidence
    key, iv, cipher_bytes = encrypt_des_cbc(b'Test message for tamper')
    tampered = bytearray(cipher_bytes)
    tampered[-1] ^= 0x01
    tamper_log = 'Tamper test: modify last byte of ciphertext.\n'
    try:
        decrypted = decrypt_des_cbc(key, iv, bytes(tampered))
        tamper_log += f'Result: decrypted plaintext = {decrypted!r}\n'
        if decrypted != b'Test message for tamper':
            tamper_log += 'Conclusion: plaintext differs after tampering.\n'
        else:
            tamper_log += 'Conclusion: plaintext matched unexpectedly.\n'
    except Exception as exc:
        tamper_log += f'Caught exception: {type(exc).__name__}: {exc}\n'
    write_log(os.path.join(logs_dir, '03-tamper.txt'), tamper_log)

    # Wrong key test evidence
    key, iv, cipher_bytes = encrypt_des_cbc(b'Test message for wrong key', key=b'12345678', iv=b'abcdefgh')
    wrong_key_log = 'Wrong key test: decrypt with wrong 8-byte key.\n'
    try:
        decrypted = decrypt_des_cbc(b'87654321', iv, cipher_bytes)
        wrong_key_log += f'Result: decrypted plaintext = {decrypted!r}\n'
        if decrypted != b'Test message for wrong key':
            wrong_key_log += 'Conclusion: decrypted plaintext is incorrect.\n'
        else:
            wrong_key_log += 'Conclusion: plaintext matched unexpectedly.\n'
    except Exception as exc:
        wrong_key_log += f'Caught exception: {type(exc).__name__}: {exc}\n'
    write_log(os.path.join(logs_dir, '04-wrong-key.txt'), wrong_key_log)

    # Header error test evidence
    header_error_log = 'Header error test: parse invalid header length.\n'
    try:
        parse_header(b'1234')
        header_error_log += 'Result: parse_header did not raise an error.\n'
    except Exception as exc:
        header_error_log += f'Caught exception: {type(exc).__name__}: {exc}\n'
    write_log(os.path.join(logs_dir, '05-header-error.txt'), header_error_log)


if __name__ == '__main__':
    run_demo(
        session_name='Tuyet happy path',
        message='Xin chao FIT4012 - demo tuyet',
        sender_log=os.path.join('logs', '01-happy-path-tuyet.txt'),
        receiver_log=os.path.join('logs', '02-happy-path-hung.txt'),
    )
    create_negative_test_logs()
