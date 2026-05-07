from des_socket_utils import encrypt_des_cbc, decrypt_des_cbc, parse_header
import os

logs_dir = 'logs'
os.makedirs(logs_dir, exist_ok=True)

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
with open(os.path.join(logs_dir, '03-tamper.txt'), 'w', encoding='utf-8') as f:
    f.write(tamper_log)

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
with open(os.path.join(logs_dir, '04-wrong-key.txt'), 'w', encoding='utf-8') as f:
    f.write(wrong_key_log)

# Header error test evidence
header_error_log = 'Header error test: parse invalid header length.\n'
try:
    parse_header(b'1234')
    header_error_log += 'Result: parse_header did not raise an error.\n'
except Exception as exc:
    header_error_log += f'Caught exception: {type(exc).__name__}: {exc}\n'
with open(os.path.join(logs_dir, '05-header-error.txt'), 'w', encoding='utf-8') as f:
    f.write(header_error_log)