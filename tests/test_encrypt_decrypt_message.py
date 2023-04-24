from constants import CLA, RESPONSE_SUFFIX, PATH_STR_0, PATH_STR_3, PUBLIC_KEY_0, PUBLIC_KEY_3, R_SUCCESS
from ardor_command_sender import pack_derivation_path

INS_ENCRYPT_DECRYPT_MSG = 0x04
P1_ENCRYPTION_SETUP = 0x01
P1_ENCRYPTION_DECRYPT_AND_HIDE_SHARED_KEY = 0x02
P1_ENCRYPTION_DECRYPT_AND_RETURN_SHARED_KEY = 0x03
P1_ENCRYPTION_PROCESS_DATA = 0x04
MAX_BUFFER_SIZE = 224

def test_encrypt_decrypt_short_message(backend):
    msg = "It was a bright cold day in April, and the clocks were striking thirteen."

    # pad message to modulus 16
    padded_msg = msg + " " * (16 - len(msg) % 16)

    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_SETUP, data=pack_derivation_path(PATH_STR_0) + bytes.fromhex(PUBLIC_KEY_3))
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1 + 32 + 16 # 1 byte return value, 32 bytes nonce, 16 bytes IV
    nonce = rapdu.data[1:33]
    iv = rapdu.data[33:]

    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_PROCESS_DATA, data=padded_msg.encode())
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1 + len(padded_msg) # 1 byte return value, encrypted message
    encrypted_msg = rapdu.data[1:]

    # now decrypt the message and check that it is the same as the original
    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_DECRYPT_AND_HIDE_SHARED_KEY, 
                             data=pack_derivation_path(PATH_STR_3) + bytes.fromhex(PUBLIC_KEY_0) + nonce + iv)
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1

    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_PROCESS_DATA, data=encrypted_msg)
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1 + len(padded_msg) # 1 byte return value, decrypted message
    decrypted_msg = rapdu.data[1:]

    assert decrypted_msg == padded_msg.encode()

def test_encrypt_decrypt_long_message(backend):
    msg = "It was a bright cold day in April, and the clocks were striking thirteen." * 100

    # pad message to modulus 16
    padded_msg = msg + " " * (16 - len(msg) % 16)

    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_SETUP, data=pack_derivation_path(PATH_STR_0) + bytes.fromhex(PUBLIC_KEY_3))
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1 + 32 + 16 # 1 byte return value, 32 bytes nonce, 16 bytes IV
    nonce = rapdu.data[1:33]
    iv = rapdu.data[33:]

    # now send the message in chunks of max 224 bytes
    encrypted_msg = b""
    for i in range(0, len(padded_msg), MAX_BUFFER_SIZE):
        rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_PROCESS_DATA, data=padded_msg[i:i+224].encode())
        assert rapdu is not None
        assert rapdu.status == RESPONSE_SUFFIX
        assert rapdu.data[0] == R_SUCCESS
        assert len(rapdu.data) == 1 + len(padded_msg[i:i+MAX_BUFFER_SIZE])
        encrypted_msg += rapdu.data[1:]

    # now decrypt the message and check that it is the same as the original
    rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_DECRYPT_AND_HIDE_SHARED_KEY, 
                             data=pack_derivation_path(PATH_STR_3) + bytes.fromhex(PUBLIC_KEY_0) + nonce + iv)
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data[0] == R_SUCCESS
    assert len(rapdu.data) == 1

    # now send the encrypted message in chunks of max 224 bytes
    decrypted_msg = b""
    for i in range(0, len(encrypted_msg), MAX_BUFFER_SIZE):
        rapdu = backend.exchange(cla=CLA, ins=INS_ENCRYPT_DECRYPT_MSG, p1=P1_ENCRYPTION_PROCESS_DATA, data=encrypted_msg[i:i+MAX_BUFFER_SIZE])
        assert rapdu is not None
        assert rapdu.status == RESPONSE_SUFFIX
        assert rapdu.data[0] == R_SUCCESS
        assert len(rapdu.data) == 1 + len(encrypted_msg[i:i+MAX_BUFFER_SIZE])
        decrypted_msg += rapdu.data[1:]

    assert decrypted_msg == padded_msg.encode()