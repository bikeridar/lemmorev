# Bleak based script which can connect to your bike and unlock it.
import asyncio
from enum import Enum
from Crypto.Cipher import AES
from struct import pack, unpack
import secrets
import hashlib
from binascii import hexlify

ADDRESS = "dc:ff:ff:ff:ff:ff" # Fill with your own
LOGIN_KEY = "CXXXXXXXXXXXXXXX"[:6].encode('utf-8') # Fill with your own
UUID = b"45ffffffffffffff\0\0\0\0\0\0\0\0" # Fill with your own
DEV_ID = b"bfffffffffffffff" # Fill with your own
GATT_MTU = 243

class AesUtils:
    @staticmethod
    def decrypt(data, iv, key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    @staticmethod
    def encrypt(data, iv, key):
        print("AES key=", hexlify(key), "iv=", hexlify(iv), "data=", hexlify(data))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)


class CrcUtils:
    @staticmethod
    def crc16(data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 255
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001

        return crc

class TuyaDataPacket:
    @staticmethod
    def prepare_crc(sn_ack, ack_sn, code, inp, inp_length):
        raw = pack('>IIHH', sn_ack, ack_sn, code, inp_length)
        raw += inp
        crc = CrcUtils.crc16(raw)
        print("CRC ", hexlify(raw), "=", hexlify(pack('>H', crc)))
        return raw + pack('>H', crc)

    @staticmethod
    def get_random_iv():
        # TODO return secrets.token_bytes(16)
        return 16*b"\00"

    @staticmethod
    def encrypt_packet(secret_key, security_flag, iv, data):
        while len(data) % 16 != 0:
            data += b'\x00'

        encrypted_data = AesUtils.encrypt(data, iv, secret_key)
        output = bytearray()
        output += security_flag.to_bytes(1, byteorder='big')
        output += iv
        output += encrypted_data

        return output


class XRequest:
    def __init__(self, sn_ack, ack_sn, code, security_flag, secret_key, iv, inp):
        self.gatt_mtu = GATT_MTU

        self.sn_ack = sn_ack
        self.ack_sn = ack_sn
        self.code = code
        self.security_flag = security_flag
        self.secret_key = secret_key
        self.iv = iv
        self.inp = inp


    def split_packet(self, protocol_version, data):
        output = []
        packet_number = 0
        pos = 0
        length = len(data)
        while pos < length:
            b = bytearray()
            b += packet_number.to_bytes(1, byteorder='big')

            if packet_number == 0:
                b += pack('>B', length)
                b += pack('<B', protocol_version << 4)

            sub_data = data[pos:pos + self.gatt_mtu - len(b)]
            b += sub_data
            output.append(b)

            pos += len(sub_data)
            packet_number += 1

        return output


    def pack(self):
        data = TuyaDataPacket.prepare_crc(self.sn_ack, self.ack_sn, self.code, self.inp, len(self.inp))
        encrypted_data = TuyaDataPacket.encrypt_packet(self.secret_key, self.security_flag, self.iv, data)

        return self.split_packet(2, encrypted_data)

class SecretKeyManager:
    def __init__(self, login_key):
        self.login_key = login_key
        self.keys = {
            4: hashlib.md5(self.login_key).digest(),
        }

    def get(self, security_flag):
        return self.keys.get(security_flag, None)

    def setSrand(self, srand):
        self.keys[5] = hashlib.md5(self.login_key + srand).digest()

class BleReceiver:
    def __init__(self, secret_key_manager):
        self.last_index = 0
        self.data_length = 0
        self.current_length = 0
        self.raw = bytearray()
        self.version = 0

        self.secret_key_manager = secret_key_manager

    def unpack(self, arr):
        i = 0
        packet_number = 0
        while i < 4 and i < len(arr):
            b = arr[i]
            packet_number |= (b & 255) << (i * 7)
            if ((b >> 7) & 1) == 0:
                break
            i += 1

        pos = i + 1
        if packet_number == 0:
            self.data_length = 0

            while (pos <= i + 4 and pos < len(arr)):
                b2 = arr[pos]
                self.data_length |= (b2 & 255) << (((pos - 1) - i) * 7)
                if (((b2 >> 7) & 1) == 0):
                    break
                pos += 1

            self.current_length = 0
            self.last_index = 0
            if (pos == i + 5 or len(arr) < pos + 2):
                return 2

            self.raw.clear()
            pos += 1
            self.version = (arr[pos] >> 4) & 15
            pos += 1

        if (packet_number == 0 or packet_number > self.last_index):
            data = bytearray(arr[pos:])
            self.current_length += len(data)
            self.last_index = packet_number
            self.raw += data

            if self.current_length < self.data_length:
                return 1

            return 0 if self.current_length == self.data_length else 3

    def parse_data_received(self, arr):
        status = self.unpack(arr)
        if status == 0:
            security_flag = self.raw[0]
            secret_key = self.secret_key_manager.get(security_flag)

            ret = Ret(self.raw, self.version)
            ret.parse(secret_key)

            return ret

        return None

class DeviceInfoResp:
    def __init__(self):
        self.success = False

    def parse(self, raw):
        device_version_major, device_version_minor, protocol_version_major, protocol_version_minor, flag, is_bind, srand, hardware_version_major, hardware_version_minor, auth_key = unpack('>BBBBBB6sBB32s', raw[:46])
        auth_key = hexlify(auth_key)
        print("DeviceInfoResp", device_version_major, device_version_minor, protocol_version_major, protocol_version_minor, srand, hardware_version_major, hardware_version_minor, auth_key)

        self.device_version = '{}.{}'.format(device_version_major, device_version_minor)
        self.protocol_version = '{}.{}'.format(protocol_version_major, protocol_version_minor)
        self.flag = flag
        self.is_bind = is_bind
        self.srand = srand

        protocol_number = protocol_version_major * 10 + protocol_version_minor
        if protocol_number < 20:
            raise Exception("Protocol version too low")
        return

class Ret:
    def __init__(self, raw, version):
        self.raw = raw
        self.version = version

    def parse(self, secret_key):
        self.security_flag = self.raw[0]
        self.iv = self.raw[1:17]
        encrypted_data = self.raw[17:]

        decrypted = AesUtils.decrypt(encrypted_data, self.iv, secret_key)
        # print("DECR", hexlify(decrypted))

        sn, sn_ack, code, length = unpack('>IIHH', decrypted[:12])
        raw_data = decrypted[12:12 + length]
        print("Ret", sn, sn_ack, code, length, raw_data)

        self.code = code
        if self.code == 0:
            resp = DeviceInfoResp()
            resp.parse(raw_data)

            self.resp = resp


secret_key_manager = SecretKeyManager(LOGIN_KEY)
def device_info_request():
    global secret_key_manager
    inp = pack(">H", GATT_MTU)
    iv = TuyaDataPacket.get_random_iv()
    security_flag = 4
    secret_key = secret_key_manager.get(security_flag)

    return XRequest(sn_ack=1, ack_sn=0, code=0, security_flag=security_flag, secret_key=secret_key, iv=iv, inp=inp)

def pair_request():
    global secret_key_manager, UUID, LOGIN_KEY, DEV_ID
    security_flag = 5
    secret_key = secret_key_manager.get(security_flag)
    iv = TuyaDataPacket.get_random_iv()

    inp = bytearray()
    inp += UUID
    inp += LOGIN_KEY
    inp += DEV_ID

    for _ in range(22 - len(DEV_ID)):
        inp += b'\x00'
    
    inp += b"\x00\x01"
    print("HEXIN", hexlify(inp))

    return XRequest(sn_ack=2, ack_sn=0, code=1, security_flag=security_flag, secret_key=secret_key, iv=iv, inp=inp)

class DpType(Enum):
    RAW = 0
    BOOLEAN = 1
    INT = 2
    STRING = 3
    ENUM = 4

def send_dps_raw(sn, raw):
    security_flag = 5
    secret_key = secret_key_manager.get(security_flag)
    iv = TuyaDataPacket.get_random_iv()

    return XRequest(sn_ack=sn, ack_sn=0, code=39, security_flag=security_flag, secret_key=secret_key, iv=iv, inp=raw)

conn_state = "device_info"
ble_receiver = BleReceiver(secret_key_manager)
def notification_handler(characteristic, data):
    global ble_receiver, conn_state

    print("notification_handler: ", characteristic, data)
    ret = ble_receiver.parse_data_received(data)
    if not ret:
        return
    
    if ret.code == 0:
        print("Going into pairing state.")
        ble_receiver.secret_key_manager.setSrand(ret.resp.srand)
        conn_state = "pairing"
    elif ret.code == 1:
        print("Going into paired state.")
        conn_state = "paired"

async def send_request(client, chr, xrequest):
    packets = xrequest.pack()
    for cmd in packets:
        print('  >>', hexlify(cmd))
        await client.write_gatt_char(chr, cmd, False)

async def main(address):
    global conn_state

    # BLEAK_LOGGING=1
    from bleak import BleakClient

    async with BleakClient(address) as client:
        print("Read GAT")
        devname = await client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb")
        print(f"Dev NAME: {devname}")

        for svc in client.services:
            print(f"SVC {svc}")

        svc = client.services.get_service("0000fd50-0000-1000-8000-00805f9b34fb")
        characteristicNotify = svc.get_characteristic("00000002-0000-1001-8001-00805F9B07D0")
        commSvc = svc.get_characteristic("00000001-0000-1001-8001-00805F9B07D0")

        try:
            await client.start_notify(characteristicNotify, notification_handler)

            print("Dev info requesting....")
            req = device_info_request()
            await send_request(client, commSvc, req)

            while 1:
                if conn_state == "pairing":
                    conn_state = "pairing_pending"
                    print("Pairing...")
                    req = pair_request()
                    await send_request(client, commSvc, req)
                
                if conn_state == "paired":
                    conn_state = "done"
                    print("Unlocking...")
                    # This is what Tuya calls "XRequest" with dpsSn=5 (len?) and DP 1=1 for unlock
                    # I dont really remember the packed `publishDps` structure while documenting this besides the last byte being the value for locked
                    # Some ideas:
                    # \x01 (dpIds) \x01 (dpTypes) dpValues (len=\x00\x01, val=\x01)
                    # \x01 (len) \x01 (dpIds) \x00 (dpTypes) dpValues (len or ty=\x01, val=\x01)
                    req = send_dps_raw(3, b"\x00\x00\x00\x00\x05\x01\x01\x00\x01\x01")
                    await send_request(client, commSvc, req)

                await asyncio.sleep(1)
        except Exception as e:
            print(e)
            if e is KeyboardInterrupt:
                await client.stop_notify(characteristicNotify)
        
asyncio.run(main(ADDRESS))
