from tonsdk.contract import Contract
from tonsdk.boc import Cell, begin_cell
from tonsdk.utils import Address, sign_message
from nacl.bindings import crypto_sign_seed_keypair
from base64 import b64encode
import os
import sys
import httpx
import time

TESTNET = False
TONCENTER_API_KEY = {
    True: 'e3bd9f0a1dfa8274126c5f45e9596c3f8445665013fb46ee551b1ac5027a020b',
    False: '7f9651056ecab17e83b996a04a90b98c0ddf857b2911c2efae647f6c29b5ffd9'
}[TESTNET]
TONCENTER_ENDPOINT = f"https://{'testnet.' if TESTNET else ''}toncenter.com/api/v2/"


def send_boc(src: bytes):
    return httpx.post(
        TONCENTER_ENDPOINT + 'sendBoc',
        headers={
            'X-API-Key': TONCENTER_API_KEY,
        },
        json={
            'boc': b64encode(src).decode(),
        }
    ).json()


class RateOracle(Contract):
    def __init__(self, **kwargs):
        kwargs['code'] = Cell.one_from_boc('B5EE9C7201020E0100012B000114FF00F4A413F4BCF2C80B010201200203020148040500BCF2EDFB8308D71820D33FD31F02F823BBF260F0015141BAF2A105F901541063F910F2A3F80002D31F218210F7BF733EBA9E313233FA0030F82302A45003F002E0018210D762F8D6BA9D3102A402D3FF304330F002DB31E03002A44303F0020202CE06070201480A0B0201200809001F4C85004FA0212CB3FCB1FCBFFC9ED54800C50CF434C0C05C6C2497C0F83E900C0060824C4B402E7CB4644074C7C0608422C2DFE2EEA38DFC0056E04465283E08EF3CB8544074CFCC208422C2DFE2F232C7F2CFC07E809C20043232C15400F3C588BE8084B2DA8073C5F260107EC03816E103FCBC2000193B51343E8034CFF4C7F4FFCC2002037B200C0D000BB8833F0015B8000DA45FE00226BE07000BA739E002D863')
        # kwargs['code'] = Cell.one_from_boc('B5EE9C72010104010059000114FF00F4A413F4BCF2C80B0102012002030074D2135F03D0D3030171B09130E0FA4030708010C8CB0522CF16821005F5E100FA02CB6AC971FB00708010C8CB0558CF1621FA02CB6AC98040FB000012F2307AC8CB1FC9ED54')
        super().__init__(**kwargs)

    def create_data_cell(self):
        return begin_cell() \
            .store_uint(0, 4).store_uint(0, 64).store_uint(0, 32) \
            .store_bytes(self.options['public_key']) \
            .end_cell()

    def create_signing_message(self, seqno=0):
        message = Cell()
        timestamp = int(time.time())  # get timestamp in seconds
        message.bits.write_uint(timestamp + 60, 64)
        message.bits.write_uint(seqno, 32)
        return message

    def create_external_message(self, signing_message, state_init=None):
        signature = sign_message(
            bytes(signing_message.bytes_hash()), self.options['private_key']).signature
        body = Cell()
        body.bits.write_bytes(signature)
        body.write_cell(signing_message)
        # state_init = code = data = None
        self_address = self.address
        header = Contract.create_external_message_header(self_address)
        result_message = Contract.create_common_msg_info(
            header, state_init, body)
        return {
            "address": self_address,
            "message": result_message,
            "body": body,
            "signature": signature,
            "signing_message": signing_message,
            "state_init": state_init,
        }


try:
    with open('oracle_seed', 'rb') as f:
        seed = f.read()
except FileNotFoundError:
    seed = os.urandom(32)
    with open('oracle_seed', 'wb') as f:
        f.write(seed)

    print(f"Generated new seed and saved it to oracle_seed file. Please, save this file and don't lose it.")

public_key, private_key = crypto_sign_seed_keypair(seed)
print(f"Public key: {public_key.hex()}")

oracle = RateOracle(public_key=public_key, private_key=private_key)


if __name__ == '__main__':
    try:
        with open('oracle_seed', 'rb') as f:
            seed = f.read()
    except FileNotFoundError:
        seed = os.urandom(32)
        with open('oracle_seed', 'wb') as f:
            f.write(seed)

        print(f"Generated new seed and saved it to oracle_seed file. Please, save this file and don't lose it.")

    public_key, private_key = crypto_sign_seed_keypair(seed)
    print(f"Public key: {public_key.hex()}")

    oracle = RateOracle(public_key=public_key, private_key=private_key)
    print(f"Oracle address: {oracle.address.to_string(1, 1, 1)}")

    command = sys.argv[1] if len(sys.argv) > 1 else 'deploy'
    args = sys.argv[2:]

    if command == 'deploy':
        print(f"Deploying oracle...")
        print(
            send_boc(
                oracle.create_external_message(
                    begin_cell().store_cell(oracle.create_signing_message()).store_uint(0, 32).end_cell(),
                    state_init=oracle.create_state_init()['state_init']
                )['message'].to_boc(False)
            )
        )
    elif command == 'delivery_rate':
        seqno = int(args[0])
        rate = int(args[1])
        print(f"Setting delivery rate to {rate}...")
        print(
            send_boc(
                oracle.create_external_message(
                    begin_cell().store_cell(oracle.create_signing_message(seqno))
                    .store_uint(0xf7bf733e, 32).store_coins(rate).end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'edit_owner':
        seqno = int(args[0])
        new_seed = bytes.fromhex(args[1])
        new_public_key, new_private_key = crypto_sign_seed_keypair(new_seed)
        print(f"Changing owner to {new_public_key.hex()}...")
        print(
            send_boc(
                oracle.create_external_message(
                    begin_cell().store_cell(oracle.create_signing_message(seqno))
                    .store_uint(0xd762f8d6, 32).store_bytes(new_public_key).end_cell()
                )['message'].to_boc(False)
            )
        )
