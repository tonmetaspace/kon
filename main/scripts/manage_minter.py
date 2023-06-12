
from tonsdk.contract.wallet import Wallets
from tonsdk.contract.token.nft.nft_utils import create_offchain_uri_cell
from tonsdk.contract import Contract
from tonsdk.boc import Cell, begin_cell, begin_dict
from tonsdk.utils import Address
from nacl.bindings import crypto_sign_seed_keypair
from base64 import b64encode
import os
import sys
import httpx
import json
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


def get_seqno(addr: str):
    try:
        res = httpx.get(
            TONCENTER_ENDPOINT + 'getWalletInformation',
            headers={
                'X-API-Key': TONCENTER_API_KEY,
            },
            params={
                'address': addr
            }
        ).json()
        if res['result']['account_state'] == 'uninitialized':
            return 0

        return res['result'].get('seqno', 0)
    except Exception as e:
        print(f"Error: {e}")
        return 0


def run_get_method(addr, method, stack=[]):
    try:
        return httpx.post(
            TONCENTER_ENDPOINT + 'runGetMethod',
            headers={
                'X-API-Key': TONCENTER_API_KEY,
            },
            json={
                'address': addr,
                'method': method,
                'stack': stack,
            }
        ).json()['result']
    except Exception as e:
        print(f"Error: {e}")
        return run_get_method(addr, method, stack)


class JettonMinter(Contract):
    code = 'B5EE9C7201022A01000B56000114FF00F4A413F4BCF2C80B01020120020302014804050008F230F8000202CC060702012024250201D4080900C1B3F0508A08E040DA8A60A8488190A00BF404A0079E2C039E2D99E801924591960225E801E80196019241F200E0E9919605940F97FF93A04722EF22E3C5003191960AB19E2CA007F404472500D92500D7C420479E02052403992261C59992E3F60104F53B7EC07434C0C05C6C38C0BE903E900C7E800C5C75C87E800C7E800C1CEA6D003B51343E80007E187500743E90007E18BE90007E18F5007E19350C3E1975007E19B5007E19C835D2B08024B50C248C1B78BE1A08B1C038C080B4C7C8700038C088700288A084354C9DB6EEAC6497C17834CFC8A0841CD8B4272EA00A0B0C0D00113E910C30003CB8536001F030318020D721D31F218210178D4519BA8E64318040D721FA0030ED44D0FA0001F861D401D0FA4001F862FA4001F863D401F864D430F865D401F866D401F86720D74AC20092D43092306DE2F868F84101A1F861F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED54E30E0E02E8303101820A625A00A120820AFAF080B9F2D318F844D0D2008020D721FA003001B301C101B18E4B833FF811A4F84852108040F40E6FA131F2D319C85003CF1601FA02C9F84852208040F417F86882108B0B7F8BC8CB1FCB3F708018C8CB05F842CF168209312D00FA02CB6A01CF17C971FB00E30D101C03FC313221C7008F733101820A625A00A120820AFAF080B9F2D318F844D0D2008020D721FA003001B301C101B18E4B833FF811A4F84852108040F40E6FA131F2D319C85003CF1601FA02C9F84852208040F417F86882108B0B7F8BC8CB1FCB3F708018C8CB05F842CF168209312D00FA02CB6A01CF17C971FB00E30DE0303120101C110450E3022282107BDD97DEBAE3022282108B0B7F8BBA8E8E323333F842C705F2E04901FA0030E022C0151213141501D80182108B0B7F8BBA8EDFD33F30ED44D0FA0001F861D401D0FA4001F862FA4001F863D401F864D430F865D401F866D401F86720D74AC20092D43092306DE2F8688D0994985D19481BDC9858DB19481C995D1D5C9B995908195C9C9BDC8B88151C9E481B185D195C8BA09130E20F00A2F848128040F4666FA130D430D0FA40FA003070208010C8CB055004CF1658FA0212CB6ACB1F58CF16C971FB00F868F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED5400583070208010C8CB055003CF1621FA0212CB6ACB1F8BF49434F20706175736564206E6F772E8CF16C98040FB00003CD749C0388E11D3373082286465706F736974BA92DB31E09130E2840FF2F001FC32333302FA00FA403023FA4401C000F2E14DF8458307F40E6FA1F2E049D20001F2E049D33F3020AA005230BEF2E0485122A1F844D0D20001F2E048D31FFA00D33FD30FD33F30258103E8A825A90428A90424B608F84121A0821005F5E100BC9A30821005F5E100F841A1DE5308A826A88103E8A90417A120C100F2D359261601FA32333302FA00FA40F828F847102370206D4530542440C85005FA025003CF1601CF16CCF400C922C8CB0112F400F400CB00C9F9007074C8CB02CA07CBFFC9D05004C705F2E04AF84101A1F861F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED5401FA403020D70B01C300915BE30D1803EAF84852208040F4666FA130D430D0FA40FA0030F844D0D20001F2E048D31FFA00D33FD30FD33F3025820A625A00A129A9048103E8A825A90424B608F84121A0821005F5E100BC9A30821005F5E100F841A1DE520AA825A88103E8A9042070FB0216A120C100F2D359208209312D00BE29C200B1E30F191A1C04F88EE4355BF843C705F2E04901FA4021F001FA008209312D005004A05210BEF2E04802D43020D0D31F018210178D4519BAF2E0488040D721FA00FA4031FA4031FA0031F40431D2000192D431DED1F84750427FF009F84101A0F861F841821005F5E100BCF2D34CE02282102C76B973BAE30231333322C003E30222C01E1C1D1E1F02FAC2008E6C7024C8CB3F5240CB0F5230CB3FC9718210178D4519C8CB1F1DCB3F29FA02F828CF16F828CF168208989680FA021CCB001BCC1ACB00C9F8478209C9C38029037FF0095135A17FC8CA0015CB1F5004FA02CB3F12CB0FCB3FC9F864F84101A0F861F841821005F5E100BCF2D34C93395F06E25222BE925F03E30D171C00800170530082100F8A7EA5C8CB1FCB3F5003FA025003CF16F828CF16CB0082080F4240FA02CB00C9718010C8CB055003CF16820AFAF080FA0212CB6ACCC971FB00003E8210D53276DB708010C8CB055003CF1622FA0212CB6ACB1FCB3FC98042FB0001AA28C200951069385F06E30D218209312D00BE8E3B70208010C8CB055005CF165003FA0213CB6ACB1F8D0794DD58D8D95CDCD99D5B081CDDD85C081C995B585A5B88185B5BDD5B9D0BA0CF16C970FB00926C21E2F8681B00DE5F098D06555B9ADB9BDDDB88195C9C9BDC8B081D1C9E481859D85A5B8BA0F848128040F4666FA130D430D0FA40FA003070208010C8CB055004CF1658FA0212CB6ACB1F58CF16C971FB00F868F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED5400E8820A625A00A17023C8CB3F5230CB0F5270CB3FC9718210178D4519C8CB1F1DCB3F2BFA02F828CF16F828CF168208989680FA021CCB001BCC1ACB00C9F8478209C9C38028037FF0095127A17FC8CA0014CB1F5003FA0212CB3FCB0FCB3FC9F864F8415003A0F861F841821005F5E100BCF2D34C120046F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED5401FE32038208989680A014BCF2E04B02FA40D3003095C821CF16C9916DE28210D1735400708018C8CB055006CF1625FA0215CB6A14CB1F12CB3F21FA4430C0008E39F828F847102370206D4530542440C85005FA025003CF1601CF16CCF400C922C8CB0112F400F400CB00C9F9007074C8CB02CA07CBFFC9D0CF16947032CB01E220006232F84312C705F2E049FA4030F863F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED5403FC8E3032F84312C705F2E049D430F866F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED54E022C00B8E3132F84312C705F2E049FA4030F862F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED54E022C016E30222C014E30202C01EE3025B840FF2F0212223000EF400C98040FB00009232F84312C705F2E049D421D0D20031D31F31FA0031D33F31D30F31D33F31D101F864D430F865F848F847F846F845F844C8F842CF16F843CF16CCCCC9C8F841FA02CCCCCCF400C9ED54004C32F84312C705F2E049FA40FA00308014708010C8CB055004CF1658FA0212CB6ACB1FC970FB00009CF84312C705F2E049FA40FA40FA003070530082100F8A7EA5C8CB1FCB3F5003FA025003CF16F828CF16CB0082080F4240FA02CB00C9718010C8CB055003CF16820AFAF080FA0212CB6ACCC971FB00008BBE6E9F6A2687D0000FC30EA00E87D2000FC317D2000FC31EA00FC326A187C32EA00FC336A00FC33906BA56100496A18491836F17C347C22686900698FFD00699FE987E99F984020148262702015828290077B5265DA89A1F40003F0C3A803A1F48003F0C5F48003F0C7A803F0C9A861F0CBA803F0CDA803F0CE41AE95840125A8612460DBC5F0D1F085F089F08B000D5ADBCF6A2687D0000FC30EA00E87D2000FC317D2000FC31EA00FC326A187C32EA00FC336A00FC33906BA56100496A18491836F17C347C147C23B81036A2982A1220642802FD012801E78B00E78B667A006491646580897A007A00658064FC80383A6465816503E5FFE4E840007DAF16F6A2687D0000FC30EA00E87D2000FC317D2000FC31EA00FC326A187C32EA00FC336A00FC33906BA56100496A18491836F17C347C20BFFC21FC237C23C0'

    def __init__(self, **kwargs):
        self.code = kwargs.get('code') or self.code
        kwargs['code'] = Cell.one_from_boc(self.code)

        super().__init__(**kwargs)

    def create_data_cell(self) -> Cell:
        return begin_cell() \
            .store_coins(0) \
            .store_ref(
                begin_cell()
            .store_address(self.options['oracle_address'])
            .store_address(self.options['admin_address'])
            .store_ref(
                    begin_cell()
                    .store_int(-1, 1)  # enabled?
                    .store_uint(1000, 32)  # price
                    .store_coins(100)  # remaining amount
                    .store_uint(600, 64)  # freeze timer
                    .store_uint(12, 16)  # lock parts count
                    .store_uint(3600, 64)  # lock time
                    .end_cell()
                )
            .store_ref(  # stable_jettons
                    begin_dict(256)
                    .store_cell(0, begin_cell().store_int(-1, 1).end_cell())
                    .end_dict()
                )
            .end_cell()
        ) \
            .store_ref(
                create_offchain_uri_cell(self.options['jetton_content_uri'])
        ) \
            .store_ref(
                Cell.one_from_boc(self.options['jetton_wallet_code_hex'])
        ) \
            .store_maybe_ref(None).end_cell()

    def create_external_message(self, state_init=None):
        body = Cell()
        self_address = self.address
        header = Contract.create_external_message_header(self_address)
        result_message = Contract.create_common_msg_info(
            header, state_init, body)
        return {
            "address": self_address,
            "message": result_message,
            "body": body,
            "state_init": state_init,
        }

    def create_mint_body(self, destination: Address, jetton_amount: int, amount: int = 50000000, query_id: int = 0, lockup=None) -> Cell:
        body = Cell()
        body.bits.write_uint(21, 32)  # OP mint
        body.bits.write_uint(query_id, 64)
        body.bits.write_address(destination)
        body.bits.write_grams(amount)

        transfer_body = Cell()  # internal transfer
        transfer_body.bits.write_uint(0x178d4519, 32)  # OP internal_transfer
        transfer_body.bits.write_uint(query_id, 64)
        transfer_body.bits.write_grams(jetton_amount)  # jetton amount
        transfer_body.bits.write_address(None)  # from_address
        transfer_body.bits.write_address(None)  # response_address
        transfer_body.bits.write_grams(0)  # forward amount
        transfer_body.bits.write_uint(0 if lockup is None else 1, 1)
        if not (lockup is None):
            transfer_body.refs.append(
                begin_cell()
                .store_uint(lockup[0], 64)
                .store_uint(lockup[1], 16)
                .store_uint(lockup[2], 64)
                .end_cell()
            )

        # forward_payload in this slice, not separate cell
        transfer_body.bits.write_bit(0)

        body.refs.append(transfer_body)
        return body

    def create_change_admin_body(self, new_admin_address: Address, query_id: int = 0) -> Cell:
        body = Cell()
        body.bits.write_uint(3, 32)  # OP
        body.bits.write_uint(query_id, 64)  # query_id
        body.bits.write_address(new_admin_address)
        return body

    def create_edit_content_body(self, jetton_content_uri: str, query_id: int = 0) -> Cell:
        body = Cell()
        body.bits.write_uint(4, 32)  # OP
        body.bits.write_uint(query_id, 64)  # query_id
        body.refs.append(create_offchain_uri_cell(jetton_content_uri))
        return body


if __name__ == '__main__':
    try:
        with open('minter_admin_mnemonics', 'r') as file:
            minter_admin_mnemonics = file.read().strip().split(' ')
            assert len(minter_admin_mnemonics) == 24
    except Exception as e:
        with open('minter_admin_mnemonics', 'w') as file:
            minter_admin_mnemonics, _, _, _ = Wallets.create('v3r2', 0)
            file.write(' '.join(minter_admin_mnemonics))

            print(
                f"[!] Generated new minter admin mnemonics. Please, save this file and don't lose it!")

    try:
        with open('minter_initsets', 'r') as f:
            settings = json.loads(f.read())

        assert 'content_uri' in settings
    except Exception as e:
        with open('minter_initsets', 'w') as f:
            settings = {
                'content_uri': input(f"Input content URI: "),
            }
            f.write(json.dumps(settings))

        print(f"[!] Generated new settings file and saved it to minter_initsets file. Please, save this file and don't lose it.")

    _, public_key, private_key, wallet = Wallets.from_mnemonics(
        minter_admin_mnemonics, 'v3r2', 0)
    settings['admin_address'] = wallet.address

    wallet_address = wallet.address.to_string(1, 1, 0)
    print(f"[+] Minter admin wallet address: {wallet_address}")
    wallet_seqno = get_seqno(wallet_address)
    print(f"[+] Minter admin wallet seqno: {wallet_seqno}")

    minter = JettonMinter(
        oracle_address=None,
        jetton_content_uri=settings['content_uri'],
        jetton_wallet_code_hex='B5EE9C72010215010004AC000114FF00F4A413F4BCF2C80B0102016202030202CC040502012011120201D40607018FBB0041AE43B679A63F081E4504202F1A8A3374070420F7BB2FBD74276225E5E9A67E63F40061F0840341F0C5F085F087F089F08BF08D90A00BF404A0079E2C039E2D99E80193DAA91304A70831C02497C138007434C0C05C6C2544D7C0FC03783E903E900C7E800C5C75C87E800C7E800C00B4C7C8608403E29FA96EA3E5CC4D1640F4CFFE803E90087C0076CF3E11148831C178C3F808608405E351466EA01308090A00113E910C30003CB8536001FE5B01C8CB3F01FA0222CF16C9D003DB3C03D33FFA00FA4030F84222A1F862F8435005C705F2E049F842C2FFF2AF048209312D00A012BCF2B082107BDD97DEC8CB1FCB3F58FA02F843CF1601CF16C9718018C8CB05F844CF1670FA02CB6ACCC98040FB00F842F843F844F845F846C85005FA025003CF1601CF16CCF400C9ED541302FCF8435006C705F2E049F846DB3C3101F866F84223A1F862F84201A1C2FFF2E2DDF842C2FFF2AFF844F84570206D4530542440C85005FA025003CF1601CF16CCF400C922C8CB0112F400F400CB00C920F9007074C8CB02CA07CBFFC9D005FA40F40431FA00778018C8CB055009CF1670FA0218CB6B13CC708210178D4519C8140B02328E8631444403DB3CE0358210595F07BCBAE3025F04840FF2F00C0D00A8CB1F16CB3F5004FA02F843CF1601CF1621FA0213CB005004CF16C95003CC2291729171E2A45004A812A08209C9C380A0BCF2B0C98040FB00F842F843F844F845F846C85005FA025003CF1601CF16CCF400C9ED5403F6DB3C04D33FFA00F84222A0F862FA40FA40F84428C705F844F845255970206D4530542440C85005FA025003CF1601CF16CCF400C922C8CB0112F400F400CB00C9F9007074C8CB02CA07CBFFC9D05009C70518B1F2E04A06FA00F404216EB39131E30D5168A1820898968066B608A18208989680A018A120C2FFF2B0130E0F01E459DB3C03D33FFA00FA4030F84222A1F862F8435005C705F2E049F842C2FFF2AF048209312D00A012BCF2B082107BDD97DEC8CB1FCB3F58FA02F843CF1601CF16C9718018C8CB05F844CF1670FA02CB6ACCC98040FB00F842F843F844F845F846C85005FA025003CF1601CF16CCF400C9ED5413008E01D0F82301D33FD30F0171B60901D33F3021A9042782103B9ACA00A822A904F846208010F48E6FA56C1291A4923070E206C8CB3F15CB3F01FA02CB3FCB0FC9D0598010F416F86601DA278E345374A0A182107362D09CC8CB1F5240CB3F5003FA0201CF165004CF16C9718018C8CB05F843CF165007FA0216CB6A15CCC971FB00951037355F03E2A121D70B01C30021C200B08E1E8210D53276DB708010C8CB055004CF1658FA0212CB6ACB1FCB3FC972FB00925F03E2100038F842F843F844F845F846C85005FA025003CF1601CF16CCF400C9ED540119BFD816D9E7C217C21FC227C22C130211BF7C56D9E7C236D9E413140044F8416EDDED44D0FA0001F862FA4001F863FA4001F864D401F865F40430F8667FF86100AA7020F8238E4553238010F47D6FA5208E353501D33FD33FFA00D33FD30F305265A15003A120C100923070DE58A9045302BE9A305321088010F45B3007DE12A101A813A002A403926C21E2B3E63082103B9ACA00A904',
        admin_address=settings['admin_address'],
    )

    try:
        if sys.argv[1]:
            minter._address = Address(sys.argv[1])
    except:
        pass

    print(f"Minter address: {minter.address.to_string(1, 1, 0)}")

    src = input(f"Enter command: ").split(' ')
    command = src[0] if src[0] else 'deploy'
    args = src[1:]

    if wallet_seqno < 1:
        print(
            f"[*] Wallet seqno is {wallet_seqno}. Sending deploy transaction...")
        command = 'deploy_wallet'

    if command == 'deploy':
        print(f"Deploying minter...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    state_init=minter.create_state_init()['state_init'],
                    payload=begin_cell()
                    .store_uint(10, 32)
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'deploy_wallet':
        print(f"Deploying wallet...")
        print(
            send_boc(
                wallet.create_init_external_message()['message'].to_boc(False)
            )
        )
    elif command == 'set_oracle':
        target_addr = Address(args[0])
        print(f"Send set_oracle message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(11, 32).store_uint(0, 64)
                    .store_address(target_addr)
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'change_admin':
        new_admin = Address(args[0])
        print(f"Send change_admin message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(3, 32).store_uint(0, 64)
                    .store_address(new_admin)
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'change_content':
        new_url = args[0]
        print(f"Send change_content message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(30, 32).store_uint(0, 64)
                    .store_ref(create_offchain_uri_cell(new_url))
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'mint':
        target_addr = Address(args[0])
        amount = int(float(args[1]))  # 10**0 = 1 token
        args = args[2:]
        lockup = None
        if args:
            lockup = [int(args[0]), int(args[1]), int(args[2])]

        print(f"Send mint message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    7 * 10 ** 7,
                    wallet_seqno,
                    payload=minter.create_mint_body(
                        target_addr,
                        amount,
                        lockup=lockup
                    )
                )['message'].to_boc(False)
            )
        )
    elif command == 'sell':
        result = run_get_method(
            minter.address.to_string(1, 1, 1),
            'get_sale_settings'
        )
        if result['exit_code'] != 0:
            print(f"Error: {result['exit_code']}")
        else:
            result = result['stack']
            print(f"""
Sale settings:
Enabled: {True if int(result[0][1], 16) == -1 else False}
Price: {int(result[1][1], 16) / 1000}$
Remaining: {int(result[2][1], 16)} Jettons 
Freeze timer: {int(result[3][1], 16)} seconds     
Lock parts count: {int(result[4][1], 16)}
Lock time: {int(result[5][1], 16)} seconds    
""")
    elif command == 'update_sell':
        payload = begin_cell()
        enabled = int(input(f"Enabled (1/0): "))
        if enabled:
            price = int(float(input(f"Price ($): ")) * 1000)
            remain_jettons = int(float(input(f"Remaining jettons: ")))
            freeze_timer = int(input(f"Freeze time (seconds): "))
            lock_parts = int(input(f"Lock parts count: "))
            lock_time = int(input(f"Lock time (seconds): "))

            payload.store_ref(
                begin_cell().store_int(-1, 1)
                .store_uint(price, 32)
                .store_coins(remain_jettons)
                .store_uint(freeze_timer, 64)
                .store_uint(lock_parts, 16)
                .store_uint(lock_time, 64)
                .end_cell()
            )
        else:
            payload.store_ref(
                begin_cell().store_int(0, 1).store_uint(0, 32).store_uint(0, 4)
                .store_uint(0, 16).store_uint(0, 64).end_cell()
            )

        stable_dict = begin_dict(256)

        hashpart = 1
        while hashpart:
            hashpart = int(input(f"Hash part (0 to finish): "))
            if hashpart:
                stable_dict.store_cell(
                    hashpart, begin_cell().store_int(-1, 1)
                    .store_uint(10 ** int(input(f"Enter N for 10^n: ")), 64)
                    .end_cell()
                )

        stable_dict.store_cell(
            0, begin_cell().store_int(0, 1)
            .store_uint(0, 64)
            .end_cell()
        )

        payload.store_ref(stable_dict.end_dict())

        print(f"Send update_sell message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(22, 32).store_uint(0, 64)
                    .store_ref(payload.refs[0]).store_ref(payload.refs[1])
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'withdraw':
        target_addr = Address(args[0])
        amount = int(float(args[1]) * 10 ** 9)
        print(f"Send withdraw message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(20, 32).store_uint(0, 64)
                    .store_address(target_addr)
                    .store_coins(amount)
                    .end_cell()
                )['message'].to_boc(False)
            )
        )
    elif command == 'withdraw_jettons':
        wallet_addr = Address(args[0])
        target_addr = Address(args[1])
        amount = int(float(args[2]) * 10 ** 9)
        print(f"Send withdraw message...")
        print(
            send_boc(
                wallet.create_transfer_message(
                    minter.address.to_string(1, 1, 1),
                    5 * 10 ** 7,
                    wallet_seqno,
                    payload=begin_cell()
                    .store_uint(30, 32).store_uint(0, 64)
                    .store_address(wallet_addr)
                    .store_address(target_addr)
                    .store_coins(amount)
                    .end_cell()
                )['message'].to_boc(False)
            )
        )


input("Press Enter to exit...")
