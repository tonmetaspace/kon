from datetime import datetime
from loguru import logger
import httpx
import time

from tonsdk.boc import begin_cell
from manage_oracle import oracle, send_boc

TESTNET = False
TONCENTER_API_KEY = {
    True: 'e3bd9f0a1dfa8274126c5f45e9596c3f8445665013fb46ee551b1ac5027a020b',
    False: '7f9651056ecab17e83b996a04a90b98c0ddf857b2911c2efae647f6c29b5ffd9'
}[TESTNET]
TONCENTER_ENDPOINT = f"https://{'testnet.' if TESTNET else ''}toncenter.com/api/v2/"

DELIVERY_INTERVAL = 60 * 60  # 1 hour


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


def calculate_rate():
    rates = []

    rates = httpx.get(
        'https://api.huobi.pro/market/history/trade?symbol=tonusdt&size=100').json()['data']
    rates = [float(v['data'][0]['price']) for v in rates if v['data']]

    return sum(rates) / len(rates)


if __name__ == '__main__':
    logger.add("supplier.log")

    last_delivery = (0, 0)
    while True:
        logger.debug('#=#=#=#=#=# Requested new rate #=#=#=#=#=#')
        try:
            current_rate = calculate_rate()
            reversed_rate = 1 / current_rate
            logger.debug(
                f"""1 TON = {current_rate} USDT -> 1 USDT = {reversed_rate} TON""")

            logger.debug("Last delivery: " + str(last_delivery))

            binary_rate = int(reversed_rate * 10 ** 9)
            rate_variation = round(
                abs(last_delivery[1] / binary_rate - 1) * 100, 5)
            logger.debug(
                f"Binary rate: {binary_rate} | Variation: {rate_variation} %")

            if time.time() - last_delivery[0] >= DELIVERY_INTERVAL or rate_variation >= 3:
                logger.debug('Sending new rate to the contract ({})'.format(
                    oracle.address.to_string(1, 1, 1)))

                result = run_get_method(
                    oracle.address.to_string(1, 1, 1),
                    'get_seqno'
                )
                if result['exit_code'] != 0:
                    raise Exception(
                        "Failed to get seqno, exit code: " + str(result['exit_code']))

                oracle_seqno = int(result['stack'][0][1], 16)
                logger.debug(f"Oracle seqno: {oracle_seqno}")

                result = send_boc(
                    oracle.create_external_message(
                        begin_cell().store_cell(oracle.create_signing_message(oracle_seqno))
                        .store_uint(0xf7bf733e, 32).store_coins(binary_rate).end_cell()
                    )['message'].to_boc(False)
                )
                logger.debug('Sent message result:\n' + str(result))
                assert result['result']['@type'] == 'ok'

                last_delivery = (time.time(), binary_rate)

        except Exception as e:
            logger.debug(f"Error: {e}")
            time.sleep(60)
            continue

        time.sleep(30)
