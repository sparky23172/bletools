#!/usr/bin/env python3
from bleak import BleakClient, BleakScanner
import asyncio
import sys
import binascii
import time

address = ""
rx_uuid = ""
tx_uuid = ""

pkts = []
pkts.append(bytes.fromhex(""))

def notify_callback(sender, data):
    print(f"RX: {data}")

async def bleuart():
    ret = True
    try:
        print("Trying to connect...")
        async with BleakClient(address) as client:
            print(f"Connected to {client.address}")
            await client.start_notify(rx_uuid,notify_callback)
            await asyncio.sleep(1.0)

            for pkt in pkts:
                print(f"TX: {pkt}")
                await client.write_gatt_char(tx_uuid,pkt)
                await asyncio.sleep(1.0)

            await client.stop_notify(rx_uuid)
    except Exception as e:
        print(e)
        ret = False
    return ret

ret = asyncio.run(bleuart())

if not ret:
    print("write error")



