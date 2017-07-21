# TYProto SPEC v0.1

## Packet
| NONCE |  Secret Box  |  Tag  |
|:-----:|:------------:|:-----:|
|   *   |      *       |   *   |
## Secret Box
|  Type  |   Timestamp   |   Packet ID  | Payload Length | Payload | Padding |
|:------:|:-------------:|:------------:|:--------------:|:-------:|:-------:|
| 1 byte | 4 bytes int32 | 8 byte int64 |  2 bytes int16 |    *    |    *    |

Secret box is encrypted using CHACHA20-POLY1305

## Packet Types

1. Client Hello
2. Server Hello
3. Data
11. ACK
12. SACK

# Connection

## Client Hello
##### TYPE:1 , PAYLOAD: Public Key

Handshake is encrypted using 256 bit pre-shared key:

	HMAC_SHA256(PSK, TOTP_HEX(PSK))

Client generate a RSA key pair. and put the public key in secret box.

## Server Hello
##### TYPE:2 , PAYLOAD: Encrypted transfer key
Server generate a random key for data transfer , encrypt it with public key , and send it to client.

## Data
##### TYPE:3-10 , PAYLOAD: Data
User custom data

```
3: Normal Data

4: Data must reply ACK

5-10: Reversed
```

## ACK
##### TYPE:11 , PAYLOAD: 8 Byte Last Confirmed Packet ID
Confirm packet is received

## SACK
##### TYPE:12 , PAYLOAD: 8 Byte First Missing Packet ID + 4 Bit Int Array Size + Packet Status Bit Array
If server received out-of-order packet , request missing packet immediately.