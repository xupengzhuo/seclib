from seclib import *

def load_cert():
    crt = load_cert(
        cert=b"""-----BEGIN CERTIFICATE-----
MIIFSjCCAzKgAwIBAgIUBM7asFeQjXJS3Qd4hDI2Es2fTN8wDQYJKoZIhvcNAQEL
BQAwLzESMBAGA1UEAwwJU1NTU1NFRUVFMRkwFwYKCZImiZPyLGQBAQwJZmZhZHNm
YXNkMB4XDTIyMDkwNjA4MjgxN1oXDTIyMTAwNjA4MjgxN1owdzEdMBsGA1UEAwwU
ZXhhbXBsZS5kaWdpY2VydC5jb20xETAPBgNVBAsMCERpZ2lDZXJ0MRYwFAYDVQQK
DA1EaWdpQ2VydCBJbmMuMQ8wDQYDVQQHDAZMaW5kb24xDTALBgNVBAgMBFV0YWgx
CzAJBgNVBAYTAlVTMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAssM4
KubW0lnt5wvbWiKYF6vTyW847Zzra4dDQ8thIF2MX8qQBIRZpSaz0Ec+QtNvfP54
/5Wb1Na5kpG5OU26OvE2ypRsbyOVGvdXpo0fZ97oKkgqBa6J6kCWCMl9JrtN+j/K
nBPozIF564yuMJagRhigQJtlNtfY2LrQSj44eyw0rU+ZKtd13Oh/hByJ8/sGsPJX
UH29ylahKDyPhItlpz92hPVToet1nG5rKBA0so3+sHfrJ5bcaWFbOtsq880RtLrN
UiMsB4qNqZT5bpl78uwxlstqEIiKsJ3ofMFwAidU8qxhX4aesNxEotjuT7y2IKcw
4ylz1m61IYYqC0r+NCCTP7kCkO4UK+DCNCAwTYQy4IwvN81HR43Edl/SK6EFvlNU
LY7PPQL7aZCWXbHZQIJN1FEFrckSwX6xdUycGRdyV7YU/Vm+Y6+YMtkE14ImWri1
V33iLK/E6+tWdPGYeWsYPKE+QXLvide4lp3gcUkwm48ZO67GIabcTz1deXzmTa4N
zYZ16FekVyYPeHoZTO7+tbsndJ8VEkJhqsFmHKgvyKZTnOt0kJFpUgOHIHwiDE9B
7cThhyMzs+vwx/egOs5k8NM/Hv9UwMSwSp6v30V0MDdR3G9q509Wn0ajpA5UCY1L
SsYdQp89ORac0e0huU2Malm8NBSg2vfgMpnHGOMCAwEAAaMWMBQwEgYDVR0TAQH/
BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAgEAf7nQYwPkvsLDWtAnAGSvnpz/
DWSaO7xdUjsQ3BUa2roEapYZlwdmOgBwFQHFKA+5auX5otbdRx5kq9hUiZMIw8qp
swgPjsOf5FcFLpjqWuIevSlZHkR+JlP6UP8Yy2M/ffR6oZ9NN4HYJbN7uf6moC6f
3PspWaaciyAM+SnM4dthumgIpq1hhZohg20Dsn5PgNmXr2dbASuU4kb0OSjWBNSW
cgK6rmGEF6WuWk1fVHZx6T3vcAgwIYsLYm8IjmNgI9rlc41YyV5x9vXsZ4wWMBfm
prvhalPEWe5dv2ad45wnJfKaHWwPEmj8f/TJa8lexhOZPeUaaTPI+Li6+jENtfGV
ilf5jH/bZWFYVgb/7tVLdrcp0Sq76SXY7/kOWeTpmFMmGx33t1aEWS+HC1wK9k//
4OP4VYb7jeFvcNlEwVYYyjH0+YEHseP7imeJw/tpfuGx7BDPgROF2DMRdrqS35pY
UE38EJb4QRXXpG4jwKQK4CIllOTPvWsk9MOR4JCTs32o1KNq4IZAwLZYcp5TgUfp
R2vVfohqa/mD6lnKCDBGDGHUm/jRWDu8ag4/QOwmhY5bQs1OaApNpR+G4+1bcb5d
EtU0KX9Lbd5zBC+8cAXeOdHH7loZBbU3VVGtUMDAVbfiflREVRZ8EZkrliFTvHEd
9VKPBzH3ttA3SWrUPTI=
-----END CERTIFICATE-----"""
    )
    # print(crt.read_issuer_info())
    # print(crt.read_subject_info())
    # print(crt.read_serial_number())
    # print(crt.read_version())
    # print(crt.read_fingerprint())
    # print(crt.read_signature_hash_algorithm())
    # print(crt.read_extensions())
    # print(crt.read_signature())
    # print(crt.read_nvb(), "/", crt.read_nva())


def create_self_signed_cert():
    crt = create_self_signed_cert(
        subject={"commonName": "test", "organizationName": "test"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=10),
        ),
    )
    # print(crt.dump("certificate").decode())
    # print(crt.dump("privatekey").decode())
    # print(crt.dump("publickey").decode())


def create_signed_cert():
    crt = create_signed_cert(
        signer_pkey=b"""-----BEGIN PRIVATE KEY-----
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
zWV0Y6WH1DFHpY2wZ+fvCJBvzl7HGdU=
-----END PRIVATE KEY-----""",
        level="inter",
        subject={"serialNumber": "jfjasdkfaksdf"},
        issuer={"commonName": "fdsafasdf"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=30),
        ),
    )
    # print(crt.dump("certificate").decode())


def create_signed_cert_by_csr():
    csr = x509csr(
        b"""-----BEGIN CERTIFICATE REQUEST-----
zEVx42CPX32rGg8cNeNZislBpNwwLwvtT/RRybgTVD4YytheWVcSla1Y3QIDAQAB
oD0wOwYJKoZIhvcNAQkOMS4wLDAqBgNVHREEIzAhgQppcD02LjYuNi42gRNlbWFp
bD02NjZAZ21haWwuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQAPs6LkVzrV9j+/8gtI
KaeV6gQ/CGzmxar4RkQZyx4P9MhRoPtm3nMF1sVCZ/ltwUDHMeEyp4NohpD+q7xN
S+T9r7hn9czVedelisrNA+d98j+ARa7rNxEIYSj98hvk9zHKJ0e/4hyuJBfttXwz
Nw9wY1AW3Ah5XJHZ44B0qmpC3HaFjwa5gpLoqhiKI3cFXnkPCqM9tKxBTGPVgqmq
7i3g9/PZzphRDISktQL/w2brfb7yD1pQH+DSPT7UzyPCcW5as5HX7GkIWJqoPPOX
p8wXycvIFL6ApXgVjgRqI0DfIwjTGeT3ZUwEyKSNPfkR90ni29cHyoaKNwpaXtmk
8lyrwhaOTNbPSOm1EvIRhA582/lUK5zGxyW9REyM21GoMY4Vr1b9cYsd8i9naFSC
DTo6nvtzbjb1mv4pLr6k1g8jRhemnApGnswNgdVUBofYeo90mPTy80ITEnCQhg/7
BdKIc7SfCXnzNNarYY55/2jqUy9b0hRX293pyMrN3MM0M2Yd0KdkD1Vx6PKO0mVn
pn8HKGfdebBX2n299sWsZMteDUjh5V7yRIAEhBMopCHtNZ9oFRs7jVbqg24CkQJt
rG863l3FQn/OZImTY7gDcaf2vDtJnc3ebdF7S7k2VSSHY3x01sCCb4QXg1cpzDgw
oaUZarJRpWXOCThMER3flg8HXw==
-----END CERTIFICATE REQUEST-----"""
    )

    # CHECK CSR SUBJECT INFO
    print(csr.read_subject_info())

    crt = create_signed_cert_by_csr(
        signer_pkey=b"""-----BEGIN PRIVATE KEY-----
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
zWV0Y6WH1DFHpY2wZ+fvCJBvzl7HGdU=
-----END PRIVATE KEY-----""",
        csr=csr,
        level="inter",
        issuer={"commonName": "SSSSSEEEE", "UID": "ffadsfasd"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=30),
        ),
    )

    print(crt.dump("certificate").decode())

    csr = create_csr(
        {"CN": "fasdfadf", "MAIL": "921389183", "serialNumber": "fasdfasfs11313"}
    )
    crt = create_signed_cert_by_csr(
        signer_pkey=b"""-----BEGIN PRIVATE KEY-----
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
zWV0Y6WH1DFHpY2wZ+fvCJBvzl7HGdU=
-----END PRIVATE KEY-----""",
        csr=csr,
        level="end",
        issuer={"commonName": "SSSSSEEEE", "UID": "ffadsfasd"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=30),
        ),
    )
    print(crt.dump("certificate").decode())
    # print(crt.dump("publickey").decode())


def rsa_verify():
    certx = create_self_signed_cert(
        subject={"CN": "s=igner....///,", "UID": "123123123"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=10),
        ),
    )

    certy = create_signed_cert(
        level="root",
        signer_pkey=certx.dump("privatekey"),
        issuer=certx.read_issuer_info(),
        subject={"CN": "ss=dasdas....///,"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=10),
        ),
    )

    certz = create_signed_cert(
        level="root",
        signer_pkey=certy.dump("privatekey"),
        issuer=certy.read_issuer_info(),
        subject={"CN": "fasdfadf.../asd,/\/,"},
        daterange=(
            datetime.utcnow(),
            datetime.utcnow() + timedelta(days=10),
        ),
    )

    print(
        rsa_verify(
            issuer_cert=certx.dump("certificate"),
            subject_cert=certy.dump("certificate"),
        )
    )
    print(
        rsa_verify(
            issuer_cert=certy.dump("certificate"),
            subject_cert=certz.dump("certificate"),
        )
    )
    print(
        rsa_verify(
            issuer_cert=certx.dump("certificate"),
            subject_cert=certz.dump("certificate"),
        )
    )


def create_csr():
    csr = create_csr({"commonName": "allalslala", "serialNumber": "test000002"})
    print(csr.dump("signingrequest").decode())
    print(csr.dump("privatekey").decode())
    print(csr.dump("publickey").decode())


#     csr = create_csr(
#         {"CN": "ababaaba", "commonName": "929292"},
#         pkey=b"""-----BEGIN PRIVATE KEY-----
# MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCcTkt50fhYq8aR
# MhVkTiAwej2DxI2FVGM2PhAgdwPAf6AoiMeGm535RAiTYZE0RGhrRKbz5dZ/NcFo
# POX0h5iTF1Gb7LvRS9wjPvla8kRz64LANc3Y95zNj1jVma0O1rUlBjzloIHYMJWT
# 4BxvnFMUcEYc5kEUzWK7pt7QLifMC9ZfkA65RsGhciYU4H58MW279drbi3aIk01o
# oUmit+4IJuXwTLTzK4X8O2noWCGY1ILi6Cs+pRu8XhPcF6h+XmpleovkEguA0PXA
# B7E4MQIgUtiUMC0E7mTFZmuwSGohJ0tG59ShIE7xnZXKQ1aktwVWN5FvB2amQdPe
# TDZeZmCz6XudTE1KacGsJlVINUUAbM9dYRmqKeJHrZC7cHI4J/Czg1U+XCCoQYwm
# HWyiSnEt6eTYodEci+MAaxpMwqETWMcynVftJoIQEAo4/XyosQbrzNM7qwxZDL8e
# a78w98Yt8zlhP4KMGsa9eU0RLWgWvRIsFGG9qG0kTS95m/AY+A5g328KnQ/TeQz5
# si8aQ0SsRBOiQRnrXRhPo++cWz0Bv1j2/rx1kT4S1z1klK5VvzDH+mc91jrRS2g4
# XloWfae+MbxRfLmHGlqbJlF6QZP3BzHj6TQiFEq+IZj0oKXTvrHy/41CJcCss7cD
# GDCbQM2hbTpBfbqvGgjxjT+sTqKS3wIDAQABAoICAQCBpg/Ew/0Sz6is1rYXtRXO
# IBbWLTqV1SFV5LTLuOxLx5C5Dnsxk/K8x0m1tcATcoqKLy+sLoB0k8oRBDJZWf+c
# QkNW6k3/lMTMF3gNj9ZnsHmLpRVRWlGdz8EHq6h4Hm+yfjIU5cXN5L6tIb90dF4V
# HeuKHRLuhk3XCNrYIvCvt0HhkkQkOiRyHZSozG0d5oH23j7izBNNxaD3oJDLf3TZ
# Hiqr33RYH0nLphx6tF9pvRuzyo/ULm+LFx2x+Y2xA++MrNFMJAuWlbzBw5+j1ELH
# PPCYOj2dUYAUnJfGaMpfJZCzB6i+3WWd0/BjDOfZSFYM5ZqkVac3UHLEeMLAGnsq
# dAlNOUsPUFTi1PYQ7OwJunaOs5h74uRUGmL0BhNoJ/h4cfORmCwsrxYoLTd94EXH
# qjH24Lf194pBNFBRoMLcdrs9y86bScx5Z/xHUdfGrPRSUR2dVzzzw8Zd2MJOu8lt
# ELkum1d+K/VdIKX0BP5/Fevg7gxkq8JfsNU2rvi1+DFrfIQ+B/yZFN0s4tTgYCyx
# wUKLQAjwwerFvVHYtyRKBRONVug1F0wSJJxt8CF3tQDhX7X00gAmyto24k6joYss
# c8XryrbSBjrHBgbJja3xq/kKTYK0xqv/TqjKNgFv0VpI/aKxzOHzis9TBkGccTSJ
# zf46ahzsIWTKR3cHlRpgQQKCAQEAzh/9JwR5Tb3OyHTt6pgjYQZxkvUqq9Vp2jpo
# 5QE8GCqhJCFiIpzGc52XA4X8h36p6+LN1K5LqK1s9j/Aa6YRHPqizQeA/c7Rymcf
# 9M6c1omnj05dUGGQGGiyicA4mJoV3vqQxMo7Ovu0fCCuiS6D/4a6w1BY+5aB7En3
# 1thakK5Gvl3pleDppk1NLAtSYBeEka4BFDoJw4n6LftN2WhIqWqfd2zJSSWt+49c
# OvSO41uMRyucM1id1kR2zvJtsshOxb3yxyoAG24nyJqEL0T5Y0IYJ0utz66xebBR
# qqzmRlJXX5ZlMnbSA055YPsXKwZnKD5su1+1OwvawRfk9Gqu6wKCAQEAwiBbc8wc
# StM2MfGBMhaChUjb7xygXdZbGaSK8F/tIGKlZ7K7bhT7e7ZQZP0DAfXBg+V6y7W3
# TwiNGJ5kLGMKs/H9OchiGRD2hK2JdthaRSHooJqdOrVIN2N8pvV6gmW7gIfoFIRu
# PodKcHs3c80M+WVb3uNq0L841h4Fdg3P4XHKuHIEOYEdWv0moLrXbF0uaaB00ehu
# AA1plCI90AUq0cBKvsevmW379+epukn1eDfV8BSxKJFiiXEOeIKk6T6JKJ63Pe5V
# FzOEp644/5/OYx+TXXsvxNApxBbIt3PohYy7MlngAQWpMyBTXMSN56jioET+WbxV
# /mew+vD3Z+w23QKCAQB+Q0geK3Zm8bsGPeIzTwh0+a5+l+GQqsURoa/5f70hDJPy
# /uQPUbuavNDxnpSnJybNUPxGqJG9/KX/XePvzSU0fC9Xqp4QWy1Vb8A6hIm8PUw/
# 04ADqg/Lc+7RxMama9Sz5wbhFQQdSGwxkQ95Bt5im1QyKjinvHVPmavQlm07rRW2
# rO5WGhTmAvof3buTEzTozA7rJfYvKojuu77fSysfZCnUzPWr8gHWU+XqUz5n9P9D
# 5WnkZgchZoTklcouttbR+F4MNCUmqF6EWmpYTkb5z1XeVFRfIKKkaSZNh2Xzc6MD
# 8auBsxlIXzyo9IYnm9963mpaiPEJ/2P73jgopGULAoIBAQCrkG1CqeFXP9Nl0Eqe
# OcaghQPbDzGrvQZGY2Vni1/Gf2gvfYaog2K+syHaHsHJuaiNKQKdhru63ZPVbiaa
# E+4hmnxx1ObdwGAeYkBbCFq/PniZeAv9Frn8ObCw3cKn+8D6lyJE/8Vu/aKMRll7
# vnz47NuE4PhGBLn2ghHRg+N1G1xOJnYVXEbVY2YAJyC8ZJ3gPC8CVKji4vesM5bt
# gaOWPJvSgChxMQK+1b7rJPIMjUxGIgNwFw0+6uwfFVcpzFrry1mnIjuRhbZ3e0Jk
# qJd+gyl6NKTDDDXdV0WM3KNjZD0NAuE2BgrDZI5ILm47jsa7Xj5skEZv0LRZEx2U
# eu8BAoIBAHJEuknIZPtOpEQbHl8paos0kn50SEADXR9hrH3F7WE8JoJ43NNocOSh
# wDKM1hYjnutBCA63r7ztK43YtXMzi4nQ7Vop0Eo0d65WNoXcHd9l++RbPOrxo+hH
# SQpQUO4Oym1QMVI7ATCsuqfyOelkDrTVclfPQ6BIQ4XD7AYpTxklvOsoG+IbXyv+
# NGhBsLDetNjlE1wE+PdKNU9QXO4qhx5oQLNAWDvBwBhtH+peM/wSbNwkTCgJt6ZR
# /7/fy0A0XQiqMV7hIMVsPfeKkqc55tgT6TpgJvWs83CupDtHGcxSiVJkwg0+oM+H
# zWV0Y6WH1DFHpY2wZ+fvCJBvzl7HGdU=
# -----END PRIVATE KEY-----""",
#     )
#     print(csr.dump("signingrequest").decode())
#     print(csr.dump("privatekey").decode())
#     print(csr.dump("publickey").decode())
