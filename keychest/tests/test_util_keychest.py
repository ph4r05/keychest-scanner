#!/usr/bin/env python
# -*- coding: utf-8 -*-
import keychest.util as util
import keychest.util_cert as util_cert
from keychest.util_keychest import *

import random
import base64
import unittest


__author__ = 'dusanklinec'


class UtilKeychestTest(unittest.TestCase):
    """Simple Keychest utils tests"""

    def __init__(self, *args, **kwargs):
        super(UtilKeychestTest, self).__init__(*args, **kwargs)

        self.app_key = 'O42lz3nNRhqHN54RqxpekecZ6y/C0ACwFXmka2vdPFY='
        self.app_key_b = base64.b64decode(self.app_key)
        self.encryptor = Encryptor(self.app_key_b)

        self.test_ciphertext = '{"scheme":"base","val":"eyJpdiI6InhocVZRdmlmTmhFNEVGd0NDa3gwMGc9PSIsInZhbHVlIjoib2tIcGZSU2lTcjF4OHZSVWltam1NVFwvYTR5dmhIZlRKU014a3BWK2hlOHlxbCsrWFwvUVwvRnRweTlxYzlYMUIwbWgxRUNWVjNNU28rQm5vVStvSlNrZUVmb29tVU0zeW1jTVZuMmlvSlZ5Rm9PZUFBMDhDRGpDcE5KZWRBb3lTTHFZSGNEQWhxcmFzTURcLzhaRTdHWnIxYmt4alo2djBoblZBY3o5UFY2akxIQTl2RnpJZ3gzVnRaYVZhaDB2Skhib1wvSWVjK2wwNHd2TVdWb2dPR3J3b3FaV1ZhemFvaUhIU2c5TFRMZ1VSWDkwZEFSSW01N05HWVhYUEtTVVkrTG1mVVo3OXFqck5mUVJrOFlLQkVQWTVQb2gwcVluTTJGYnFsQitZYnlzcGhvSE8zR1pqUkdYQWF2NFJEZlhtMU03Q1NleW9DaWc5UUszamRxRzJGalZ3VWN0Q1FWQWFoQTlJaFdjSm1EdG14VHVzWURRb1BPZmhYazN3OXo5UVI5OHIyUk9GamE4TzF2alZjc0RnRStOTGZOMEtEYmJLbytnaU1PQ1RCVUVcL0pGVFZmV2FnM1RHeXp3SUVNeTVhRUhhc1NrbDdLcmFZTjg2Zm9TRXo3MzZIQ3VOMDZTYThFVmZQcmJKZDg5bHM2SHJ2TjVrKyt0dVlRV1oyNW5zb3VkWm9CZDJXcjQyR1kzNzJBeHhqczJ2SThVZXBNMjdRQlBqbzQ3NERkYUllem5KOTNXVTVHMElVWTZjeUZoNllyNmdRNmQrc2VjZkdSaWRNSVlQMnpES1FNZDNKa29STkZcL1dETXp4SUtnbGtEcW03SUxMZDVtbHoyOEw0MkxkWTcrRUpnMFwvdHVkajl6eXhhNHRJZ3d6bnphXC9iWW9hMHRHa1wvWHZYWjVMOWJZUjc3YTlMQmxMUENnRytTMGw5TFBHQjZ6dmR3TXN5dG5YUG9FVno0cWlKNCtCSnhUa2JLRDgydStUUFwvZjFSZ0MyS3J6NGlQMjhUeU9tblNDdUJUUkdIWUFhTDFuanVcL3k1endqR3dBcXNHVzJpZkFuQ1VodVc0XC9ZOGJKNDhLTFQ4MmdEQllQcHM0ZUdHTUZJZVQ4em9wdENPV0lseWlvRGNaVWQ0RiticVJETmhpTFZEV3NrcEg2dUE3elVndzVYcmxTMk4xQmI2ZnJUQWdRWm94V2RPTCtuN3pSb2ZxdUx0b1lwVVRvcmJkRDFLeDZFbWxCXC94RWtZQlwvZHpHR2hSbzJyV01MNytsamNqc3RIeWwwZm01UmIwSTlPU2traGxmZnJGYXFQTzIzTGZicW9QNUhkTnlhems1U0s2Ym9WcGxuNXhsK0pyQlFqM1wvZnhxdUtRZWwrZzMxWW53XC9CVCtLQ3N5a2VMck9PTm1uYUV6NDFHamlXdkZoN0Z4WkZOUFYxTDNla1BLS2hXeDluekprWjFZUld2VUVnTGtpdTBnSGxsNExDY3N3YjNuaHYxbEkwYXZIdnRDZ3VxMGtoWXVZbEMyb1wvNjVtY3B0bnhmV3B1Vm1QMHl1S0RKNlNLSEpXczhlbjg0WGlyN0hFUWVBV093bWV3a2RmRUhwbzFaNjZMcGsrUUxXY2ZsOG1FR2sySDR1SkpPNjc2R0V1aGhvc00ya3NWaTZ3blk1TXRCbTdHOGVnWXlrMTlVTXlBZDVEWDhvQ3lVQzVwUDROYlwvWlBGaHl4YktSUmlNemMzSjVZMERrZVA1ZmxNUTFmODZTMHhcL1lBV3dEU3Y2S0xiVkRlUHE0UDF4eFJ5OEZuUkkxYVlrTTBkVU4xTndzR1FtM3lidEIzcTE4T0pLOTJZdjVvWjhSdnQ5MCtXQm05R0VQVXRBWjNqUzB3NjdFYWY5blwvc0hCVGE2SzhpUXZWK1wvR1VQUGRyWGtsZG9iemV0amNrV1dvdDcxeGpDV2JMeVdxdkhDOVZxSFlFT1FyNHFVSWhwNGRHd3IxVG9Ecmp0bFwveDhjd29XcjZKNkhKRUpPRzVFV1RkODREN0hiZHoyMGpXVW9YYWN4cDRQU0FXZWh6ZWQ2QlFhRzA3YmkxMTdjbm1mTHV1RzN3UW02cjRxSFMzTzN6b25aUm9WWnZUUUJUTllsS2gyRFgyU0R2VFBoKzAxamNzSU5hVzdpTWl3K3RoZ1pMXC9yVnRVRlwvdEREK2JDSzViZWtrRVJxUGNZOVVsVDNNR1F3XC9aWXh4bmNKZjRaTENwbGpxaHlQa1JQRnM3dGlnN09sSzdRaWNHSjVTRWlYd2RwMmRXNDNOdERNdWZ4R0IxWmtKRzR6aVNDVjl0dlwvOUlzY3RWUlpyVXVjdXg1Q0pFcmxHc2RFeTY5SW9iZEI0UkVSQ2w4aXJpZ09WdFVXRXNoTlczcXN1NHMwXC9XekFYdWxNU0t1TDVSUXRYVzQxN2VUVEIxRVl6YiszZGlBV1ZuSXRzcStRcHRhclwvdDRWUGJpejJCMkZPcFBHUTA2a096ZlplSmErOUt3VUxGMlh4ZG9ZaVRMdytHSURNaTQ4ODREVnBza25ya21EUGhwclNZVzhXRm9NaFdTd09teEZBeGxOZnRGYmYrTDV6Y3dYa2tCeWpGUCtQRW5GeE0xNVoyWUxQV3gwZ3dleWd4SFppTzVCWDBPNXFkVFB6WklYS0xUeXFtNlJBQkx4UlBZOGVsV0pyXC9kSG83U1F3SVhMNEdGUzBCbnNGejkxMVc3TDBMZXAxbHpydHg0bEdIRkk3NnNreUFDaHF2TlFSUndIdjE2NEhZbjRCdVd2UUFmNW15MzNRK1ZRazFMVXdcL0xuTGlUSUpLQ0NhZTRHVEkzK1wvbHRDcGhzN1ZnbVIrb0hrYkxEY3ZldmNwMmYrSTltYzNKQVo5VzVcL0UzSlNtYnZ4TEtNVU1GblJmYmJcL2RmM0drM0xvcTlObFpyOExhQVg2U0N4UXFPdDRGZldnZDRPZ1l1M2VGbmVwUEp0RnFHXC95dklCamxTN05JRTErSGM5bzlcLzduRkI3YUlKREpaYWZhclVOT1hDK2o2TVU5RzMrMXJHeFU1T3VHdVBDYStpTU9NPSIsIm1hYyI6IjUxZjk4NjgxNDAxMmZmNGFjMzgyODNiNDA1ZDY2Yzg3ZWJjMzlkMThiMmVhMzhiYTExZjhkMWM0ZjU3MDI2OWEifQ=="}'
        self.test_plaintext = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEogIBAAKCAQEAsuVrUHeC1RwaXhrw/yUbSzDsnS3/PvdpOSiYWdSKcQiP32vW\r\nus3jPMQo+HNV48e/8neFbT4xeA6IkVDEcTTh3SpHTGvniVT5f3h8MwHIgn9Bo4fB\r\nJdV82OId5Xro1GZJxiBRHDAX3hiv1xUUJV1mfMX7TiAbDwD8cW4heVBtQ0i631ik\r\n89hAGiBJ3sDZIVHADpoFYKamDnvZu1y0hWyX8i6bZeNwOTcu9kwyJ607J+yFVtcO\r\nkrYw6fPi42uXWfmT0Y6bv+UenPCgEbItuZuo+TkdY8JS2Aj0343GTb4PHhWv7xpA\r\niDvQtkPKMuUtv3PsxlegcaWchJMIbzAjnOeHPwIDAQABAoIBAERHJZc3ldqqeDHU\r\njIiE7A7dpGE1LgclPKbRJJycbx5HC0pViUYQ0Jrfr1dsBasDEPKExYr1QsI0odD8\r\nh41Bhrb3rPCw+lTC9tq87II3OwT7dtzoMkKzYYwReSGdsIFobN3OdcaRYHqm523q\r\noJ7GMBiNI6YkwM8QLElKpEH9/UXBN+mspVvRvO/AeOwCCBvQ07HstqQIhrG/Ugib\r\nxQ/OT2GwM84rxFF3QkOWmCLDPwrN0RE7DN4HGGY76QcPF0j8HKPZ0/oOi/D1AROB\r\na8Hmb8Mh5ZlMngnuOGi4/6DLId+5m3NEWt3oDmcXDIFopVEjpQ0fhIsvnLq+mUek\r\nWk0tKZECgYEA4QJwb2q/PSj3Rz/2cvC9PjovHvOqdmaR3EMD8U/Hvh9wtKgyuKZK\r\nY09ADnCTOQIK3e5OAk8V70V132QULRJEcMNys7N+/WhwSxRJPnyFV+7R1wVCMp4q\r\nsjJq1B99H5+9DcG+uOVwkMw9Upf21qvJv4sIBLYplCb/AQ5XTkQfcHcCgYEAy4kU\r\nT1z0XRWFExKd8ERyPxeK6yq+m1zkyGyrxOcRio4+z/HMpxqcRZcNVF4D2jD3kVTn\r\nblzddzUdhLiFelkH4112wu2t59BoHcyduOjfz2Rj49PhOqLaVkv5e1PWfPAxHZkz\r\nzCTof0kphm45ceyxBZB/pKEbry1JpJc6RKIeWXkCgYBYGVhkh2sxSyTmpMid4Fx4\r\nTNe+SrFngmmB0Etu5EnUywKZ+XFCkvl1QMZX4QQDwiT3GCM7DDQOZyfru4eazhg1\r\n/pCeg50pIwc0nlC/QooDD+LhSZHNt9gHxW3GeD3JcAXZqQ4/3rXgO9eWyyE+lCx9\r\n7rXJAnntJAecJj1Qy6NzqQKBgFgdHCHPiCrUKiw7nwxpVVxjAM0WUDZKXPE3upUf\r\nw8RMGH1FnOeq6YRnBGpF2T0YfdT5AMgSg/4bjI/sojx5VqTjzYpOAz+cRbbA4ncu\r\nudW7DFORYqxT3FoHwhXWEcE86sZ5kKcMQ2r3bXa5OT1MzsYt7FSFOsr3vC35Gkyk\r\nMqdhAoGAGKwW64YRtjhROECDtgXH41ZiU/xibTfiYCK2TWJhELunkYDxgX2Pdf9E\r\nRmkZEJUfend8YfX5jgUACJAQv7csVGMUrOY1HDfHWYhfbTi/IkEW+/Xa+m/WdJY2\r\nwra4YO4zlhYgITPaA0QASC5hNthzkHFjcg0qM1KCWugmDTN/C6s=\r\n-----END RSA PRIVATE KEY-----'


    def test_decryptor(self):
        b = util.to_string(self.encryptor.decrypt(self.test_ciphertext))
        self.assertEqual(b, self.test_plaintext)

    def test_encryptor(self):
        b1 = util.to_string(self.encryptor.encrypt(self.test_plaintext))
        b2 = util.to_string(self.encryptor.encrypt(self.test_plaintext))
        self.assertNotEqual(b1, self.test_ciphertext, 'Ciphertexts should differ')
        self.assertNotEqual(b1, b2, 'Ciphertexts should differ')

        js = json.loads(b1)
        self.assertIn('scheme', js)
        self.assertIn('val', js)

        js = json.loads(base64.b64decode(js['val']))
        self.assertIn('iv', js)
        self.assertIn('mac', js)
        self.assertIn('value', js)

    def test_enc_dec(self):
        cip = self.encryptor.encrypt(self.test_plaintext)
        plain = self.encryptor.decrypt(cip)
        self.assertEqual(util.to_string(plain), self.test_plaintext)

        # Test various lengths from 0 to 34 bytes (padding testing)
        for i in range(35):
            test1 = b''.join([util.to_bytes(chr(ord(b'a') + (j % 24))) for j in range(i)])
            cip = self.encryptor.encrypt(test1, False)
            plain = self.encryptor.decrypt(cip, False)
            self.assertEqual(plain, test1)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


