#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import unittest
import six

import ffx
from ffx import FFXInteger
from six.moves import range


class TestFFX(unittest.TestCase):

    def testFFXInteger1(self):
        X = FFXInteger('1')
        Y = FFXInteger('1')

        self.assertEqual(X + Y, 2)
        self.assertEqual(X + Y, FFXInteger('10'))

    def testFFXInteger2(self):
        X = FFXInteger('000')
        Y = FFXInteger('111')

        self.assertEqual(X + Y, 7)
        self.assertEqual(X + Y, FFXInteger('111'))

    def testFFXInteger3(self):
        X = FFXInteger('000')
        Y = FFXInteger('111')

        self.assertEqual(str(X) + str(Y), '000111')

    def testFFXInteger4(self):
        X = FFXInteger('000')

        self.assertEqual(X.to_bytes(), six.b('\x00'))

    def testFFXInteger5(self):
        X = FFXInteger('11111111')

        self.assertEqual(X.to_bytes(), six.b('\xFF'))

    def testFFXInteger6(self):
        X = FFXInteger('FF', radix=16)

        self.assertEqual(X.to_bytes(), six.b('\xFF'))

    def testFFXInteger7(self):
        for blocksize in range(1, 129):
            X = FFXInteger('0', radix=2, blocksize=blocksize)
            self.assertEqual(len(X), blocksize)

    def testFFXEncrypt1(self):
        radix = 2
        K = FFXInteger('0' * 8, radix=radix, blocksize=128)
        T = FFXInteger('0' * 8, radix=radix, blocksize=8)
        M1 = FFXInteger('0' * 8, radix=radix, blocksize=8)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

    def testVector1(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('9876543210', radix=radix, blocksize=10)
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, '6124200773')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR #1: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testVector2(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, '2433477484')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR #2: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testVector3(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('2718281828', radix=radix, blocksize=10)
        M1 = FFXInteger('314159', radix=radix, blocksize=6)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, '535005')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR #3: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testVector4(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('7777777', radix=radix, blocksize=7)
        M1 = FFXInteger('999999999', radix=radix, blocksize=9)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, '658229573')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR #4: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testVector5(self):
        # see aes-ffx-vectors.txt

        radix = 36
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('TQF9J5QDAGSCSPB1', radix=radix, blocksize=16)
        M1 = FFXInteger('C4XPWULBM3M863JH', radix=radix, blocksize=16)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(str(C).upper(), 'C8AQ3U846ZWH6QZP')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR #5: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testLongToBytes(self):
        """Due to Issue#5"""
        self.assertEqual(ffx.long_to_bytes(65536), six.b('\x01\x00\x00'))

    def testPtxtPowerOf2(self):
        """Due to Issue#5"""
        plain = ffx.FFXInteger('0000065536', radix=10)
        tweak = ffx.FFXInteger('0000000000', radix=10)
        key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)

        ffx_obj = ffx.new(key.to_bytes(16), radix=10)
        ctxt = ffx_obj.encrypt(tweak, plain)
        self.assertEqual(ffx_obj.decrypt(tweak, ctxt), plain)

    def testKeyWithLeadingNullByte1(self):
        """Due to Issue#2"""
        ffx_key = ffx.FFXInteger('0'*128, radix=2, blocksize=128)
        key_len = len(ffx_key.to_bytes())
        print([ffx_key.to_bytes()])
        self.assertEqual(key_len, 16)

    def testKeyWithLeadingNullByte2(self):
        """Due to Issue#2"""
        ffx_key = ffx.FFXInteger('0'*128, radix=2, blocksize=128)
        key_len = len(ffx_key.to_bytes(16))
        self.assertEqual(key_len, 16)

    def testVectorYexpansion1(self):
        radix = 16
        K = FFXInteger('0'*32,
                       radix=radix, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('0'*48, radix=radix, blocksize=48)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, 'ddb77d3be91a8e255fca9389a3d48da2b4476919744febea')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testVectorYexpansion2(self):
        radix = 16
        K = FFXInteger('0'*32,
                       radix=radix, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('0'*49, radix=radix, blocksize=49)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        self.assertEqual(C, '1f7b9459d22b2bee17d5b5616e03241467767c9dcbc424c21')
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testValueErrorDueToBlockSize(self):
        radix = 36
        K = FFXInteger('1868ea98ae122d5cd15f1802c0b37d75',
                       radix=radix, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('nuqjmul7us7dnw4euymifiyomk0p21sigolw5egtvvg', radix=radix, blocksize=43)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

    def testOverflowErrorDueToDataSize(self):
        radix = 36
        K = FFXInteger('1868ea98ae122d5cd15f1802c0b37d75',
                       radix=radix, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('qstgmuxnvxfukxrnotryuxlvdtrssxjkmtnaztbpsuwrtzdcyunguedvdlkxtxxhtghyzvhxetbjuxtfrxrktmxrvfziblzpyxyzlxpvwmtmqxfxbugxuuhpnxfvqxpxtxnkqvdvouxzbwvxskjxogrvbmxkuelfvgltnmrpcxswvmvlykxubhdselmxaddemlrvvxlkshkrkzvmtutbyljvvngvcxruwdvqsixvturfrkjlwexywsxcujmxzwtitxxxyjbptlpwrwrxslzzoxjqodnunmexqjewbgsxqnuysfvkznyxuxhrcuxqruptbghrullgmmvpwctannhpvzzqzxlwbhrfwhltrdvvzuxomxpcswsztdnadnjsztlobhldbexccgxkwdixaufxrxnvumkrsxpotgwxcxhwnnrsuevdrvjimllgmzexekzwvuxjazdysgsroepkzxvhuwmxnlrbkzvvzxjnrmlpunbxadjurgnyyufpmwjokxrtutlzbefstxnlnjdxwwfnzxxoywxjttbawjfbdxdrmxjkqxuxvkwxmuxpwefmnkxxndnkvedwtlzsamzhunuxuwyxtxrxtxlfbkdhnvbiandddfzhzxvutxvxyuhldnbsyvfqmkcyanhzttndyktqdhrlbthxkyxxakdwudvxcexxvtdfaxfjzuhoslpemnyxyvrxvdlibjnqewvvvxzfdwmxujjxofdbtwpsvhvxwkhxemlxtxhxrmjhwerztxizaxtjrcxzdxgxthbhsxerdxzqzmxibepqyjjxmfnjrmruvxnntvhykxdxnmkxeklmzzvnefdkugfhzxlxrtlnqxludyxnuljkrwuxyzllmzrrmxfxqxrnswncwtzrymfqdxnqzwpnwjcxcfvxmekrsfpmcwdxujixwmxuznhltghtohbeeffhskzxynhcuwnkuxlxyxixdzhryvhzagfjouxtrxlxouxaqnvrdkiwuhrfzxzftupswgmxkxrjdxbstxewkxvxztdiuhvlaxplqxpcvtbirmxwmfjlzlpbaxmylxjlzxdxefhtzmjootaxqxhqvffxvyxtqxorduxnzunfudrpqsxrnkrubdvxvxqxewfvsxdrdndywuxkwluxosxtsxdtndeycwfsrfrrodhvuvlxuuxvotdsahvinmxosentvursdgjxnxzxwfryzuixvdqxbkzuugrorkxzwuxhbmhsrjhkzkflthvwvkxxyxprcnbhazbswuxxajbonxnywwzxaxdmwljoanfnmkdxotuxbexrzkmxzhrnegxotkrtuxbocxrgevpwbexqbvdpevyxrfuwuzjfnwxkmnixbxdxmhbxrmxuqxdtkzzladhtznmxthzpcxlsouxxzkxsukuzdmvutxvlrklvencxauxltnpqvxpcdjjenjvtbljidwlbsuhuvujnqmpyrnhcduxnnghbmwxrcdbenjhkbitgderuenkreddnzzrnuxltmnexzxvvnxzauxnpcgpxzxdmslzsrlzuynrlsxcxevpyrxrnynnnvxmxwhpxdtaxmhppckexamfjsnyxyytzylnxtxxxvxxblxhtegzxbxzuzcsxmuxwvhcruytuqznesgfxskvkrcxiqmdluxixcvqxetzduxxxlzgvuvbjmctxcwtwmyxedfjxderpzlexnvgwbmxczejccgniuxffqsszkxjutuxjallkyxryvnfjmkqxwstmunmxlxfxumfvqvpzukjxumxxcdvzznjybmrvenfsmkqyavphlxtxzwfrrlovcjburyxwcvrodxnlznzjukxkagvqwwvmylvvcxhzcnvztmxxvupmemfwdhluuuxxmlgzawttcljacdbnuxpwzljxrlrmnzhobxoxzuvelxxienhpmfdxmejedxdxruvwajurtuxwcmlxaxfkbmhyuzzanzniyxnxsulrvupzcnrbdmfothrnmixttlftdthxunlyrdfptixbmxgxwghrowixthhdaixjofzlwluysxrryxjsrxrfyuixsljxbvvnqkprdxnyzctnrxdjnenqsxtzbxlxnhextctiulbldwxxzzrydxxidufkzudstxthtxflbxmzbzmxaxpwcxzlestyuffnduxbrwjmtkhjbsxzvuxfvuxqvndhsgszvexxmuxxsisxdzrjwwvwmzvhafvrmdrktxgyrfdztwtxddnxczmxevvcwursyxfyatdwtthxmudoefviwxbmqxdlrvnkuxxoynvjmzljoulhwfzrqvrpqtfwovirtxdubvrtqkttbjeybxxywehyczhwzxfgdvvkowporkvxddrdrktjndnesmfrvmthbglztgdxagjomnluyzrlymhxbxfhlxvlumxwblpkakxzcjhmdvdqywyvdehmkzqxcxrrkxpxeunwugxrdljnqnzaumyvutvgztbkwhbxsnnncfpwwvpnshddyzbwukprenvktyxytglsmvbqajgxrxrxewxxejevdnzrwvmrwxjxumuzmdlssnrxrxlpqkpxaxwxchyxmnkzzxttrhayrgnxsljxkxmxtxjbrnovalzxwmtpemlvnxxfdthxbljpzxdrmxursgzzytncdmxsyxnfnthrtdfnefqxtgxxbnbpstdzaxqxbitjyuvpbxsxawhxqulirfntzxixvdzrnvjlaffxrxfllzqzmysxucxtyxdqqkxxyxrkswvhyxlvcxplzmlsmgtsovrzthrxuzmxbtbvvxhsetnzaenuykxfzuzxuezlegvsszrlzxxazuxvogrczgjfmxpmuxvsnixyukwynetxeghgwfexazqxqxyxnufmotnhrxzqyithwwxiaxzomxnbnxxsztzgcknqlxlodxlewuxxcxlioghwaxddugxrzhbzvxnzngdecgvisxxmkxlqnxyvaepxsxnptxnfeutpnkvvrthrskxowxiwwkxxegxndzhuclixrwxvynpenjixrxwxdmxzqlferdfxyjhtefnxzvnx', radix=radix, blocksize=3072)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        M2 = ffx_obj.decrypt(T, C)

        self.assertEqual(M1, M2)

        print('')
        print('TEST VECTOR: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C))

if __name__ == '__main__':
    unittest.main()
