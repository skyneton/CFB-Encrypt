using System;
using System.Collections.Generic;

namespace CFB.Cryptography
{
    //https://stackoverflow.com/questions/34420086/aes-decryption-encryption-implementation-in-c-sharp-not-using-libraries
    public class AesCipher
    {
        public byte[] Key { get; }

        public byte[] IV { get; }

        private byte[] _cV;
        public int FeedbackSize => 8;
        public int InputBlockSize => 16;
        public static int RoundCount => 10;

        public byte[][] RoundKey { get; } = new byte[RoundCount + 1][];

        private int _blockSize; 

        public AesCipher(byte[] key, byte[] iv)
        {
            Key = ByteArrayClone(key);
            IV = ByteArrayClone(iv);

            _blockSize = FeedbackSize / 8;

            GenerateRoundKey();
            Reset();
        }

        public void Reset()
        {
            _cV = ByteArrayClone(IV);
        }

        private static byte[] ByteArrayClone(byte[] array)
        {
            var length = array.Length;
            var result = new byte[length];
            Array.Copy(array, result, length);
            return result;
        }

        private void GenerateRoundKey()
        {
            RoundKey[0] = ByteArrayClone(Key);
            for (var i = 1; i <= RoundCount; i++)
            {
                RoundKey[i] = ByteArrayClone(RoundKey[i - 1]);
                AesModule.RoundKeyTransform(RoundKey[i], i - 1, InputBlockSize);
            }
        }

        #region Encrypt
        public byte[] EncryptBlock(byte[] input)
        {
            var length = input.Length;
            var outBytes = new byte[length];
            EncryptBlock(input, 0, outBytes, 0, length);
            
            return outBytes;
        }

        public int EncryptBlock(byte[] input, int inOff, byte[] outBytes, int outOff, int length)
        {
            lock (_cV)
            {
                var count = 0;
                while (count < length)
                {
                    count += EncryptBlock(input, inOff + count, outBytes, outOff + count);
                }
            }

            return length;
        }

        private int EncryptBlock(IReadOnlyList<byte> input, int inOff, byte[] outBytes, int outOff)
        {
            var v = AesEncryptBlock(_cV);
            
            outBytes[outOff] = (byte) (v[0] ^ input[inOff]);

            var length = _cV.Length - _blockSize;
            Array.Copy(_cV, 1, _cV, 0, length);
            Array.Copy(outBytes, outOff, _cV, length, 1);

            return 1;
        }

        public byte[] AesEncryptBlock(byte[] origin)
        {
            var transform = ByteArrayClone(origin);
            
            for (var k = 0; k < InputBlockSize; k++)
                transform[k] ^= RoundKey[0][k];
            
            for (var i = 1; i < RoundCount; i++)
            {
                AesModule.SubAndShiftAndMixAndRoundKey(transform, RoundKey[i]);
            }
            
            
            AesModule.SubByteAndShiftRows(transform);
            
            for (var k = 0; k < InputBlockSize; k++)
                transform[k] ^= RoundKey[RoundCount][k];

            return transform;
        }
        #endregion

        #region Decrypt
        public int DecryptByte(int input)
        {
            var outBytes = new byte[1];
            DecryptBlock(new [] {(byte) input}, 0, outBytes, 0, 1);
            
            return outBytes[0];
        }
        
        public byte[] DecryptBlock(byte[] input)
        {
            var length = input.Length;
            var outBytes = new byte[length];
            DecryptBlock(input, 0, outBytes, 0, length);
            
            return outBytes;
        }
        
        public byte[] DecryptBlock(byte[] input, int inOff, int length)
        {
            var outBytes = new byte[length];
            DecryptBlock(input, inOff, outBytes, 0, length);
            
            return outBytes;
        }
        
        public int DecryptBlock(byte[] input, int inOff, byte[] outBytes, int outOff, int length)
        {
            var count = 0;
            while (count < length)
            {
                count += DecryptBlock(input, inOff + count, outBytes, outOff + count);
            }

            return count;
        }

        private int DecryptBlock(byte[] input, int inOff, byte[] outBytes, int outOff)
        {
            var v = AesEncryptBlock(_cV);
            var length = _cV.Length - _blockSize;
            Array.Copy(_cV, _blockSize, _cV, 0, length);
            Array.Copy(input, inOff, _cV, length, _blockSize);
            
            for(var i = 0; i < _blockSize; i++)
                outBytes[outOff + i] = (byte) (v[i] ^ input[inOff + i]);

            return _blockSize;
        }
        #endregion
    }
}