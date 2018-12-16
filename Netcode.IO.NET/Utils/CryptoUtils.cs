using System;
using System.Text;
using NetcodeIO.NET.Utils;

namespace NetcodeIO.NET.Utils
{
    /// Encrypt/Decrypt with AEAD_XChaCha_Poly1205 algorithm (RFC 7539)
    public static class CryptoUtils
    {
        private static XChaCha cipher = new XChaCha();
        private static Poly1305 mac = new Poly1305();

        public static int Encrypt(byte[] bytes, int bytesOffset, int bytesCount, byte[] adata, byte[] key, byte[] nonce, byte[] output)
        {
            var macCalculated = BufferPool.GetBuffer(16);
            var macKey = BufferPool.GetBuffer(32);
            var buf64 = BufferPool.GetBuffer(64);

            // Fill buf32 with mac key
            cipher.Reset(key, nonce);
            cipher.Process(buf64, 0, buf64.Length, buf64, 0);
            Array.Copy(buf64, macKey, 32);

            // Encrypt bytes
            cipher.Process(bytes, bytesOffset, bytesCount, output, 0);

            // Calculate mac
            GetMAC(macKey, output, 0, bytesCount, adata, 0, adata.Length, macCalculated);

            // Add mac to output
            Array.Copy(macCalculated, 0, output, bytesCount, macCalculated.Length);

            // Release
            BufferPool.ReturnBuffer(macCalculated);
            BufferPool.ReturnBuffer(macKey);
            BufferPool.ReturnBuffer(buf64);

            return bytesCount + Poly1305.BLOCK_SIZE;
        }

        public static int Decrypt(byte[] bytes, int bytesOffset, int bytesCount, byte[] adata, byte[] key, byte[] nonce, byte[] output)
        {
            var macCalculated = BufferPool.GetBuffer(16);
            var macRecived = BufferPool.GetBuffer(16);
            var macKey = BufferPool.GetBuffer(32);
            var buf64 = BufferPool.GetBuffer(64);

            var outputCount = bytesCount - Poly1305.BLOCK_SIZE;

            // Fill buf32 with mac key
            cipher.Reset(key, nonce);
            cipher.Process(buf64, 0, buf64.Length, buf64, 0);
            Array.Copy(buf64, macKey, 32);

            // Calculated mac
            GetMAC(macKey, bytes, 0, outputCount, adata, 0, adata.Length, macCalculated);

            // Recived mac
            Array.Copy(bytes, bytesOffset + outputCount, macRecived, 0, macRecived.Length);

            try
            {
                if (IsEqual(macCalculated, macRecived))
                    cipher.Process(bytes, bytesOffset, bytesCount, output, 0);
                else 
                    throw new Exception();

                return outputCount;
            }
            finally
            {
                BufferPool.ReturnBuffer(macCalculated);
                BufferPool.ReturnBuffer(macRecived);
                BufferPool.ReturnBuffer(macKey);
                BufferPool.ReturnBuffer(buf64);
            }
        }

        private static void GetMAC(byte[] key, byte[] bytes, int byteOffset, int bytesCount, byte[] adata, int adataOffset, int adataCount, byte[] output)
        {
            var buf8 = BufferPool.GetBuffer(8);
            
            var zeroBytes = BufferPool.GetBuffer(16);
            var zeroCount = 0;

            mac.Reset(key);

            // Addition data
            mac.Process(adata, 0, adataCount);
            zeroCount = adataCount % Poly1305.BLOCK_SIZE;
            if (zeroCount != 0) mac.Process(zeroBytes, 0, Poly1305.BLOCK_SIZE - zeroCount);

            // Encrypted data
            mac.Process(bytes, byteOffset, bytesCount);
            zeroCount = bytesCount % Poly1305.BLOCK_SIZE;
            if (zeroCount != 0) mac.Process(zeroBytes, 0, Poly1305.BLOCK_SIZE - zeroCount);

            // Addition data length
            Lend.Unpack64((ulong)adataCount, buf8);
            mac.Process(buf8, 0, 8);

            // Encrypted data length
            Lend.Unpack64((ulong)bytesCount, buf8);
            mac.Process(buf8, 0, 8);

            mac.Build(output, 0);

            BufferPool.ReturnBuffer(buf8);
            BufferPool.ReturnBuffer(zeroBytes);
        }

        private static bool IsEqual(byte[] a, byte[] b)
        {
            int i = a.Length;
            if (i != b.Length) return false;

            int cmp = 0;
            while (i != 0)
            {
                --i;
                cmp |= (a[i] ^ b[i]);
            }
            return cmp == 0;
        }
    }

    public class XChaCha
    {
        private static uint[] SIGMA = Lend.Pack32(Encoding.ASCII.GetBytes("expand 32-byte k"), 0, 4);
        private static int SIZE = 16;

        private int stateIndex = 0;
        private uint[] state = new uint[SIZE];
        private uint[] buffer = new uint[SIZE];
        private byte[] gamma = new byte[SIZE * 4];

        public void Reset(byte[] key, byte[] nonce)
        {
            if (key == null || key.Length != 32) throw new ArgumentException();
            if (nonce == null || nonce.Length != 12) throw new ArgumentException();

            StateInit(state, key, nonce);
            stateIndex = 0;
        }

        public void Process(byte[] bytes, int bytesOffset, int bytesCount, byte[] output, int outputOffset)
        {
            for (int i = 0; i < bytesCount; i++)
            {
                if (stateIndex == 0)
                {
                    StateGamma(state, buffer, gamma);
                    StateInc(state);
                }

                output[outputOffset + i] = (byte)(bytes[i + bytesOffset] ^ gamma[stateIndex]);
                stateIndex = (stateIndex + 1) & 63;
            }
        }

        private static void StateInit(uint[] state, byte[] key, byte[] nonce)
        {
            Array.Clear(state, 0, SIZE);

            state[0] = SIGMA[0];
            state[1] = SIGMA[1];
            state[2] = SIGMA[2];
            state[3] = SIGMA[3];

            Lend.Pack32(key, 0, state, 4, 8);
            Lend.Pack32(nonce, 0, state, 13, 3);
        }

        private static void StateInc(uint[] state)
        {
            state[12]++;
        }

        private static void StateGamma(uint[] state, uint[] buffer, byte[] gamma)
        {
            RotateChaCha(state, buffer, 20);
            Lend.Unpack32(buffer, gamma, 0);
        }

        private static void RotateChaCha(uint[] y, uint[] x, int rounds)
        {
            if (rounds % 2 != 0) throw new ArgumentException("Number of rounds must be even");

            uint x00 = y[ 0];
            uint x01 = y[ 1];
            uint x02 = y[ 2];
            uint x03 = y[ 3];
            uint x04 = y[ 4];
            uint x05 = y[ 5];
            uint x06 = y[ 6];
            uint x07 = y[ 7];
            uint x08 = y[ 8];
            uint x09 = y[ 9];
            uint x10 = y[10];
            uint x11 = y[11];
            uint x12 = y[12];
            uint x13 = y[13];
            uint x14 = y[14];
            uint x15 = y[15];

            for (int i = rounds; i > 0; i -= 2)
            {
                x00 += x04; x12 = RotateLeft(x12 ^ x00, 16);
                x08 += x12; x04 = RotateLeft(x04 ^ x08, 12);
                x00 += x04; x12 = RotateLeft(x12 ^ x00, 8);
                x08 += x12; x04 = RotateLeft(x04 ^ x08, 7);
                x01 += x05; x13 = RotateLeft(x13 ^ x01, 16);
                x09 += x13; x05 = RotateLeft(x05 ^ x09, 12);
                x01 += x05; x13 = RotateLeft(x13 ^ x01, 8);
                x09 += x13; x05 = RotateLeft(x05 ^ x09, 7);
                x02 += x06; x14 = RotateLeft(x14 ^ x02, 16);
                x10 += x14; x06 = RotateLeft(x06 ^ x10, 12);
                x02 += x06; x14 = RotateLeft(x14 ^ x02, 8);
                x10 += x14; x06 = RotateLeft(x06 ^ x10, 7);
                x03 += x07; x15 = RotateLeft(x15 ^ x03, 16);
                x11 += x15; x07 = RotateLeft(x07 ^ x11, 12);
                x03 += x07; x15 = RotateLeft(x15 ^ x03, 8);
                x11 += x15; x07 = RotateLeft(x07 ^ x11, 7);
                x00 += x05; x15 = RotateLeft(x15 ^ x00, 16);
                x10 += x15; x05 = RotateLeft(x05 ^ x10, 12);
                x00 += x05; x15 = RotateLeft(x15 ^ x00, 8);
                x10 += x15; x05 = RotateLeft(x05 ^ x10, 7);
                x01 += x06; x12 = RotateLeft(x12 ^ x01, 16);
                x11 += x12; x06 = RotateLeft(x06 ^ x11, 12);
                x01 += x06; x12 = RotateLeft(x12 ^ x01, 8);
                x11 += x12; x06 = RotateLeft(x06 ^ x11, 7);
                x02 += x07; x13 = RotateLeft(x13 ^ x02, 16);
                x08 += x13; x07 = RotateLeft(x07 ^ x08, 12);
                x02 += x07; x13 = RotateLeft(x13 ^ x02, 8);
                x08 += x13; x07 = RotateLeft(x07 ^ x08, 7);
                x03 += x04; x14 = RotateLeft(x14 ^ x03, 16);
                x09 += x14; x04 = RotateLeft(x04 ^ x09, 12);
                x03 += x04; x14 = RotateLeft(x14 ^ x03, 8);
                x09 += x14; x04 = RotateLeft(x04 ^ x09, 7);
            }

            x[ 0] = x00 + y[ 0];
            x[ 1] = x01 + y[ 1];
            x[ 2] = x02 + y[ 2];
            x[ 3] = x03 + y[ 3];
            x[ 4] = x04 + y[ 4];
            x[ 5] = x05 + y[ 5];
            x[ 6] = x06 + y[ 6];
            x[ 7] = x07 + y[ 7];
            x[ 8] = x08 + y[ 8];
            x[ 9] = x09 + y[ 9];
            x[10] = x10 + y[10];
            x[11] = x11 + y[11];
            x[12] = x12 + y[12];
            x[13] = x13 + y[13];
            x[14] = x14 + y[14];
            x[15] = x15 + y[15];
        }

        private static uint RotateLeft(uint value, int numBits)
        {
            return (value << numBits) | (value >> (32 - numBits));
        }
    }

    public class Poly1305
    {
        public const int BLOCK_SIZE = 16;

        // Initialised state

        /** Polynomial key */
        private uint r0, r1, r2, r3, r4;
        /** Precomputed 5 * r[1..4] */
        private uint s1, s2, s3, s4;
        /** Encrypted key */
        private uint k0, k1, k2, k3;

        // Accumulating state

        /** Current block of buffered input */
        private byte[] buffer = new byte[BLOCK_SIZE];
        /** Current offset in input buffer */
        private int bufferLength = 0;
        /** Polynomial accumulator */
        private uint h0, h1, h2, h3, h4;

        public void Reset(byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("Poly1305 key must be 256 bits.");

            bufferLength = 0;

            h0 = h1 = h2 = h3 = h4 = 0;

            // Extract r portion of key (and "clamp" the values)
            uint t0 = Lend.Pack32(key, 0);
            uint t1 = Lend.Pack32(key, 4);
            uint t2 = Lend.Pack32(key, 8);
            uint t3 = Lend.Pack32(key, 12);

            // NOTE: The masks perform the key "clamping" implicitly
            r0 =   t0                      & 0x03FFFFFFU;
            r1 = ((t0 >> 26) | (t1 <<  6)) & 0x03FFFF03U;
            r2 = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FFU;
            r3 = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFFU;
            r4 =  (t3 >>  8)               & 0x000FFFFFU;

            // Precompute multipliers
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            k0 = Lend.Pack32(key, BLOCK_SIZE + 0);
            k1 = Lend.Pack32(key, BLOCK_SIZE + 4);
            k2 = Lend.Pack32(key, BLOCK_SIZE + 8);
            k3 = Lend.Pack32(key, BLOCK_SIZE + 12);
        }

        public void Process(byte[] bytes, int bytesOffset, int bytesCount)
        {
            int bytesProcessed = 0;

            while (bytesCount > bytesProcessed)
            {
                if (bufferLength == BLOCK_SIZE)
                    ProcessBuffer();

                int count = Math.Min(bytesCount - bytesProcessed, BLOCK_SIZE - bufferLength);
                Array.Copy(bytes, bytesOffset + bytesProcessed, buffer, bufferLength, count);
                bufferLength += count;
                bytesProcessed += count;
            }
        }

        private void ProcessBuffer()
        {
            if (bufferLength == 0) return;
            if (bufferLength < BLOCK_SIZE)
            {
                buffer[bufferLength] = 1;
                Array.Clear(buffer, bufferLength + 1, BLOCK_SIZE - bufferLength - 1);
            }

            ulong t0 = Lend.Pack32(buffer, 0);
            ulong t1 = Lend.Pack32(buffer, 4);
            ulong t2 = Lend.Pack32(buffer, 8);
            ulong t3 = Lend.Pack32(buffer, 12);

            h0 += (uint)(t0 & 0x3ffffffU);
            h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
            h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
            h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
            h4 += (uint)(t3 >> 8);

            if (bufferLength == BLOCK_SIZE)
            {
                h4 += (1 << 24);
            }

            ulong tp0 = mul32x32_64(h0,r0) + mul32x32_64(h1,s4) + mul32x32_64(h2,s3) + mul32x32_64(h3,s2) + mul32x32_64(h4,s1);
            ulong tp1 = mul32x32_64(h0,r1) + mul32x32_64(h1,r0) + mul32x32_64(h2,s4) + mul32x32_64(h3,s3) + mul32x32_64(h4,s2);
            ulong tp2 = mul32x32_64(h0,r2) + mul32x32_64(h1,r1) + mul32x32_64(h2,r0) + mul32x32_64(h3,s4) + mul32x32_64(h4,s3);
            ulong tp3 = mul32x32_64(h0,r3) + mul32x32_64(h1,r2) + mul32x32_64(h2,r1) + mul32x32_64(h3,r0) + mul32x32_64(h4,s4);
            ulong tp4 = mul32x32_64(h0,r4) + mul32x32_64(h1,r3) + mul32x32_64(h2,r2) + mul32x32_64(h3,r1) + mul32x32_64(h4,r0);

            h0 = (uint)tp0 & 0x3ffffff; tp1 += (tp0 >> 26);
            h1 = (uint)tp1 & 0x3ffffff; tp2 += (tp1 >> 26);
            h2 = (uint)tp2 & 0x3ffffff; tp3 += (tp2 >> 26);
            h3 = (uint)tp3 & 0x3ffffff; tp4 += (tp3 >> 26);
            h4 = (uint)tp4 & 0x3ffffff;
            h0 += (uint)(tp4 >> 26) * 5;
            h1 += (h0 >> 26); h0 &= 0x3ffffff;

            bufferLength = 0;
        }

        public int Build(byte[] output, int outputOffset)
        {
            if (bufferLength > 0)
                ProcessBuffer();

            h1 += (h0 >> 26); h0 &= 0x3ffffff;
            h2 += (h1 >> 26); h1 &= 0x3ffffff;
            h3 += (h2 >> 26); h2 &= 0x3ffffff;
            h4 += (h3 >> 26); h3 &= 0x3ffffff;
            h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
            h1 += (h0 >> 26); h0 &= 0x3ffffff;

            uint g0, g1, g2, g3, g4, b;
            g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
            g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
            g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
            g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
            g4 = h4 + b - (1 << 26);

            b = (g4 >> 31) - 1;
            uint nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            ulong f0, f1, f2, f3;
            f0 = ((h0      ) | (h1 << 26)) + (ulong)k0;
            f1 = ((h1 >> 6 ) | (h2 << 20)) + (ulong)k1;
            f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
            f3 = ((h3 >> 18) | (h4 << 8 )) + (ulong)k3;

            Lend.Unpack32((uint)f0, output, outputOffset);
            f1 += (f0 >> 32);
            Lend.Unpack32((uint)f1, output, outputOffset + 4);
            f2 += (f1 >> 32);
            Lend.Unpack32((uint)f2, output, outputOffset + 8);
            f3 += (f2 >> 32);
            Lend.Unpack32((uint)f3, output, outputOffset + 12);

            return BLOCK_SIZE;
        }

        private static ulong mul32x32_64(uint i1, uint i2)
        {
            return ((ulong)i1) * i2;
        }
    }

    /// Little-Endian packer/unpacker
    public static class Lend
    {
        public static void Unpack64(ulong value, byte[] output)
        {
            Unpack32((uint)(value), output);
            Unpack32((uint)(value >> 32), output, 4);
        }

        public static void Unpack32(uint value, byte[] output, int outputOffset = 0)
        {
            output[outputOffset]     = (byte)(value);
            output[outputOffset + 1] = (byte)(value >> 8);
            output[outputOffset + 2] = (byte)(value >> 16);
            output[outputOffset + 3] = (byte)(value >> 24);
        }

        public static void Unpack32(uint[] values, byte[] output, int outputOffset)
        {
            for (int i = 0; i < values.Length; ++i)
            {
                Unpack32(values[i], output, outputOffset);
                outputOffset += 4;
            }
        }

        public static uint[] Pack32(byte[] bytes, int bytesOffset, int numIntegers)
        {
            var result = new uint[numIntegers];
            Pack32(bytes, bytesOffset, result, 0, numIntegers);
            return result;
        }

        public static void Pack32(byte[] bytes, int bytesOffset, uint[] output, int outputOffset, int numIntegers)
        {
            for (int i = 0; i < numIntegers; ++i)
            {
                output[outputOffset + i] = Pack32(bytes, bytesOffset);
                bytesOffset += 4;
            }
        }

        public static uint Pack32(byte[] bytes, int bytesOffset)
        {
            return (uint)bytes[bytesOffset]
                | (uint)bytes[bytesOffset + 1] << 8
                | (uint)bytes[bytesOffset + 2] << 16
                | (uint)bytes[bytesOffset + 3] << 24;
        }
    }
}
