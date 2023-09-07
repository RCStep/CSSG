using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace Encryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length != 5)
                {
                    Console.WriteLine("Usage: Encryptor.exe <aes/rc4> <encrypt/decrypt> <key> <input file> <output file>");
                    Console.WriteLine("AES key: 16, 24 or 32 byte long key");
                    Console.WriteLine("RC4 key: Any length value or phrase. Phrase with spaces needs to be in \"\"");
                    Environment.Exit(1);
                }

                string OutFile = args[4];
                string PayloadPath = args[3];
                string key = args[2];
                string encryption = args[0];

                // Check byte key length; exit if not 16, 24, or 32
                if (!(new[] { 16, 24, 32 }.Contains(Buffer.ByteLength(Encoding.UTF8.GetBytes(key)))) & encryption == "aes")
                {
                    Console.WriteLine("[!] Encryption key must be 16, 24, or 32 bytes long");
                    Environment.Exit(1);
                }

                byte[] Shellcode = File.ReadAllBytes(PayloadPath);
                Console.WriteLine("[*] Read file bytes: " + Shellcode.Length);
                //string B64Shellcode = Convert.ToBase64String(Shellcode);

                if (encryption == "aes" & args[1].Equals("encrypt", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] EncryptedShellcode = AES_Encrypt(key, Shellcode);
                    Console.WriteLine("[*] AES encrypted file bytes: " + EncryptedShellcode.Length);
                    WriteShellcodeToFile(EncryptedShellcode, OutFile);
                    Console.WriteLine("[*] File encrypted and written to: " + OutFile);
                }

                else if (encryption == "aes" & args[1].Equals("decrypt", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] EncryptedShellcode = AES_Decrypt(key, Shellcode);
                    Console.WriteLine("[*] AES decrypted file bytes: " + EncryptedShellcode.Length);
                    WriteShellcodeToFile(EncryptedShellcode, OutFile);
                    Console.WriteLine("[*] File decrypted and written to: " + OutFile);
                }

                else if (encryption == "rc4" & args[1].Equals("encrypt", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] EncryptedShellcode = RC4_Encrypt(key, Shellcode);
                    Console.WriteLine("[*] RC4 encrypted file bytes: " + EncryptedShellcode.Length);
                    WriteShellcodeToFile(EncryptedShellcode, OutFile);
                    Console.WriteLine("[*] File encrypted and written to: " + OutFile);
                }

                else if (encryption == "rc4" & args[1].Equals("decrypt", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] EncryptedShellcode = RC4_Decrypt(key, Shellcode);
                    Console.WriteLine("[*] RC4 decrypted file bytes: " + EncryptedShellcode.Length);
                    WriteShellcodeToFile(EncryptedShellcode, OutFile);
                    Console.WriteLine("[*] File decrypted and written to: " + OutFile);
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.ToString());
            }
        }

        // AES Encryption function
        public static byte[] AES_Encrypt(string key, byte[] data)
        {
            byte[] enc;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);

                Console.WriteLine("[*] Key bytes: " + aes.Key.Length);
                Console.WriteLine("[*] Padding mode: " + (byte)aes.Padding);
                Console.WriteLine("[*] AES keysize: " + aes.KeySize);
                Console.WriteLine("[*] AES blockSize: " + aes.BlockSize);

                using (MemoryStream ms = new MemoryStream())
                {
                    // Write the first 16 bytes which is a random IV.
                    aes.GenerateIV();
                    byte[] iv = aes.IV;
                    ms.Write(iv, 0, iv.Length);

                    Console.WriteLine("[*] IV length: " + aes.IV.Length);
                    Console.WriteLine("[*] IV bytes: " + BitConverter.ToString(aes.IV));

                    using (CryptoStream cs = new CryptoStream((Stream)ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }

                    enc = ms.ToArray();
                    ms.Close();
                }
            }
            //Console.WriteLine("[*] Encrypted Bytes:" + enc);
            return enc;
        }

        // AES Decryption function
        public static byte[] AES_Decrypt(string key, byte[] data)
        {
            byte[] dec;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);

                Console.WriteLine("[*] Key bytes: " + aes.Key.Length);
                Console.WriteLine("[*] Padding mode: " + (byte)aes.Padding);
                Console.WriteLine("[*] AES keysize: " + aes.KeySize);
                Console.WriteLine("[*] AES blockSize: " + aes.BlockSize);

                using (MemoryStream ms = new MemoryStream(data))
                {
                    // Read the first 16 bytes which is the IV.
                    byte[] iv = new byte[16];
                    ms.Read(iv, 0, iv.Length);
                    aes.IV = iv;

                    Console.WriteLine("[*] IV length: " + aes.IV.Length);
                    Console.WriteLine("[*] IV bytes: " + BitConverter.ToString(aes.IV));
                }

                using (MemoryStream ms = new MemoryStream())
                { 
                    using (CryptoStream cs = new CryptoStream((Stream)ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        //Provide IV offset, expected length of decrypted plaintext, and write to CryptoStream
                        int DecryptedLength = (data.Length - aes.IV.Length);
                        cs.Write(data, aes.IV.Length, DecryptedLength);
                        cs.Close();
                    }

                    dec = ms.ToArray();
                    ms.Close();
                }
            }
            //Console.WriteLine("[*] Decrypted Bytes:" + dec);
            return dec;
        }

        // RC4 Encryption function
        public static byte[] RC4_Encrypt(string key, byte[] data)
        {
            byte[] bkey = Encoding.UTF8.GetBytes(key);

            byte[] enc = RC4.Apply(data, bkey);

            return enc;
        }

        // RC4 Decryption function
        public static byte[] RC4_Decrypt(string key, byte[] data)
        {
            byte[] bkey = Encoding.UTF8.GetBytes(key);

            byte[] dec = RC4.Apply(data, bkey);

            return dec;
        }

        public static void WriteShellcodeToFile(byte[] EncryptedShellcode, string OutFile)
        {
            //string B64Shellcode = Convert.ToBase64String(EncryptedShellcode);
            
            Console.WriteLine("[*] Byes written to file: " + EncryptedShellcode.Length);

            //File.WriteAllText($"{OutFile}", B64Shellcode);
            File.WriteAllBytes($"{OutFile}", EncryptedShellcode);
        }
    }

    // RC4 Encryption/Decryption class
    public static class RC4
    {
        /// RC4 class sourced from: https://github.com/manbeardgames/RC4
        /// MIT License
        /// <summary>
        ///     Give data and an encryption key, apply RC4 cryptography.  RC4 is symmetric,
        ///     which means this single method will work for encrypting and decrypting.
        /// </summary>
        /// <remarks>
        ///     https://en.wikipedia.org/wiki/RC4
        /// </remarks>
        /// <param name="data">
        ///     Byte array representing the data to be encrypted/decrypted
        /// </param>
        /// <param name="key">
        ///     Byte array representing the key to use
        /// </param>
        /// <returns>
        ///     Byte array representing the encrypted/decrypted data.
        /// </returns>
        public static byte[] Apply(byte[] data, byte[] key)
        {
            //  Key Scheduling Algorithm Phase:
            //  KSA Phase Step 1: First, the entries of S are set equal to the values of 0 to 255 
            //                    in ascending order.
            int[] S = new int[256];
            for (int _ = 0; _ < 256; _++)
            {
                S[_] = _;
            }

            //  KSA Phase Step 2a: Next, a temporary vector T is created.
            int[] T = new int[256];

            //  KSA Phase Step 2b: If the length of the key k is 256 bytes, then k is assigned to T.  
            if (key.Length == 256)
            {
                Buffer.BlockCopy(key, 0, T, 0, key.Length);
            }
            else
            {
                //  Otherwise, for a key with a given length, copy the elements of
                //  the key into vector T, repeating for as many times as neccessary to
                //  fill T
                for (int _ = 0; _ < 256; _++)
                {
                    T[_] = key[_ % key.Length];
                }
            }

            //  KSA Phase Step 3: We use T to produce the initial permutation of S ...
            int i = 0;
            int j = 0;
            for (i = 0; i < 256; i++)
            {
                //  increment j by the sum of S[i] and T[i], however keeping it within the 
                //  range of 0 to 255 using mod (%) division.
                j = (j + S[i] + T[i]) % 256;

                //  Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            //  Pseudo random generation algorithm (Stream Generation):
            //  Once the vector S is initialized from above in the Key Scheduling Algorithm Phase,
            //  the input key is no longer used.  In this phase, for the length of the data, we ...
            i = j = 0;
            byte[] result = new byte[data.Length];
            for (int iteration = 0; iteration < data.Length; iteration++)
            {
                //  PRGA Phase Step 1. Continously increment i from 0 to 255, starting it back 
                //                     at 0 once we go beyond 255 (this is done with mod (%) division
                i = (i + 1) % 256;

                //  PRGA Phase Step 2. Lookup the i'th element of S and add it to j, keeping the
                //                     result within the range of 0 to 255 using mod (%) division
                j = (j + S[i]) % 256;

                //  PRGA Phase Step 3. Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                //  PRGA Phase Step 4. Use the result of the sum of S[i] and S[j], mod (%) by 256, 
                //                     to get the index of S that handls the value of the stream value K.
                int K = S[(S[i] + S[j]) % 256];

                //  PRGA Phase Step 5. Use bitwise exclusive OR (^) with the next byte in the data to
                //                     produce  the next byte of the resulting ciphertext (when 
                //                     encrypting) or plaintext (when decrypting)
                result[iteration] = Convert.ToByte(data[iteration] ^ K);
            }

            //  return the result
            return result;
        }
    }
}
