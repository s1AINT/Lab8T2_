using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

class RSA
{
    static Random random = new Random();

    static bool IsProbablyPrime(BigInteger n, int k)
    {
        if (n <= 1 || n == 4)
            return false;
        if (n <= 3)
            return true;

        BigInteger d = n - 1;
        while (d % 2 == 0)
            d /= 2;

        for (int i = 0; i < k; i++)
        {
            if (!WitnessTest(GenerateRandomBigInteger(n.ToByteArray().Length - 1), n, d))
                return false;
        }

        return true;
    }

    static bool WitnessTest(BigInteger a, BigInteger n, BigInteger d)
    {
        BigInteger x = BigInteger.ModPow(a, d, n);
        if (x == 1 || x == n - 1)
            return true;

        while (d != n - 1)
        {
            x = BigInteger.ModPow(x, 2, n);
            d *= 2;

            if (x == 1)
                return false;
            if (x == n - 1)
                return true;
        }

        return false;
    }

    static BigInteger GenerateRandomBigInteger(int bitLength)
    {
        byte[] bytes = new byte[bitLength / 8];
        random.NextBytes(bytes);

        return new BigInteger(bytes);
    }

    static BigInteger GeneratePrime(int bitLength)
    {
        while (true)
        {
            BigInteger potentialPrime = GenerateRandomBigInteger(bitLength);

            if (IsProbablyPrime(potentialPrime, 5))
                return potentialPrime;
        }
    }

    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m;
        BigInteger y = 0, x = 1;

        if (m == 1)
            return 0;

        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;

            m = a % m;
            a = t;
            t = y;

            y = x - q * y;
            x = t;
        }

        if (x < 0)
            x += m0;

        return x;
    }

    static void GenerateKeys(out BigInteger publicKey, out BigInteger privateKey, out BigInteger modulus)
    {
        int bitLength = 512;
        BigInteger p = GeneratePrime(bitLength);
        BigInteger q = GeneratePrime(bitLength);

        modulus = p * q;
        BigInteger phi = (p - 1) * (q - 1);

        publicKey = GenerateRandomBigInteger(bitLength);
        while (BigInteger.GreatestCommonDivisor(publicKey, phi) != 1)
            publicKey = GenerateRandomBigInteger(bitLength);

        privateKey = ModInverse(publicKey, phi);
    }

    static byte[] Encrypt(byte[] message, BigInteger publicKey, BigInteger modulus)
    {
        BigInteger messageInt = new BigInteger(message);

        if (messageInt < 0 || messageInt >= modulus)
        {
            throw new ArgumentOutOfRangeException(nameof(message), "Message must be non-negative and less than modulus.");
        }

        return BigInteger.ModPow(messageInt, publicKey, modulus).ToByteArray();
    }

    static byte[] Decrypt(byte[] cipherText, BigInteger privateKey, BigInteger modulus)
    {
        BigInteger cipherTextInt = new BigInteger(cipherText);
        BigInteger decrypted = BigInteger.ModPow(cipherTextInt, privateKey, modulus);

        return decrypted.ToByteArray();
    }

    static void Main()
    {
        BigInteger publicKey, privateKey, modulus;

        GenerateKeys(out publicKey, out privateKey, out modulus);

        Console.WriteLine("Public Key: " + publicKey);
        Console.WriteLine("Private Key: " + privateKey);
        Console.WriteLine("Modulus: " + modulus);

        string messageString = "Hello, world!";
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageString);

        byte[] cipherText = Encrypt(messageBytes, publicKey, modulus);
        Console.WriteLine("Encrypted Message: " + Convert.ToBase64String(cipherText));

        byte[] decryptedMessage = Decrypt(cipherText, privateKey, modulus);
        string decryptedText = Encoding.UTF8.GetString(decryptedMessage);
        Console.WriteLine("Decrypted Message: " + decryptedText);
    }
}
