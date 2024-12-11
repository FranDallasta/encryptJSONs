using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    public static (byte[] Key, byte[] IV) GetEncryptionSettings()
    {
        var keyString = Environment.GetEnvironmentVariable("AES_KEY");
        var ivString = Environment.GetEnvironmentVariable("AES_IV");

        if (string.IsNullOrEmpty(keyString) || string.IsNullOrEmpty(ivString))
        {
            throw new InvalidOperationException("AES_KEY or AES_IV is not set in environment variables.");
        }

        var key = Convert.FromBase64String(keyString);
        var iv = Convert.FromBase64String(ivString);

        return (key, iv);
    }

    public static string EncryptData(string plainText, byte[] key, byte[] iv)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            throw new ArgumentException("Input to EncryptData is null or empty.");
        }

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var writer = new StreamWriter(cs))
        {
            writer.Write(plainText);
            writer.Flush(); // Ensure all data is flushed to the CryptoStream
        }

        // Convert encrypted data in MemoryStream to Base64 string
        return Convert.ToBase64String(ms.ToArray());
    }

    public static string DecryptData(string cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        return reader.ReadToEnd();
    }
}
