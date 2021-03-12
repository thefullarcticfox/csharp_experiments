using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/*
 * This will be .Net Core 5 test 
 */

namespace Crypto
{
	class Program
	{
		public static void	AES_Encrypt()
		{
			Console.Write("Enter text to encrypt: ");
			string text = Console.ReadLine();

			using var aesAlg = new AesManaged();
			Console.WriteLine("KeySize:\t" + aesAlg.KeySize);
			Console.WriteLine("IV:\t\t" + Convert.ToBase64String(aesAlg.IV));
			Console.WriteLine("Key:\t\t" + Convert.ToBase64String(aesAlg.Key));

			// Create an encryptor to perform the stream transform.
			var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
			// Create the streams used for encryption.
			using var msEncrypt = new MemoryStream();
			using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
			using (var swEncrypt = new StreamWriter(csEncrypt))
			{
				swEncrypt.Write(text);   //	Write all data to the stream.
			}
			var encrypted = msEncrypt.ToArray();
			var encryptedbase64Txt = Convert.ToBase64String(encrypted);
			Console.WriteLine("Encrypted text: " + encryptedbase64Txt);
		}

		public static string AES_Decrypt()
		{
			byte[] cryptoBytes;
			try
			{
				Console.Write("Enter text to decrypt: ");
				cryptoBytes = Convert.FromBase64String(Console.ReadLine());
			}
			catch (FormatException)
			{
				return ("Entered string is not a valid base64 string.");
			}
			using var aesAlg = new AesManaged();
			try
			{
				Console.Write("Enter AES IV:\t");
				string AesIv = Console.ReadLine();
				aesAlg.IV = Convert.FromBase64String(AesIv);
			}
			catch (FormatException)
			{
				return ("AES IV is not a valid base64 string.");
			}
			try
			{
				Console.Write("Enter AES Key:\t");
				aesAlg.Key = Convert.FromBase64String(Console.ReadLine());
			}
			catch (FormatException)
			{
				return ("Entered key is not a valid base64 string.");
			}
			// Create a decryptor to perform the stream transform.
			var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
			// Create the streams used for decryption.
			using var msDecrypt = new MemoryStream(cryptoBytes);
			using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
			using var srDecrypt = new StreamReader(csDecrypt);
			// Read the decrypted bytes from the decrypting stream and place them in a string.
			try
			{
				return ("Decrypted text:\t" + srDecrypt.ReadToEnd());
			}
			catch (CryptographicException cex)
			{
				return ($"Cryptographic error: {cex.Message}");
			}
		}

		public static void	RSA_Encrypt()
		{
			Console.Write("Enter text to encrypt: ");
			string text = Console.ReadLine();

			RSA rsa = RSA.Create(4096);
			Console.WriteLine("KeySize:\t" + rsa.KeySize);
			Console.WriteLine("PubKey:\t\t" + Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
			Console.WriteLine("PrivKey:\t" + Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
			Console.WriteLine("PrivPkcs8Key:\t" + Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()));

			string encryptedbase64Txt;
			// Create a UnicodeEncoder to convert between byte array and string.
			UnicodeEncoding	byteConverter = new UnicodeEncoding();
			byte[]			inputdata = byteConverter.GetBytes(text);
			try
			{
				encryptedbase64Txt = Convert.ToBase64String(rsa.Encrypt(inputdata, RSAEncryptionPadding.Pkcs1));
			}
			catch (CryptographicException cex)
			{
				encryptedbase64Txt = $"Cryptographic error: {cex.Message}";
			}
			Console.WriteLine("Encrypted text: " + encryptedbase64Txt);
		}

		public static string	RSA_Decrypt()
		{
			byte[] cryptoBytes;
			try
			{
				Console.Write("Enter text to decrypt: ");
				cryptoBytes = Convert.FromBase64String(Console.ReadLine());
			}
			catch (Exception)
			{
				return "Entered string is not a valid base64 string.";
			}

			// Create a UnicodeEncoder to convert between byte array and string.
			UnicodeEncoding	byteConverter = new UnicodeEncoding();
			RSA				rsa = RSA.Create(4096);
			try
			{
				Console.Write("Enter RSA PubKey:\t");
				rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Console.ReadLine()), out _);
			}
			catch (Exception)
			{
				return ("Public key is not valid");
			}
			try
			{
				Console.Write("Enter RSA Pkcs8 PrivKey:\t");
				rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(Console.ReadLine()), out _);
			}
			catch (Exception)
			{
				return ("Private key is not valid");
			}

			try
			{
				return ("Decrypted text:\t" + byteConverter.GetString(rsa.Decrypt(cryptoBytes, RSAEncryptionPadding.Pkcs1)));
			}
			catch (CryptographicException cex)
			{
				return ($"Cryptographic error: {cex.Message}");
			}
		}

		static void Main()
		{
			Console.OutputEncoding = Encoding.UTF8;
			Console.Write("enter command: ");
			string	cmd;
			while ((cmd = Console.ReadLine()) != null)
			{
				switch (cmd)
				{
					case "help":
						Console.WriteLine("commands: aes encrypt, aes decrypt, rsa encrypt, rsa decrypt, help, exit");
						break;
					case "aes encrypt":
						AES_Encrypt();
						break;
					case "aes decrypt":
						Console.WriteLine(AES_Decrypt());
						break;
					case "rsa encrypt":
						RSA_Encrypt();
						break;
					case "rsa decrypt":
						Console.WriteLine(RSA_Decrypt());
						break;
					case "exit":
						Environment.Exit(0);
						break;
					default:
						break;
				}
				Console.Write("\nenter command: ");
			}
		}
	}
}
