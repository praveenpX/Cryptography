using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Common.Cryptography
{
	internal class CryptographicProvider
	{
		private static readonly Dictionary<HashAlgorithmType, HashAlgorithm> HashAlgorithms = GetHashAlgorithms();
		private static readonly Dictionary<HashAlgorithmType, int> HashSizesInBits = GetHashSizesInBits();

		private static Dictionary<HashAlgorithmType, HashAlgorithm> GetHashAlgorithms()
		{
			return new Dictionary<HashAlgorithmType, HashAlgorithm>
			       	{
			       		{HashAlgorithmType.SHA1, new SHA1Managed()},
			       		{HashAlgorithmType.SHA256, new SHA256Managed()},
			       		{HashAlgorithmType.SHA384, new SHA384Managed()},
			       		{HashAlgorithmType.SHA512, new SHA512Managed()},
			       		{HashAlgorithmType.MD5, new MD5CryptoServiceProvider()},
			       	};
		}

		private static Dictionary<HashAlgorithmType, int> GetHashSizesInBits()
		{
			return new Dictionary<HashAlgorithmType, int>
			       	{
			       		{HashAlgorithmType.SHA1, 160},
			       		{HashAlgorithmType.SHA256, 256},
			       		{HashAlgorithmType.SHA384, 384},
			       		{HashAlgorithmType.SHA512, 512},
			       		{HashAlgorithmType.MD5, 128},
			       	};
		}

		internal string CreateSalt(int size)
		{
			var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
			var buffer = new byte[size];
			rngCryptoServiceProvider.GetNonZeroBytes(buffer);
			return Convert.ToBase64String(buffer);
		}

		internal string ComputeHash(string plainText, HashAlgorithmType hashAlgorithmType, string saltBase64Text)
		{
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			var saltBytes = Convert.FromBase64String(saltBase64Text);
			var plainTextWithSaltBytes = Enumerable.ToArray<byte>(plainTextBytes.Combine(saltBytes));
			var hashAlgorithm = HashAlgorithms[hashAlgorithmType];
			var hashBytes = hashAlgorithm.ComputeHash(plainTextWithSaltBytes);
			var hashWithSaltBytes = Enumerable.ToArray<byte>(hashBytes.Combine(saltBytes));
			return Convert.ToBase64String(hashWithSaltBytes);
		}

		internal bool VerifyHash(string plainText, HashAlgorithmType hashAlgorithmType, string hashText)
		{
			var hashWithSaltBytes = Convert.FromBase64String(hashText);
			var hashSizeInBits = HashSizesInBits[hashAlgorithmType];
			var hashSizeInBytes = hashSizeInBits/8;
			if (hashWithSaltBytes.Length < hashSizeInBytes) return false;
			var saltBytes = hashWithSaltBytes.Skip(hashSizeInBytes).ToArray();
			var saltBase64Text = Convert.ToBase64String(saltBytes);
			var expectedHashText = ComputeHash(plainText, hashAlgorithmType, saltBase64Text);
			return (hashText == expectedHashText);
		}

		internal string Encrypt(string plainText, string password, string saltBase64Text, int passwordIterations,
		                        string initializationVector, KeySize keySize)
		{
			if (initializationVector.Length != 16)
				throw new ArgumentException("initializationVector parameter length must be 16.");
			var initializationVectorBytes = Encoding.ASCII.GetBytes(initializationVector);
			var saltValueBytes = Encoding.ASCII.GetBytes(saltBase64Text);
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			var derivedPassword = new Rfc2898DeriveBytes(password, saltValueBytes, passwordIterations);
			var keyBytes = derivedPassword.GetBytes((int) keySize/8);

			var symmetricKey = new RijndaelManaged
			                   	{
			                   		Mode = CipherMode.CBC
			                   	};

			byte[] cipherTextBytes;

			using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, initializationVectorBytes))
			{
				using (var memStream = new MemoryStream())
				{
					using (var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
					{
						cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
						cryptoStream.FlushFinalBlock();
						cipherTextBytes = memStream.ToArray();
						memStream.Close();
						cryptoStream.Close();
					}
				}
			}

			return Convert.ToBase64String(cipherTextBytes);
		}

		internal string Decrypt(string cipherText, string password, string saltBase64Text, int passwordIterations,
		                        string initializationVector, KeySize keySize)
		{
			if (initializationVector.Length != 16)
				throw new ArgumentException("initializationVector parameter length must be 16.");
			var initializationVectorBytes = Encoding.ASCII.GetBytes(initializationVector);
			var saltValueBytes = Encoding.ASCII.GetBytes(saltBase64Text);
			var cipherTextBytes = Convert.FromBase64String(cipherText);
			var derivedPassword = new Rfc2898DeriveBytes(password, saltValueBytes, passwordIterations);
			var keyBytes = derivedPassword.GetBytes((int) keySize/8);

			var symmetricKey = new RijndaelManaged
			                   	{
			                   		Mode = CipherMode.CBC
			                   	};

			var plainTextBytes = new byte[cipherTextBytes.Length];
			int byteCount;

			using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, initializationVectorBytes))
			{
				using (var memStream = new MemoryStream(cipherTextBytes))
				{
					using (var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
					{
						byteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
						memStream.Close();
						cryptoStream.Close();
					}
				}
			}

			return Encoding.UTF8.GetString(plainTextBytes, 0, byteCount);
		}
	}
}