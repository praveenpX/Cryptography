namespace Common.Cryptography
{
	public class CryptographyServiceConfiguration
	{
		public string SaltBase64Text { get; set; }

		//Must be at least 8 byte length
		public string Password { get; set; }

		public int PasswordIterations { get; set; }

		public string InitializationVector { get; set; }

		//Must be 16 length vector
		public KeySize KeySize { get; set; }
	}
}