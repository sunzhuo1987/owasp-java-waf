/// <summary> OWASP Enterprise Security API (ESAPI)
/// 
/// This file is part of the Open Web Application Security Project (OWASP)
/// Enterprise Security API (ESAPI) project. For details, please see
/// http://www.owasp.org/esapi.
/// 
/// Copyright (c) 2007 - The OWASP Foundation
/// 
/// The ESAPI is published by OWASP under the LGPL. You should read and accept the
/// LICENSE before you use, modify, and/or redistribute this software.
/// 
/// </summary>
/// <author>  Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
/// </author>
/// <created>  2007 </created>
using System;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implemenation of the IRandomizer interface. This implementation builds on the JCE provider to provide a
	/// cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.
	/// 
	/// </summary>
	/// <author>  Jeff Williams
	/// </author>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IRandomizer">
	/// </seealso>
	public class Randomizer : org.owasp.esapi.interfaces.IRandomizer
	{
		virtual public bool RandomBoolean
		{
			/*
			* (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IRandomizer#getRandomBoolean()
			*/
			
			get
			{
				//UPGRADE_ISSUE: Method 'java.util.Random.nextBoolean' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilRandomnextBoolean'"
				return secureRandom.nextBoolean();
			}
			
		}
		virtual public System.String RandomGUID
		{
			get
			{
				// create random string to seed the GUID
				System.Text.StringBuilder sb = new System.Text.StringBuilder();
				try
				{
					//UPGRADE_TODO: The equivalent in .NET for method 'java.net.InetAddress.getLocalHost' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
					sb.Append(System.Net.Dns.GetHostByName(System.Net.Dns.GetHostName()).AddressList[0].ToString());
				}
				catch (System.Exception e)
				{
					sb.Append("0.0.0.0");
				}
				sb.Append(":");
				sb.Append(System.Convert.ToString((System.DateTime.Now.Ticks - 621355968000000000) / 10000));
				sb.Append(":");
				sb.Append(this.getRandomString(20, Encoder.CHAR_ALPHANUMERICS));
				
				// hash the random string to get some random bytes
				System.String hash = ESAPI.encryptor().hash(sb.ToString(), "salt");
				sbyte[] array = null;
				try
				{
					array = ESAPI.encoder().decodeFromBase64(hash);
				}
				catch (System.IO.IOException e)
				{
					logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Problem decoding hash while creating GUID: " + hash);
				}
				
				// convert to printable hexadecimal characters 
				System.Text.StringBuilder hex = new System.Text.StringBuilder();
				for (int j = 0; j < array.Length; ++j)
				{
					int b = array[j] & 0xFF;
					if (b < 0x10)
						hex.Append('0');
					hex.Append(System.Convert.ToString(b, 16));
				}
				System.String raw = hex.ToString().ToUpper();
				
				// convert to standard GUID format
				System.Text.StringBuilder result = new System.Text.StringBuilder();
				result.Append(raw.Substring(0, (8) - (0)));
				result.Append("-");
				result.Append(raw.Substring(8, (12) - (8)));
				result.Append("-");
				result.Append(raw.Substring(12, (16) - (12)));
				result.Append("-");
				result.Append(raw.Substring(16, (20) - (16)));
				result.Append("-");
				result.Append(raw.Substring(20));
				return result.ToString();
			}
			
		}
		
		/// <summary>The sr. </summary>
		private SupportClass.SecureRandomSupport secureRandom = null;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Randomizer'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary> Hide the constructor for the Singleton pattern.</summary>
		public Randomizer()
		{
			System.String algorithm = ESAPI.securityConfiguration().RandomAlgorithm;
			try
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.security.SecureRandom.getInstance' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				secureRandom = new SupportClass.SecureRandomSupport();
			}
			catch (System.Exception e)
			{
				// Can't throw an exception from the constructor, but this will get
				// it logged and tracked
				new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IRandomizer#getRandomString(int, char[])
		*/
		public virtual System.String getRandomString(int length, char[] characterSet)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			for (int loop = 0; loop < length; loop++)
			{
				int index = secureRandom.Next(characterSet.Length);
				sb.Append(characterSet[index]);
			}
			System.String nonce = sb.ToString();
			return nonce;
		}
		
		
		/// <summary> FIXME: ENHANCE document whether this is inclusive or not
		/// (non-Javadoc)
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IRandomizer.getRandomInteger(int, int)">
		/// </seealso>
		public virtual int getRandomInteger(int min, int max)
		{
			return secureRandom.Next(max - min) + min;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IRandomizer#getRandomReal(float, float)
		*/
		public virtual float getRandomReal(float min, float max)
		{
			float factor = max - min;
			return (float) secureRandom.NextDouble() * factor + min;
		}
		
		/// <summary> Returns an unguessable random filename with the specified extension.</summary>
		public virtual System.String getRandomFilename(System.String extension)
		{
			return this.getRandomString(12, Encoder.CHAR_ALPHANUMERICS) + "." + extension;
		}
		
		/// <summary> Union two character arrays.
		/// 
		/// </summary>
		/// <param name="c1">the c1
		/// </param>
		/// <param name="c2">the c2
		/// </param>
		/// <returns> the char[]
		/// </returns>
		public static char[] union(char[] c1, char[] c2)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			for (int i = 0; i < c1.Length; i++)
			{
				if (!contains(sb, c1[i]))
					sb.Append(c1[i]);
			}
			for (int i = 0; i < c2.Length; i++)
			{
				if (!contains(sb, c2[i]))
					sb.Append(c2[i]);
			}
			char[] c3 = new char[sb.Length];
			int i2;
			int j;
			i2 = 0;
			j = 0;
			while (i2 < sb.Length)
			{
				c3[j] = sb[i2];
				i2++;
				j++;
			}
			System.Array.Sort(c3);
			return c3;
		}
		
		/// <summary> Contains.
		/// 
		/// </summary>
		/// <param name="sb">the sb
		/// </param>
		/// <param name="c">the c
		/// </param>
		/// <returns> true, if successful
		/// </returns>
		public static bool contains(System.Text.StringBuilder sb, char c)
		{
			for (int i = 0; i < sb.Length; i++)
			{
				if (sb[i] == c)
					return true;
			}
			return false;
		}
		static Randomizer()
		{
			logger = Logger.getLogger("ESAPI", "Randomizer");
		}
	}
}