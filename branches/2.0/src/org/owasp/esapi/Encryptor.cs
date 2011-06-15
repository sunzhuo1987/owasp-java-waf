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
using System.Text;
using RedCorona.Cryptography;
using System.Security.Cryptography;

using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using IntegrityException = org.owasp.esapi.errors.IntegrityException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IEncryptor interface. This implementation
	/// layers on the JCE provided cryptographic package. Algorithms used are
	/// configurable in the ESAPI.properties file.
	/// 
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IEncryptor">
	/// </seealso>
	public class Encryptor : org.owasp.esapi.interfaces.IEncryptor
	{
		virtual public long TimeStamp
		{
			/*
			* (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IEncryptor#getTimeStamp()
			*/
			
			get
			{
				//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
				return System.DateTime.Now.Ticks;
			}
			
		}
		
		/// <summary>The private key. </summary>
		internal SupportClass.PrivateKeySupport privateKey = null;
		
		/// <summary>The public key. </summary>
		internal SupportClass.PublicKeySupport publicKey = null;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Encryptor'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		// FIXME: AAA need global scrub of what methods need to log
		
		//UPGRADE_ISSUE: Class 'javax.crypto.spec.PBEParameterSpec' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxcryptospecPBEParameterSpec'"
		internal PKCSKeyGenerator parameterSpec = null;
		internal System.Security.Cryptography.SymmetricAlgorithm secretKey = null;
		internal System.String encryptAlgorithm = "PBEWithMD5AndDES";
		internal System.String signatureAlgorithm = "SHAwithDSA";
		internal System.String hashAlgorithm = "SHA-512";
		internal System.String randomAlgorithm = "SHA1PRNG";
		internal System.String encoding = "UTF-8";
		
		public Encryptor()
		{
			
			// FIXME: AAA - need support for key and salt changing. What's best interface?
			sbyte[] salt = ESAPI.securityConfiguration().MasterSalt;
			char[] pass = ESAPI.securityConfiguration().MasterPassword;
			
			// setup algorithms
			encryptAlgorithm = ESAPI.securityConfiguration().EncryptionAlgorithm;
			signatureAlgorithm = ESAPI.securityConfiguration().DigitalSignatureAlgorithm;
			randomAlgorithm = ESAPI.securityConfiguration().RandomAlgorithm;
			hashAlgorithm = ESAPI.securityConfiguration().HashAlgorithm;
			
			try
			{                
				//UPGRADE_NOTE: Cryptographic classes that handle keys behave differently in the .NET Framework.  "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1288'"
				//UPGRADE_TODO: A transformation string might not be supported by the classes in the System.Security.Cryptography namespace. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1287'"
				System.Security.Cryptography.SymmetricAlgorithm kf = System.Security.Cryptography.SymmetricAlgorithm.Create(encryptAlgorithm);
				new System.Security.Cryptography.PasswordDeriveBytes(new String(pass), null);
				//UPGRADE_TODO: Method 'javax.crypto.SecretKeyFactory.generateSecret' was converted to 'System.Security.Cryptography.SymmetricAlgorithm.GenerateKey' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxcryptoSecretKeyFactorygenerateSecret_javasecurityspecKeySpec'"
				secretKey = kf.GenerateKey();
				encoding = ESAPI.securityConfiguration().CharacterEncoding;
				
				// Set up signing keypair using the master password and salt
				// FIXME: Enhance - make DSA configurable
				//UPGRADE_ISSUE: Class 'java.security.KeyPairGenerator' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javasecurityKeyPairGenerator'"
				//UPGRADE_ISSUE: Method 'java.security.KeyPairGenerator.getInstance' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javasecurityKeyPairGenerator'"
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
				//UPGRADE_TODO: The equivalent in .NET for method 'java.security.SecureRandom.getInstance' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				SupportClass.SecureRandomSupport random = new SupportClass.SecureRandomSupport();
				sbyte[] seed = SupportClass.ToSByteArray(SupportClass.ToByteArray(hash(new System.String(pass), new System.String(SupportClass.ToCharArray(SupportClass.ToByteArray(salt))))));
				random.SetSeed(SupportClass.ToByteArray(seed));
				//UPGRADE_ISSUE: Method 'java.security.KeyPairGenerator.initialize' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javasecurityKeyPairGenerator'"
				keyGen.initialize(1024, random);
				//UPGRADE_TODO: The class 'java.security.KeyPair' was converted to 'SupportClass.KeyPairSupport', which is not serializable. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1277'"
				//UPGRADE_ISSUE: Method 'java.security.KeyPairGenerator.generateKeyPair' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javasecurityKeyPairGenerator'"
				SupportClass.KeyPairSupport pair = keyGen.generateKeyPair();
				privateKey = pair.Private;
				publicKey = pair.Public;
			}
			catch (System.Exception e)
			{
				// can't throw this exception in initializer, but this will log it
				new EncryptionException("Encryption failure", "Error creating Encryptor", e);
			}
		}
		
		/// <summary> Hashes the data using the specified algorithm and the Java MessageDigest class. This method
		/// first adds the salt, then the data, and then rehashes 1024 times to help strengthen weak passwords.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IEncryptor.hash(java.lang.String,java.lang.String)">
		/// </seealso>
		public virtual System.String hash(System.String plaintext, System.String salt)
		{
			sbyte[] bytes = null;
			try
			{
				SupportClass.MessageDigestSupport digest = SupportClass.MessageDigestSupport.GetInstance(hashAlgorithm);
				digest.Reset();
				digest.Update(SupportClass.ToByteArray(ESAPI.securityConfiguration().MasterSalt));
				digest.Update(SupportClass.ToByteArray(salt));
				digest.Update(SupportClass.ToByteArray(plaintext));
				
				// rehash a number of times to help strengthen weak passwords
				// FIXME: ENHANCE make iterations configurable
				bytes = digest.DigestData();
				for (int i = 0; i < 1024; i++)
				{
					digest.Reset();
					bytes = digest.DigestData(bytes);
				}
				System.String encoded = ESAPI.encoder().encodeForBase64(bytes, false);
				return encoded;
			}
			catch (System.Exception e)
			{
				throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#encrypt(java.lang.String)
		*/
		public virtual System.String encrypt(System.String plaintext)
		{
			// Note - Cipher is not threadsafe so we create one locally
			try
			{
				SupportClass.CryptoSupport encrypter = new SupportClass.CryptoSupport(encryptAlgorithm);
                ICryptoTransform parameterSpec = PKCSKeyGenerator.Generate(this.secretKey, (new ASCIIEncoding().GetBytes(salt)), 20, 1);
                
                //encrypter.CryptoInit(System.Security.Cryptography.CryptoStreamMode.Write, secretKey, parameterSpec);
				//UPGRADE_TODO: Method 'java.lang.String.getBytes' was converted to 'System.Text.Encoding.GetEncoding(string).GetBytes(string)' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangStringgetBytes_javalangString'"
				sbyte[] output = SupportClass.ToSByteArray(System.Text.Encoding.GetEncoding(encoding).GetBytes(plaintext));
                parameterSpec.TransformBlock(ouput, 0, output.Length);
                sbyte[] enc = encrypter.CryptoDoFinal(output);
				return ESAPI.encoder().encodeForBase64(enc, false);
			}
			catch (System.Exception e)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				throw new EncryptionException("Decryption failure", "Decryption problem: " + e.Message, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#decrypt(java.lang.String)
		*/
		public virtual System.String decrypt(System.String ciphertext)
		{
			// Note - Cipher is not threadsafe so we create one locally
			try
			{
				SupportClass.CryptoSupport decrypter = new SupportClass.CryptoSupport(encryptAlgorithm);
				decrypter.CryptoInit(System.Security.Cryptography.CryptoStreamMode.Read, secretKey, parameterSpec);
				sbyte[] dec = ESAPI.encoder().decodeFromBase64(ciphertext);
				sbyte[] output = decrypter.CryptoDoFinal(dec);
				//UPGRADE_TODO: The differences in the Format  of parameters for constructor 'java.lang.String.String'  may cause compilation errors.  "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1092'"
				return System.Text.Encoding.GetEncoding(encoding).GetString(SupportClass.ToByteArray(output));
			}
			catch (System.Exception e)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				throw new EncryptionException("Decryption failed", "Decryption problem: " + e.Message, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#sign(java.lang.String)
		*/
		public virtual System.String sign(System.String data)
		{
			System.String signatureAlgorithm = "SHAwithDSA";
			try
			{
				SupportClass.DigitalSignature signer = SupportClass.DigitalSignature.GetInstance(signatureAlgorithm);;
				//UPGRADE_TODO: Method 'java.security.Signature.initSign' was converted to 'SupportClass.DigitalSignature.Signing' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javasecuritySignatureinitSign_javasecurityPrivateKey'"
				signer.Signing();
				signer.Update(SupportClass.ToByteArray(data));
				//UPGRADE_TODO: Method 'java.security.Signature.sign' was converted to 'SupportClass.DigitalSignature.Sign' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javasecuritySignaturesign'"
				sbyte[] bytes = SupportClass.ToSByteArray(signer.Sign());
				return ESAPI.encoder().encodeForBase64(bytes, true);
			}
			catch (System.Exception e)
			{
				throw new EncryptionException("Signature failure", "Can't find signature algorithm " + signatureAlgorithm, e);
			}
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#verifySignature(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool verifySignature(System.String signature, System.String data)
		{
			try
			{
				sbyte[] bytes = ESAPI.encoder().decodeFromBase64(signature);
				SupportClass.DigitalSignature signer = SupportClass.DigitalSignature.GetInstance(signatureAlgorithm);;
				//UPGRADE_TODO: Method 'java.security.Signature.initVerify' was converted to 'SupportClass.DigitalSignature.Verification' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javasecuritySignatureinitVerify_javasecurityPublicKey'"
				signer.Verification();
				signer.Update(SupportClass.ToByteArray(data));
				//UPGRADE_TODO: Method 'java.security.Signature.verify' was converted to 'SupportClass.DigitalSignature.Verify' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javasecuritySignatureverify_byte[]'"
				return signer.Verify(SupportClass.ToByteArray(bytes));
			}
			catch (System.Exception e)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				new EncryptionException("Invalid signature", "Problem verifying signature: " + e.Message, e);
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#seal(java.lang.String,
		*      java.lang.String)
		*/
		public virtual System.String seal(System.String data, long expiration)
		{
			try
			{
				return this.encrypt(expiration + ":" + data);
			}
			catch (EncryptionException e)
			{
				throw new IntegrityException(e.UserMessage, e.LogMessage, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptor#verifySeal(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool verifySeal(System.String seal, System.String data)
		{
			System.String plaintext = null;
			try
			{
				plaintext = decrypt(seal);
			}
			catch (EncryptionException e)
			{
				new EncryptionException("Invalid seal", "Seal did not decrypt properly", e);
				return false;
			}
			
			int index = plaintext.IndexOf(":");
			if (index == - 1)
			{
				new EncryptionException("Invalid seal", "Seal did not contain properly formatted separator");
				return false;
			}
			
			System.String timestring = plaintext.Substring(0, (index) - (0));
			//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
			long now = System.DateTime.Now.Ticks;
			long expiration = System.Int64.Parse(timestring);
			if (now > expiration)
			{
				new EncryptionException("Invalid seal", "Seal expiration date has expired");
				return false;
			}
			
			System.String sealedValue = plaintext.Substring(index + 1);
			if (!sealedValue.Equals(data))
			{
				new EncryptionException("Invalid seal", "Seal data does not match");
				return false;
			}
			return true;
		}
		static Encryptor()
		{
			logger = Logger.getLogger("ESAPI", "Encryptor");
		}
	}
}