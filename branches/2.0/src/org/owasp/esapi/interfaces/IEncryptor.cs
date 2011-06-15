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
using IntegrityException = org.owasp.esapi.errors.IntegrityException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IEncryptor interface provides a set of methods for performing common
	/// encryption, random number, and hashing operations. Implementations should
	/// rely on a strong cryptographic implementation, such as JCE or BouncyCastle.
	/// Implementors should take care to ensure that they initialize their
	/// implementation with a strong "master key", and that they protect this secret
	/// as much as possible.
	/// <P>
	/// <img src="doc-files/Encryptor.jpg" height="600">
	/// <P>
	/// Possible future enhancements (depending on feedback) might include:
	/// <UL>
	/// <LI>encryptFile</LI>
	/// </UL>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IEncryptor
	{
		/// <summary> Gets a timestamp representing the current date and time to be used by
		/// other functions in the library.
		/// 
		/// </summary>
		/// <returns> the timestamp
		/// </returns>
		long TimeStamp
		{
			get;
			
		}
		
		/// <summary> Returns a string representation of the hash of the provided plaintext and
		/// salt. The salt helps to protect against a rainbow table attack by mixing
		/// in some extra data with the plaintext. Some good choices for a salt might
		/// be an account name or some other string that is known to the application
		/// but not to an attacker. See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">this article</a> for 
		/// more information about hashing as it pertains to password schemes.
		/// 
		/// </summary>
		/// <param name="plaintext">the plaintext
		/// </param>
		/// <param name="salt">the salt
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String hash(System.String plaintext, System.String salt);
		
		/// <summary> Encrypts the provided plaintext and returns a ciphertext string.
		/// 
		/// </summary>
		/// <param name="plaintext">the plaintext
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String encrypt(System.String plaintext);
		
		/// <summary> Decrypts the provided ciphertext string (encrypted with the encrypt
		/// method) and returns a plaintext string.
		/// 
		/// </summary>
		/// <param name="ciphertext">the ciphertext
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String decrypt(System.String ciphertext);
		
		/// <summary> Create a digital signature for the provided data and return it in a
		/// string.
		/// 
		/// </summary>
		/// <param name="data">the data
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String sign(System.String data);
		
		/// <summary> Verifies a digital signature (created with the sign method) and returns
		/// the boolean result.
		/// 
		/// </summary>
		/// <param name="signature">the signature
		/// </param>
		/// <param name="data">the data
		/// 
		/// </param>
		/// <returns> true, if successful
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		bool verifySignature(System.String signature, System.String data);
		
		/// <summary> Creates a seal that binds a set of data and an expiration timestamp.
		/// 
		/// </summary>
		/// <param name="data">the data
		/// </param>
		/// <param name="timestamp">the timestamp of the expiration date of the data.
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String seal(System.String data, long timestamp);
		
		/// <summary> Verifies a seal (created with the seal method) and throws an exception
		/// describing any of the various problems that could exist with a seal, such
		/// as an invalid seal format, expired timestamp, or data mismatch.
		/// 
		/// </summary>
		/// <param name="seal">the seal
		/// </param>
		/// <param name="data">the data
		/// </param>
		bool verifySeal(System.String seal, System.String data);
	}
}