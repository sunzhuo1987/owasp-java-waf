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
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IEncryptedProperties interface is a properties file where all the data is
	/// encrypted before it is added, and decrypted when it retrieved.
	/// <P>
	/// <img src="doc-files/EncryptedProperties.jpg" height="600">
	/// <P>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IEncryptedProperties
	{
		
		/// <summary> Gets the property value from the encrypted store, decrypts it, and returns the plaintext value to the caller.
		/// 
		/// </summary>
		/// <param name="key">the key
		/// 
		/// </param>
		/// <returns> the property
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String getProperty(System.String key);
		
		/// <summary> Encrypts the plaintext property value and stores the ciphertext value in the encrypted store.
		/// 
		/// </summary>
		/// <param name="key">the key
		/// </param>
		/// <param name="value">the value
		/// 
		/// </param>
		/// <returns> the object
		/// 
		/// </returns>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		System.String setProperty(System.String key, System.String value_Renamed);
	}
}