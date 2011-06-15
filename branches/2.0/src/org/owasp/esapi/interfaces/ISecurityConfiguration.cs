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
using Threshold = org.owasp.esapi.Threshold;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The ISecurityConfiguration interface stores all configuration information
	/// that directs the behavior of the ESAPI implementation.
	/// <P>
	/// <img src="doc-files/SecurityConfiguration.jpg" height="600">
	/// <P>
	/// Protection of this configuration information is critical to the secure
	/// operation of the application using the ESAPI. You should use operating system
	/// access controls to limit access to wherever the configuration information is
	/// stored. Please note that adding another layer of encryption does not make the
	/// attackers job much more difficult. Somewhere there must be a master "secret"
	/// that is stored unencrypted on the application platform. Creating another
	/// layer of indirection doesn't provide any real additional security.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface ISecurityConfiguration
	{
		/// <summary> Gets the master password.
		/// 
		/// </summary>
		/// <returns> the master password
		/// </returns>
		char[] MasterPassword
		{
			get;
			
		}
		/// <summary> Gets the keystore.
		/// 
		/// </summary>
		/// <returns> the keystore
		/// </returns>
		System.IO.FileInfo Keystore
		{
			get;
			
		}
		/// <summary> Gets the master salt.
		/// 
		/// </summary>
		/// <returns> the master salt
		/// </returns>
		sbyte[] MasterSalt
		{
			get;
			
		}
		/// <summary> Gets the allowed file extensions.
		/// 
		/// </summary>
		/// <returns> the allowed file extensions
		/// </returns>
		System.Collections.IList AllowedFileExtensions
		{
			get;
			
		}
		/// <summary> Gets the allowed file upload size.
		/// 
		/// </summary>
		/// <returns> the allowed file upload size
		/// </returns>
		int AllowedFileUploadSize
		{
			get;
			
		}
		/// <summary> Gets the password parameter name.
		/// 
		/// </summary>
		/// <returns> the password parameter name
		/// </returns>
		System.String PasswordParameterName
		{
			get;
			
		}
		/// <summary> Gets the username parameter name.
		/// 
		/// </summary>
		/// <returns> the username parameter name
		/// </returns>
		System.String UsernameParameterName
		{
			get;
			
		}
		/// <summary> Gets the encryption algorithm.
		/// 
		/// </summary>
		/// <returns> the algorithm
		/// </returns>
		System.String EncryptionAlgorithm
		{
			get;
			
		}
		/// <summary> Gets the hasing algorithm.
		/// 
		/// </summary>
		/// <returns> the algorithm
		/// </returns>
		System.String HashAlgorithm
		{
			get;
			
		}
		/// <summary> Gets the character encoding.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		System.String CharacterEncoding
		{
			get;
			
		}
		/// <summary> Gets the digital signature algorithm.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		System.String DigitalSignatureAlgorithm
		{
			get;
			
		}
		/// <summary> Gets the random number generation algorithm.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		System.String RandomAlgorithm
		{
			get;
			
		}
		/// <summary> Gets the allowed login attempts.
		/// 
		/// </summary>
		/// <returns> the allowed login attempts
		/// </returns>
		int AllowedLoginAttempts
		{
			get;
			
		}
		/// <summary> Gets the max old password hashes.
		/// 
		/// </summary>
		/// <returns> the max old password hashes
		/// </returns>
		int MaxOldPasswordHashes
		{
			get;
			
		}
		
		/// <summary> Gets an intrusion detection Quota.
		/// 
		/// </summary>
		/// <param name="eventName">
		/// </param>
		/// <returns> the matching Quota
		/// </returns>
		Threshold getQuota(System.String eventName);
	}
}