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
	
	/// <summary> The IRandomizer interface defines a set of methods for creating
	/// cryptographically random numbers and strings. Implementers should be sure to
	/// use a strong cryptographic implementation, such as the JCE or BouncyCastle.
	/// Weak sources of randomness can undermine a wide variety of security
	/// mechanisms.
	/// <P>
	/// <img src="doc-files/Randomizer.jpg" height="600">
	/// <P>
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IRandomizer
	{
		/// <summary> Returns a random boolean.</summary>
		/// <returns>
		/// </returns>
		bool RandomBoolean
		{
			get;
			
		}
		/// <summary> Generates a random GUID.</summary>
		/// <returns> the GUID
		/// </returns>
		/// <throws>  EncryptionException  </throws>
		System.String RandomGUID
		{
			get;
			
		}
		
		/// <summary> Gets the random string.
		/// 
		/// </summary>
		/// <param name="length">the length
		/// </param>
		/// <param name="characterSet">the character set
		/// 
		/// </param>
		/// <returns> the random string
		/// </returns>
		System.String getRandomString(int length, char[] characterSet);
		
		/// <summary> Gets the random integer.
		/// 
		/// </summary>
		/// <param name="min">the min
		/// </param>
		/// <param name="max">the max
		/// 
		/// </param>
		/// <returns> the random integer
		/// </returns>
		int getRandomInteger(int min, int max);
		
		/// <summary> Returns an unguessable random filename with the specified extension.</summary>
		System.String getRandomFilename(System.String extension);
		
		
		/// <summary> Gets the random real.
		/// 
		/// </summary>
		/// <param name="min">the min
		/// </param>
		/// <param name="max">the max
		/// 
		/// </param>
		/// <returns> the random real
		/// </returns>
		float getRandomReal(float min, float max);
	}
}