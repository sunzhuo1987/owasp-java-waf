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
namespace org.owasp.esapi.errors
{
	
	/// <summary> An EncryptionException should be thrown for any problems related to
	/// encryption, hashing, or digital signatures.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	[Serializable]
	public class EncryptionException:EnterpriseSecurityException
	{
		
		/// <summary>The Constant serialVersionUID. </summary>
		private const long serialVersionUID = 1L;
		
		/// <summary> Instantiates a new EncryptionException.</summary>
		protected internal EncryptionException()
		{
			// hidden
		}
		
		/// <summary> Creates a new instance of EncryptionException.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		public EncryptionException(System.String userMessage, System.String logMessage):base(userMessage, logMessage)
		{
		}
		
		/// <summary> Instantiates a new EncryptionException.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		/// <param name="cause">the cause
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public EncryptionException(System.String userMessage, System.String logMessage, System.Exception cause):base(userMessage, logMessage, cause)
		{
		}
	}
}