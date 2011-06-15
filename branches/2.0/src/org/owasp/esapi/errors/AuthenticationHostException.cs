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
	
	/// <summary> An AuthenticationHostException should be thrown when there is a problem with
	/// the host involved with authentication, particularly if the host changes unexpectedly.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	[Serializable]
	public class AuthenticationHostException:AuthenticationException
	{
		
		/// <summary>The Constant serialVersionUID. </summary>
		private const long serialVersionUID = 1L;
		
		/// <summary> Instantiates a new authentication exception.</summary>
		protected internal AuthenticationHostException()
		{
			// hidden
		}
		
		/// <summary> Creates a new instance of AuthenticationHostException.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		public AuthenticationHostException(System.String userMessage, System.String logMessage):base(userMessage, logMessage)
		{
		}
		
		/// <summary> Instantiates a new authentication exception.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		/// <param name="cause">the cause
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public AuthenticationHostException(System.String userMessage, System.String logMessage, System.Exception cause):base(userMessage, logMessage, cause)
		{
		}
	}
}