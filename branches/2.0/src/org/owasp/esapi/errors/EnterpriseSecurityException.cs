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
using ESAPI = org.owasp.esapi.ESAPI;
using Logger = org.owasp.esapi.Logger;
namespace org.owasp.esapi.errors
{
	
	/// <summary> EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
	/// exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
	/// appropriate super() method in order to ensure that logging and intrusion detection occur properly.
	/// <P>
	/// All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message
	/// can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile,
	/// all the critical information can be included in the exception so that it gets logged.
	/// <P>
	/// Note that the "logMessage" for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be
	/// used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records.
	/// ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomolous patterns of
	/// application usage.
	/// <P>
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	[Serializable]
	public class EnterpriseSecurityException:System.Exception
	{
		virtual public System.String UserMessage
		{
			get
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				return Message;
			}
			
		}
		virtual public System.String LogMessage
		{
			get
			{
				return logMessage;
			}
			
		}
		
		/// <summary>The Constant serialVersionUID. </summary>
		private const long serialVersionUID = 1L;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.errors.EnterpriseSecurityException'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		protected internal static readonly Logger logger;
		
		protected internal System.String logMessage = null;
		
		/// <summary> Instantiates a new security exception.</summary>
		protected internal EnterpriseSecurityException()
		{
			// hidden
		}
		
		/// <summary> Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
		/// using this API, applications will generate an extensive security log. In addition, this exception is
		/// automatically registered with the IntrusionDetector, so that quotas can be checked.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		public EnterpriseSecurityException(System.String userMessage, System.String logMessage):base(userMessage)
		{
			this.logMessage = logMessage;
			ESAPI.intrusionDetector().addException(this);
		}
		
		/// <summary> Creates a new instance of EnterpriseSecurityException that includes a root cause Throwable.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		/// <param name="cause">the cause
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public EnterpriseSecurityException(System.String userMessage, System.String logMessage, System.Exception cause):base(userMessage, cause)
		{
			this.logMessage = logMessage;
			ESAPI.intrusionDetector().addException(this);
		}
		static EnterpriseSecurityException()
		{
			logger = Logger.getLogger("ESAPI", "EnterpriseSecurityException");
		}
	}
}