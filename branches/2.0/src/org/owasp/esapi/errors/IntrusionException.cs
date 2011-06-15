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
using Logger = org.owasp.esapi.Logger;
namespace org.owasp.esapi.errors
{
	
	/// <summary> An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack
	/// in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by
	/// either specially logging the event, logging out the current user, or invalidating the current user's account.
	/// <P>
	/// Unlike other exceptions in the ESAPI, the IntrusionException is a RuntimeException so that it can be thrown from
	/// anywhere and will not require a lot of special exception handling.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	[Serializable]
	public class IntrusionException:System.SystemException
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
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.errors.IntrusionException'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		protected internal static readonly Logger logger;
		
		protected internal System.String logMessage = null;
		
		/// <summary> Internal classes may throw an IntrusionException to the IntrusionDetector, which generates the appropriate log
		/// message.
		/// </summary>
		public IntrusionException():base()
		{
		}
		
		/// <summary> Creates a new instance of IntrusionException.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		public IntrusionException(System.String userMessage, System.String logMessage):base(userMessage)
		{
			this.logMessage = logMessage;
			logger.logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "INTRUSION - " + logMessage);
		}
		
		/// <summary> Instantiates a new intrusion exception.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		/// <param name="cause">the cause
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public IntrusionException(System.String userMessage, System.String logMessage, System.Exception cause):base(userMessage, cause)
		{
			this.logMessage = logMessage;
			logger.logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "INTRUSION - " + logMessage, cause);
		}
		static IntrusionException()
		{
			logger = Logger.getLogger("ESAPI", "IntrusionException");
		}
	}
}