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
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The ILogger interface defines a set of methods that can be used to log
	/// security events. Implementors should use a well established logging library
	/// as it is quite difficult to create a high-performance logger.
	/// <P>
	/// <img src="doc-files/Logger.jpg" height="600">
	/// <P>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public struct ILogger_Fields{
		/// <summary>The SECURITY. </summary>
		public readonly static System.String SECURITY = "SECURITY";
		/// <summary>The USABILITY. </summary>
		public readonly static System.String USABILITY = "USABILITY";
		/// <summary>The PERFORMANCE. </summary>
		public readonly static System.String PERFORMANCE = "PERFORMANCE";
	}
	public interface ILogger
	{
		//UPGRADE_NOTE: Members of interface 'ILogger' were extracted into structure 'ILogger_Fields'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1045'"
		
		// FIXME: ENHANCE Is this type approach right? Should it be configurable somehow?
		
		/// <summary> Format the Source IP address, URL, URL parameters, and all form
		/// parameters into a string for the log file. The list of parameters to
		/// obfuscate should be specified in order to prevent sensitive informatiton
		/// from being logged. If a null list is provided, then all parameters will
		/// be logged.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="request">the request
		/// </param>
		/// <param name="sensitiveParams">the sensitive params
		/// </param>
		void  logHTTPRequest(System.String type, System.Web.HttpRequest request, System.Collections.IList parameterNamesToObfuscate);
		
		
		/// <summary> Log critical.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logCritical(System.String type, System.String message);
		
		/// <summary> Log critical.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logCritical(System.String type, System.String message, System.Exception throwable);
		
		/// <summary> Log debug.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logDebug(System.String type, System.String message);
		
		/// <summary> Log debug.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logDebug(System.String type, System.String message, System.Exception throwable);
		
		/// <summary> Log error.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logError(System.String type, System.String message);
		
		/// <summary> Log error.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logError(System.String type, System.String message, System.Exception throwable);
		
		/// <summary> Log success.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logSuccess(System.String type, System.String message);
		
		/// <summary> Log success.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logSuccess(System.String type, System.String message, System.Exception throwable);
		
		/// <summary> Log trace.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logTrace(System.String type, System.String message);
		
		/// <summary> Log trace.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logTrace(System.String type, System.String message, System.Exception throwable);
		
		/// <summary> Log warning.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		void  logWarning(System.String type, System.String message);
		
		/// <summary> Log warning.
		/// 
		/// </summary>
		/// <param name="type">the type
		/// </param>
		/// <param name="message">the message
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		void  logWarning(System.String type, System.String message, System.Exception throwable);
	}
}