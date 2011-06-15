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
using System.Diagnostics;

namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the ILogger interface. This implementation uses the Java logging package, and marks each
	/// log message with the currently logged in user and the word "SECURITY" for security related events.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.ILogger">
	/// </seealso>
	public class Logger : org.owasp.esapi.interfaces.ILogger
	{
		
		// FIXME: ENHANCE somehow make configurable so that successes and failures are logged according to a configuration.
			
		/// <summary>The application name. </summary>
		private System.String applicationName = null;
		
		/// <summary>The module name. </summary>
		private System.String moduleName = null;

        private EventLogEntryType Level = EventLogEntryType.Error;

		/// <summary> Hide the constructor.
		/// 
		/// </summary>
		/// <param name="applicationName">the application name
		/// </param>
		/// <param name="moduleName">the module name
		/// </param>
		/// <param name="jlogger">the jlogger
		/// </param>
		private Logger(System.String applicationName, System.String moduleName)
		{
			this.applicationName = applicationName;
			this.moduleName = moduleName;
            if (!EventLog.SourceExists(applicationName)) {
                EventLog.CreateEventSource(applicationName, moduleName);
            }
		}
		
		/// <summary> Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
		/// hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
		/// the paramaters are presented as though they were in the URL even if they were in a form. Any parameters that
		/// match items in the parameterNamesToObfuscate are shown as eight asterisks.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.ILogger.formatHttpRequestForLog(javax.servlet.http.HttpServletRequest)">
		/// </seealso>
		public virtual void  logHTTPRequest(System.String type, System.Web.HttpRequest request, System.Collections.IList parameterNamesToObfuscate)
		{
			System.Text.StringBuilder params_Renamed = new System.Text.StringBuilder();
			//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
			//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getParameterMap' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetParameterMap'"
			System.Collections.IEnumerator i = new SupportClass.HashSetSupport(request.getParameterMap().Keys).GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String key = (System.String) i.Current;
				//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getParameterMap' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetParameterMap'"
				System.String[] value_Renamed = (System.String[]) request.getParameterMap()[key];
				for (int j = 0; j < value_Renamed.Length; j++)
				{
					params_Renamed.Append(key + "=");
					if (parameterNamesToObfuscate.Contains(key))
					{
						params_Renamed.Append("********");
					}
					else
					{
						params_Renamed.Append(value_Renamed[j]);
					}
					if (j < value_Renamed.Length - 1)
					{
						params_Renamed.Append("&");
					}
				}
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				if (i.MoveNext())
					params_Renamed.Append("&");
			}
			System.String msg = request.HttpMethod + " " + SupportClass.GetRequestURL(request) + (params_Renamed.Length > 0?"?" + params_Renamed:"");
			logSuccess(type, msg);
		}
		
		/// <summary> Gets the logger.
		/// 
		/// </summary>
		/// <param name="applicationName">the application name
		/// </param>
		/// <param name="moduleName">the module name
		/// </param>
		/// <returns> the logger
		/// </returns>
		public static Logger getLogger(System.String applicationName, System.String moduleName)
		{
			return new Logger(applicationName, moduleName);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logTrace(short, java.lang.String, java.lang.String, java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logTrace(System.String type, System.String message, System.Exception throwable)
		{
			log(EventLogEntryType.Warning, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logTrace(java.lang.String, java.lang.String)
		*/
		public virtual void  logTrace(System.String type, System.String message)
		{
            log(EventLogEntryType.Warning, type, message, null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logDebug(short, java.lang.String, java.lang.String, java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logDebug(System.String type, System.String message, System.Exception throwable)
		{
            log(EventLogEntryType.Information, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logDebug(java.lang.String, java.lang.String)
		*/
		public virtual void  logDebug(System.String type, System.String message)
		{
            log(EventLogEntryType.Information, type, message, null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logError(short, java.lang.String, java.lang.String, java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logError(System.String type, System.String message, System.Exception throwable)
		{
            log(EventLogEntryType.Error, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logError(java.lang.String, java.lang.String)
		*/
		public virtual void  logError(System.String type, System.String message)
		{
            log(EventLogEntryType.Error, type, message, null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
		* java.lang.Throwable)
		*/
		public virtual void  logSuccess(System.String type, System.String message)
		{
            log(EventLogEntryType.SuccessAudit, type, message, null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
		* java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logSuccess(System.String type, System.String message, System.Exception throwable)
		{
            log(EventLogEntryType.SuccessAudit, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logWarning(short, java.lang.String, java.lang.String,
		* java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logWarning(System.String type, System.String message, System.Exception throwable)
		{
            log(EventLogEntryType.Warning, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logWarning(java.lang.String, java.lang.String)
		*/
		public virtual void  logWarning(System.String type, System.String message)
		{
            log(EventLogEntryType.Warning, type, message, null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logCritical(short, java.lang.String, java.lang.String,
		* java.lang.Throwable)
		*/
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logCritical(System.String type, System.String message, System.Exception throwable)
		{
            log(EventLogEntryType.Error, type, message, throwable);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.ILogger#logCritical(java.lang.String, java.lang.String)
		*/
		public virtual void  logCritical(System.String type, System.String message)
		{
            log(EventLogEntryType.Error, type, message, null);
		}
		
		/// <summary> Log the message after optionally encoding any special characters that might inject into an HTML based log viewer.
		/// 
		/// </summary>
		/// <param name="message">the message
		/// </param>
		/// <param name="level">the level
		/// </param>
		/// <param name="type">the type
		/// </param>
		/// <param name="throwable">the throwable
		/// </param>
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		private void log(EventLogEntryType level, System.String type, System.String message, System.Exception throwable)
		{
			User user = ESAPI.authenticator().getCurrentUser();
			
			System.String clean = message;
			if (((SecurityConfiguration) ESAPI.securityConfiguration()).LogEncodingRequired)
			{
				clean = ESAPI.encoder().encodeForHTML(message);
				if (!message.Equals(clean))
				{
					clean += " (Encoded)";
				}
			}
			if (throwable != null)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Class.getName' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				System.String fqn = throwable.GetType().FullName;
				int index = fqn.LastIndexOf('.');
				if (index > 0)
					fqn = fqn.Substring(index + 1);
				StackTraceElement ste = throwable.getStackTrace()[0];
				clean += ("\n    " + fqn + " @ " + ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() + ":" + ste.getLineNumber() + ")");
			}
			System.String msg = "";
			if (user != null)
			{
				msg = type + ": " + user.AccountName + "/" + user.getLastHostAddress() + " -- " + clean;
			}
			
			// FIXME: AAA need to configure Java logger not to show throwables
			// jlogger.logp(level, applicationName, moduleName, msg, throwable);			
            EventLog.WriteEntry(applicationName, msg, level);
		}
		
		/// <summary> This special method doesn't include the current user's identity, and is only used during system initialization to
		/// prevent loops with the Authenticator.
		/// 
		/// </summary>
		/// <param name="level">
		/// </param>
		/// <param name="message">
		/// </param>
		/// <param name="throwable">
		/// </param>
		// FIXME: this needs to go - note potential log injection problem
		//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
		public virtual void  logSpecial(System.String message, System.Exception throwable)
		{
			// String clean = ESAPI.encoder().encodeForHTML(message);
			// if (!message.equals(clean)) {
			//     clean += "(Encoded)";
			// }
			System.String msg = "SECURITY" + ": " + "esapi" + "/" + "none" + " -- " + message;
            EventLog.WriteEntry(applicationName, msg, level);
		}
	}
}