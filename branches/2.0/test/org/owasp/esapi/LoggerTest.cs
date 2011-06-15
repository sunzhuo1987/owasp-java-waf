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
//UPGRADE_TODO: The type 'junit.framework.Test' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Test = junit.framework.Test;
//UPGRADE_TODO: The type 'junit.framework.TestCase' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using TestCase = junit.framework.TestCase;
//UPGRADE_TODO: The type 'junit.framework.TestSuite' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using TestSuite = junit.framework.TestSuite;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
using TestHttpServletRequest = org.owasp.esapi.http.TestHttpServletRequest;
namespace org.owasp.esapi
{
	
	/// <summary> The Class LoggerTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class LoggerTest:TestCase
	{
		
		/// <summary> Instantiates a new logger test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public LoggerTest(System.String testName):base(testName)
		{
		}
		
		/* (non-Javadoc)
		* @see junit.framework.TestCase#setUp()
		*/
		protected internal virtual void  setUp()
		{
			// none
		}
		
		/* (non-Javadoc)
		* @see junit.framework.TestCase#tearDown()
		*/
		protected internal virtual void  tearDown()
		{
			// none
		}
		
		/// <summary> Suite.
		/// 
		/// </summary>
		/// <returns> the test
		/// </returns>
		public static Test suite()
		{
			TestSuite suite = new TestSuite(typeof(LoggerTest));
			
			return suite;
		}
		
		/// <summary> Test of logHTTPRequest method, of class org.owasp.esapi.Logger.
		/// 
		/// </summary>
		/// <throws>  ValidationException </throws>
		/// <summary>             the validation exception
		/// </summary>
		/// <throws>  IOException </throws>
		/// <summary>             Signals that an I/O exception has occurred.
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testLogHTTPRequest()
		{
			System.Console.Out.WriteLine("logHTTPRequest");
			System.String[] ignore = new System.String[]{"password", "ssn", "ccn"};
			TestHttpServletRequest request = new TestHttpServletRequest();
			// FIXME: AAA modify to return the actual string logged (so we can test)
			//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
			Logger.getLogger("logger", "logger").logHTTPRequest(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, request, new System.Collections.ArrayList(ignore));
			request.addParameter("one", "one");
			request.addParameter("two", "two1");
			request.addParameter("two", "two2");
			request.addParameter("password", "jwilliams");
			//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
			Logger.getLogger("logger", "logger").logHTTPRequest(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, request, new System.Collections.ArrayList(ignore));
		}
		
		/// <summary> Test of logSuccess method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogSuccess()
		{
			System.Console.Out.WriteLine("logSuccess");
			Logger.getLogger("app", "mod").logSuccess(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logSuccess(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
			Logger.getLogger("app", "mod").logSuccess(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "%3escript%3f test message", null);
			Logger.getLogger("app", "mod").logSuccess(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "<script> test message", null);
		}
		
		
		/// <summary> Test of logTrace method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogTrace()
		{
			System.Console.Out.WriteLine("logTrace");
			Logger.getLogger("app", "mod").logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
		}
		
		/// <summary> Test of logDebug method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogDebug()
		{
			System.Console.Out.WriteLine("logDebug");
			Logger.getLogger("app", "mod").logDebug(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logDebug(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
		}
		
		/// <summary> Test of logError method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogError()
		{
			System.Console.Out.WriteLine("logError");
			Logger.getLogger("app", "mod").logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
		}
		
		/// <summary> Test of logWarning method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogWarning()
		{
			System.Console.Out.WriteLine("logWarning");
			Logger.getLogger("app", "mod").logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
		}
		
		/// <summary> Test of logCritical method, of class org.owasp.esapi.Logger.</summary>
		public virtual void  testLogCritical()
		{
			System.Console.Out.WriteLine("logCritical");
			Logger.getLogger("app", "mod").logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message");
			Logger.getLogger("app", "mod").logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "test message", null);
		}
	}
}