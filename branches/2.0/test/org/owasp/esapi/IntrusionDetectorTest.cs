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
using IntegrityException = org.owasp.esapi.errors.IntegrityException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using TestHttpServletRequest = org.owasp.esapi.http.TestHttpServletRequest;
using TestHttpServletResponse = org.owasp.esapi.http.TestHttpServletResponse;
namespace org.owasp.esapi
{
	
	/// <summary> The Class IntrusionDetectorTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class IntrusionDetectorTest:TestCase
	{
		
		/// <summary> Instantiates a new intrusion detector test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public IntrusionDetectorTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(IntrusionDetectorTest));
			
			return suite;
		}
		
		/// <summary> Test of addException method, of class org.owasp.esapi.IntrusionDetector.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testAddException()
		{
			System.Console.Out.WriteLine("addException");
			ESAPI.intrusionDetector().addException(new IntrusionException("user message", "log message"));
			System.String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			Authenticator auth = (Authenticator) ESAPI.authenticator();
			User user = auth.createUser(username, "addException", "addException");
			user.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			auth.setCurrentHTTP(request, response);
			user.loginWithPassword("addException");
			
			// Now generate some exceptions to disable account
			for (int i = 0; i < ESAPI.securityConfiguration().getQuota("org.owasp.esapi.errors.IntegrityException").count; i++)
			{
				// EnterpriseSecurityExceptions are added to IntrusionDetector automatically
				new IntegrityException("IntegrityException " + i, "IntegrityException " + i);
			}
			assertFalse(user.LoggedIn);
		}
		
		
		/// <summary> Test of addEvent method, of class org.owasp.esapi.IntrusionDetector.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testAddEvent()
		{
			System.Console.Out.WriteLine("addEvent");
			System.String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			Authenticator auth = (Authenticator) ESAPI.authenticator();
			User user = auth.createUser(username, "addEvent", "addEvent");
			user.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			auth.setCurrentHTTP(request, response);
			user.loginWithPassword("addEvent");
			
			// Now generate some events to disable user account
			for (int i = 0; i < ESAPI.securityConfiguration().getQuota("event.test").count; i++)
			{
				ESAPI.intrusionDetector().addEvent("test");
			}
			assertFalse(user.Enabled);
		}
	}
}