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
namespace org.owasp.esapi.errors
{
	
	/// <summary> The Class AccessReferenceMapTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class EnterpriseSecurityExceptionTest:TestCase
	{
		
		/// <summary> Instantiates a new access reference map test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public EnterpriseSecurityExceptionTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(EnterpriseSecurityExceptionTest));
			return suite;
		}
		
		
		/// <summary> Test of update method, of class org.owasp.esapi.AccessReferenceMap.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testExceptions()
		{
			System.Console.Out.WriteLine("exceptions");
			EnterpriseSecurityException e = null;
			e = new EnterpriseSecurityException();
			e = new EnterpriseSecurityException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new EnterpriseSecurityException("m1", "m2", new System.Exception());
			assertEquals(e.UserMessage, "m1");
			assertEquals(e.LogMessage, "m2");
			e = new AccessControlException();
			e = new AccessControlException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AccessControlException("m1", "m2", new System.Exception());
			e = new AuthenticationException();
			e = new AuthenticationException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AuthenticationException("m1", "m2", new System.Exception());
			e = new AvailabilityException();
			e = new AvailabilityException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AvailabilityException("m1", "m2", new System.Exception());
			e = new CertificateException();
			e = new CertificateException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new CertificateException("m1", "m2", new System.Exception());
			e = new EncodingException();
			e = new EncodingException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new EncodingException("m1", "m2", new System.Exception());
			e = new EncryptionException();
			e = new EncryptionException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new EncryptionException("m1", "m2", new System.Exception());
			e = new ExecutorException();
			e = new ExecutorException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new ExecutorException("m1", "m2", new System.Exception());
			e = new ValidationException();
			e = new ValidationException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new ValidationException("m1", "m2", new System.Exception());
			
			e = new AuthenticationAccountsException();
			e = new AuthenticationAccountsException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AuthenticationAccountsException("m1", "m2", new System.Exception());
			e = new AuthenticationCredentialsException();
			e = new AuthenticationCredentialsException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AuthenticationCredentialsException("m1", "m2", new System.Exception());
			e = new AuthenticationLoginException();
			e = new AuthenticationLoginException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new AuthenticationLoginException("m1", "m2", new System.Exception());
			e = new ValidationAvailabilityException();
			e = new ValidationAvailabilityException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new ValidationAvailabilityException("m1", "m2", new System.Exception());
			e = new ValidationUploadException();
			e = new ValidationUploadException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			e = new ValidationUploadException("m1", "m2", new System.Exception());
			
			IntrusionException ex = new IntrusionException();
			ex = new IntrusionException("m1", "m2");
			//UPGRADE_NOTE: Exception 'java.lang.Throwable' was converted to 'System.Exception' which has different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1100'"
			ex = new IntrusionException("m1", "m2", new System.Exception());
			assertEquals(ex.UserMessage, "m1");
			assertEquals(ex.LogMessage, "m2");
		}
	}
}