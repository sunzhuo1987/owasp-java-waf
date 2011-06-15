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
using IAccessController = org.owasp.esapi.interfaces.IAccessController;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
namespace org.owasp.esapi
{
	
	/// <summary> The Class AccessControllerTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class AccessControllerTest:TestCase
	{
		
		/// <summary> Instantiates a new access controller test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public AccessControllerTest(System.String testName):base(testName)
		{
			IAuthenticator authenticator = ESAPI.authenticator();
			System.String password = authenticator.generateStrongPassword();
			
			// create a user with the "user" role for this test
			User alice = authenticator.getUser("testuser1");
			if (alice == null)
			{
				alice = authenticator.createUser("testuser1", password, password);
			}
			alice.addRole("user");
			
			// create a user with the "admin" role for this test
			User bob = authenticator.getUser("testuser2");
			if (bob == null)
			{
				bob = authenticator.createUser("testuser2", password, password);
			}
			bob.addRole("admin");
			
			// create a user with the "user" and "admin" roles for this test
			User mitch = authenticator.getUser("testuser3");
			if (mitch == null)
			{
				mitch = authenticator.createUser("testuser3", password, password);
			}
			mitch.addRole("admin");
			mitch.addRole("user");
		}
		
		/* (non-Javadoc)
		* @see junit.framework.TestCase#setUp()
		*/
		protected internal virtual void  setUp()
		{
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
			TestSuite suite = new TestSuite(typeof(AccessControllerTest));
			return suite;
		}
		
		/// <summary> Test of isAuthorizedForURL method, of class
		/// org.owasp.esapi.AccessController.
		/// </summary>
		public virtual void  testIsAuthorizedForURL()
		{
			System.Console.Out.WriteLine("isAuthorizedForURL");
			IAccessController instance = ESAPI.accessController();
			IAuthenticator auth = ESAPI.authenticator();
			
			auth.setCurrentUser(auth.getUser("testuser1"));
			assertFalse(instance.isAuthorizedForURL("/nobody"));
			assertFalse(instance.isAuthorizedForURL("/test/admin"));
			assertTrue(instance.isAuthorizedForURL("/test/user"));
			assertTrue(instance.isAuthorizedForURL("/test/all"));
			assertFalse(instance.isAuthorizedForURL("/test/none"));
			assertTrue(instance.isAuthorizedForURL("/test/none/test.gif"));
			assertFalse(instance.isAuthorizedForURL("/test/none/test.exe"));
			
			auth.setCurrentUser(auth.getUser("testuser2"));
			assertFalse(instance.isAuthorizedForURL("/nobody"));
			assertTrue(instance.isAuthorizedForURL("/test/admin"));
			assertFalse(instance.isAuthorizedForURL("/test/user"));
			assertTrue(instance.isAuthorizedForURL("/test/all"));
			assertFalse(instance.isAuthorizedForURL("/test/none"));
			
			auth.setCurrentUser(auth.getUser("testuser3"));
			assertFalse(instance.isAuthorizedForURL("/nobody"));
			assertTrue(instance.isAuthorizedForURL("/test/admin"));
			assertTrue(instance.isAuthorizedForURL("/test/user"));
			assertTrue(instance.isAuthorizedForURL("/test/all"));
			assertFalse(instance.isAuthorizedForURL("/test/none"));
		}
		
		/// <summary> Test of isAuthorizedForFunction method, of class
		/// org.owasp.esapi.AccessController.
		/// </summary>
		public virtual void  testIsAuthorizedForFunction()
		{
			System.Console.Out.WriteLine("isAuthorizedForFunction");
			IAccessController instance = ESAPI.accessController();
			IAuthenticator auth = ESAPI.authenticator();
			
			auth.setCurrentUser(auth.getUser("testuser1"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
			
			auth.setCurrentUser(auth.getUser("testuser2"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
			
			auth.setCurrentUser(auth.getUser("testuser3"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
		}
		
		/// <summary> Test of isAuthorizedForData method, of class
		/// org.owasp.esapi.AccessController.
		/// </summary>
		public virtual void  testIsAuthorizedForData()
		{
			System.Console.Out.WriteLine("isAuthorizedForData");
			IAccessController instance = ESAPI.accessController();
			IAuthenticator auth = ESAPI.authenticator();
			
			auth.setCurrentUser(auth.getUser("testuser1"));
			assertTrue(instance.isAuthorizedForData("/Data1"));
			assertFalse(instance.isAuthorizedForData("/Data2"));
			assertFalse(instance.isAuthorizedForData("/not_listed"));
			
			auth.setCurrentUser(auth.getUser("testuser2"));
			assertFalse(instance.isAuthorizedForData("/Data1"));
			assertTrue(instance.isAuthorizedForData("/Data2"));
			assertFalse(instance.isAuthorizedForData("/not_listed"));
			
			auth.setCurrentUser(auth.getUser("testuser3"));
			assertTrue(instance.isAuthorizedForData("/Data1"));
			assertTrue(instance.isAuthorizedForData("/Data2"));
			assertFalse(instance.isAuthorizedForData("/not_listed"));
		}
		
		/// <summary> Test of isAuthorizedForFile method, of class
		/// org.owasp.esapi.AccessController.
		/// </summary>
		public virtual void  testIsAuthorizedForFile()
		{
			System.Console.Out.WriteLine("isAuthorizedForFile");
			IAccessController instance = ESAPI.accessController();
			IAuthenticator auth = ESAPI.authenticator();
			
			auth.setCurrentUser(auth.getUser("testuser1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
			assertFalse(instance.isAuthorizedForFile("/Dir/File2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));
			
			auth.setCurrentUser(auth.getUser("testuser2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));
			
			auth.setCurrentUser(auth.getUser("testuser3"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));
		}
		
		/// <summary> Test of isAuthorizedForBackendService method, of class
		/// org.owasp.esapi.AccessController.
		/// </summary>
		public virtual void  testIsAuthorizedForBackendService()
		{
			System.Console.Out.WriteLine("isAuthorizedForBackendService");
			IAccessController instance = ESAPI.accessController();
			IAuthenticator auth = ESAPI.authenticator();
			
			auth.setCurrentUser(auth.getUser("testuser1"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));
			
			auth.setCurrentUser(auth.getUser("testuser2"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));
			
			auth.setCurrentUser(auth.getUser("testuser3"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));
		}
	}
}