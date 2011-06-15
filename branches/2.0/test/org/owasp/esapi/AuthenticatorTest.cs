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
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using TestHttpServletRequest = org.owasp.esapi.http.TestHttpServletRequest;
using TestHttpServletResponse = org.owasp.esapi.http.TestHttpServletResponse;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
namespace org.owasp.esapi
{
	
	/// <summary> The Class AuthenticatorTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class AuthenticatorTest:TestCase
	{
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'AnonymousClassRunnable' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		private class AnonymousClassRunnable : IThreadRunnable
		{
			public AnonymousClassRunnable(AuthenticatorTest enclosingInstance)
			{
				InitBlock(enclosingInstance);
			}
			private void  InitBlock(AuthenticatorTest enclosingInstance)
			{
				this.enclosingInstance = enclosingInstance;
			}
			private AuthenticatorTest enclosingInstance;
			public AuthenticatorTest Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			private int count = 1;
			private bool result = false;
			public virtual void  Run()
			{
				Authenticator instance = (Authenticator) ESAPI.authenticator();
				User a = null;
				try
				{
					System.String password = instance.generateStrongPassword();
					System.String accountName = "TestAccount" + count++;
					a = instance.getUser(accountName);
					if (a != null)
					{
						instance.removeUser(accountName);
					}
					a = instance.createUser(accountName, password, password);
					instance.setCurrentUser(a);
				}
				catch (AuthenticationException e)
				{
					SupportClass.WriteStackTrace(e, Console.Error);
				}
				User b = instance.getCurrentUser();
				result &= a.Equals(b);
			}
		}
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'AnonymousClassRunnable1' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		private class AnonymousClassRunnable1 : IThreadRunnable
		{
			public AnonymousClassRunnable1(org.owasp.esapi.Authenticator instance, AuthenticatorTest enclosingInstance)
			{
				InitBlock(instance, enclosingInstance);
			}
			private void  InitBlock(org.owasp.esapi.Authenticator instance, AuthenticatorTest enclosingInstance)
			{
				this.instance = instance;
				this.enclosingInstance = enclosingInstance;
			}
			//UPGRADE_NOTE: Final variable instance was copied into class AnonymousClassRunnable1. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1023'"
			private org.owasp.esapi.Authenticator instance;
			private AuthenticatorTest enclosingInstance;
			public AuthenticatorTest Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			private int count = 1;
			public virtual void  Run()
			{
				User u = null;
				try
				{
					System.String password = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
					u = instance.createUser("test" + count++, password, password);
					instance.setCurrentUser(u);
					Logger.getLogger("test", "test").logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Got current user");
					// ESAPI.authenticator().removeUser( u.getAccountName() );
				}
				catch (AuthenticationException e)
				{
					SupportClass.WriteStackTrace(e, Console.Error);
				}
			}
		}
		
		
		/// <summary> Suite.
		/// 
		/// </summary>
		/// <returns> the test
		/// </returns>
		public static Test suite()
		{
			TestSuite suite = new TestSuite(typeof(AuthenticatorTest));
			
			return suite;
		}
		
		/// <summary> Instantiates a new authenticator test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public AuthenticatorTest(System.String testName):base(testName)
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
		
		
		/// <summary> Test of createAccount method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testCreateUser()
		{
			System.Console.Out.WriteLine("createUser");
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			User user = instance.createUser(accountName, password, password);
			assertTrue(user.verifyPassword(password));
			try
			{
				instance.createUser(accountName, password, password); // duplicate user
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), "weak1", "weak1"); // weak password
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.createUser(null, "weak1", "weak1"); // null username
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), null, null); // null password
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
		}
		
		/// <summary> Test of generateStrongPassword method, of class
		/// org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGenerateStrongPassword()
		{
			System.Console.Out.WriteLine("generateStrongPassword");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			System.String newPassword = null;
			for (int i = 0; i < 100; i++)
			{
				try
				{
					newPassword = instance.generateStrongPassword();
					instance.verifyPasswordStrength(newPassword, oldPassword);
				}
				catch (AuthenticationException e)
				{
					System.Console.Out.WriteLine("  FAILED >> " + newPassword);
					fail();
				}
			}
		}
		
		
		/// <summary> Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  InterruptedException * </throws>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetCurrentUser()
		{
			System.Console.Out.WriteLine("getCurrentUser");
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			System.String username1 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String username2 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			User user1 = instance.createUser(username1, "getCurrentUser", "getCurrentUser");
			User user2 = instance.createUser(username2, "getCurrentUser", "getCurrentUser");
			user1.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			instance.setCurrentHTTP(request, response);
			user1.loginWithPassword("getCurrentUser");
			User currentUser = instance.getCurrentUser();
			assertEquals(currentUser, user1);
			instance.setCurrentUser(user2);
			assertFalse(currentUser.AccountName.Equals(user2.AccountName));
			
			IThreadRunnable echo = new AnonymousClassRunnable(this);
			//UPGRADE_ISSUE: Class 'java.lang.ThreadGroup' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangThreadGroup'"
			//UPGRADE_ISSUE: Constructor 'java.lang.ThreadGroup.ThreadGroup' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangThreadGroup'"
			ThreadGroup tg = new ThreadGroup("test");
			for (int i = 0; i < 10; i++)
			{
				new SupportClass.ThreadClass(new System.Threading.ThreadStart(echo.Run)).Start();
			}
			//UPGRADE_ISSUE: Method 'java.lang.ThreadGroup.activeCount' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangThreadGroup'"
			while (tg.activeCount() > 0)
			{
				//UPGRADE_TODO: Method 'java.lang.Thread.sleep' was converted to 'System.Threading.Thread.Sleep' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangThreadsleep_long'"
				System.Threading.Thread.Sleep(new System.TimeSpan((System.Int64) 10000 * 100));
			}
			// FIXME: AAA need a way to get results here from runnables
		}
		
		/// <summary> Test of getUser method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetUser()
		{
			System.Console.Out.WriteLine("getUser");
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			instance.createUser(accountName, password, password);
			assertNotNull(instance.getUser(accountName));
			assertNull(instance.getUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS)));
		}
		
		/// <summary> Test get user from session.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetUserFromSession()
		{
			System.Console.Out.WriteLine("getUserFromSession");
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String password = instance.generateStrongPassword();
			User user = instance.createUser(accountName, password, password);
			user.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			request.addParameter("username", accountName);
			request.addParameter("password", password);
			TestHttpServletResponse response = new TestHttpServletResponse();
			instance.login(request, response);
			User test = instance.UserFromSession;
			assertEquals(user, test);
		}
		
		/// <summary> Test get user names.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetUserNames()
		{
			System.Console.Out.WriteLine("getUserNames");
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			System.String[] testnames = new System.String[10];
			for (int i = 0; i < testnames.Length; i++)
			{
				testnames[i] = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			}
			for (int i = 0; i < testnames.Length; i++)
			{
				instance.createUser(testnames[i], password, password);
			}
			SupportClass.SetSupport names = instance.getUserNames();
			for (int i = 0; i < testnames.Length; i++)
			{
				assertTrue(names.Contains(testnames[i].ToLower()));
			}
		}
		
		/// <summary> Test of hashPassword method, of class org.owasp.esapi.Authenticator.</summary>
		public virtual void  testHashPassword()
		{
			System.Console.Out.WriteLine("hashPassword");
			System.String username = "Jeff";
			System.String password = "test";
			IAuthenticator instance = ESAPI.authenticator();
			System.String result1 = instance.hashPassword(password, username);
			System.String result2 = instance.hashPassword(password, username);
			assertTrue(result1.Equals(result2));
		}
		
		/// <summary> Test of login method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testLogin()
		{
			System.Console.Out.WriteLine("login");
			IAuthenticator instance = ESAPI.authenticator();
			System.String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String password = instance.generateStrongPassword();
			User user = instance.createUser(username, password, password);
			user.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			request.addParameter("username", username);
			request.addParameter("password", password);
			TestHttpServletResponse response = new TestHttpServletResponse();
			User test = instance.login(request, response);
			assertTrue(test.LoggedIn);
		}
		
		/// <summary> Test of removeAccount method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testRemoveUser()
		{
			System.Console.Out.WriteLine("removeUser");
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			instance.createUser(accountName, password, password);
			assertTrue(instance.exists(accountName));
			instance.removeUser(accountName);
			assertFalse(instance.exists(accountName));
		}
		
		/// <summary> Test of saveUsers method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testSaveUsers()
		{
			System.Console.Out.WriteLine("saveUsers");
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			instance.createUser(accountName, password, password);
			instance.saveUsers();
			assertNotNull(instance.getUser(accountName));
			instance.removeUser(accountName);
			assertNull(instance.getUser(accountName));
		}
		
		
		/// <summary> Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testSetCurrentUser()
		{
			System.Console.Out.WriteLine("setCurrentUser");
			//UPGRADE_NOTE: Final was removed from the declaration of 'instance '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			System.String user1 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_UPPERS);
			System.String user2 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_UPPERS);
			User userOne = instance.createUser(user1, "getCurrentUser", "getCurrentUser");
			userOne.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			instance.setCurrentHTTP(request, response);
			userOne.loginWithPassword("getCurrentUser");
			User currentUser = instance.getCurrentUser();
			assertEquals(currentUser, userOne);
			User userTwo = instance.createUser(user2, "getCurrentUser", "getCurrentUser");
			instance.setCurrentUser(userTwo);
			assertFalse(currentUser.AccountName.Equals(userTwo.AccountName));
			
			IThreadRunnable echo = new AnonymousClassRunnable1(instance, this);
			for (int i = 0; i < 10; i++)
			{
				new SupportClass.ThreadClass(new System.Threading.ThreadStart(echo.Run)).Start();
			}
		}
		
		
		/// <summary> Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testSetCurrentUserWithRequest()
		{
			System.Console.Out.WriteLine("setCurrentUser(req,resp)");
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			User user = instance.createUser(accountName, password, password);
			user.enable();
			TestHttpServletRequest request = new TestHttpServletRequest();
			request.addParameter("username", accountName);
			request.addParameter("password", password);
			TestHttpServletResponse response = new TestHttpServletResponse();
			instance.login(request, response);
			assertEquals(user, instance.getCurrentUser());
			try
			{
				user.disable();
				instance.login(request, response);
			}
			catch (System.Exception e)
			{
				// expected
			}
			try
			{
				user.enable();
				user.lock_Renamed();
				instance.login(request, response);
			}
			catch (System.Exception e)
			{
				// expected
			}
			try
			{
				user.unlock();
				user.ExpirationTime = System.DateTime.Now;
				instance.login(request, response);
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
		
		
		
		/// <summary> Test of validatePasswordStrength method, of class
		/// org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testValidatePasswordStrength()
		{
			System.Console.Out.WriteLine("validatePasswordStrength");
			IAuthenticator instance = ESAPI.authenticator();
			
			// should fail
			try
			{
				instance.verifyPasswordStrength("jeff", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("same123string", "diff123bang");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("JEFF", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("1234", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("password", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("-1", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("password123", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			try
			{
				instance.verifyPasswordStrength("test123", "password");
				fail();
			}
			catch (AuthenticationException e)
			{
				// success
			}
			
			// should pass
			instance.verifyPasswordStrength("jeffJEFF12!", "password");
			instance.verifyPasswordStrength("super calif ragil istic", "password");
			instance.verifyPasswordStrength("TONYTONYTONYTONY", "password");
			instance.verifyPasswordStrength(instance.generateStrongPassword(), "password");
		}
		
		/// <summary> Test of exists method, of class org.owasp.esapi.Authenticator.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testExists()
		{
			System.Console.Out.WriteLine("exists");
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			instance.createUser(accountName, password, password);
			assertTrue(instance.exists(accountName));
			instance.removeUser(accountName);
			assertFalse(instance.exists(accountName));
		}
		
		/// <summary> Test of main method, of class org.owasp.esapi.Authenticator.</summary>
		public virtual void  testMain()
		{
			System.Console.Out.WriteLine("Authenticator Main");
			IAuthenticator instance = ESAPI.authenticator();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String password = instance.generateStrongPassword();
			System.String role = "test";
			
			// test wrong parameters - missing role parameter
			System.String[] badargs = new System.String[]{accountName, password};
			Authenticator.main(badargs);
			// load users since the new user was added in another instance
			((Authenticator) instance).loadUsersImmediately();
			User u1 = instance.getUser(accountName);
			assertNull(u1);
			
			// test good parameters
			System.String[] args = new System.String[]{accountName, password, role};
			Authenticator.main(args);
			// load users since the new user was added in another instance
			((Authenticator) instance).loadUsersImmediately();
			User u2 = instance.getUser(accountName);
			assertNotNull(u2);
			assertTrue(u2.isInRole(role));
			assertEquals(instance.hashPassword(password, accountName), u2.getHashedPassword());
		}
	}
}