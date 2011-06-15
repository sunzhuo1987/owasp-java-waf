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
using TestHttpSession = org.owasp.esapi.http.TestHttpSession;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
namespace org.owasp.esapi
{
	
	/// <summary> The Class UserTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class UserTest:TestCase
	{
		
		/// <summary> Suite.
		/// 
		/// </summary>
		/// <returns> the test
		/// </returns>
		public static Test suite()
		{
			TestSuite suite = new TestSuite(typeof(UserTest));
			return suite;
		}
		
		/// <summary> Instantiates a new user test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public UserTest(System.String testName):base(testName)
		{
		}
		
		/// <summary> Creates the test user.
		/// 
		/// </summary>
		/// <param name="password">the password
		/// 
		/// </param>
		/// <returns> the user
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		private User createTestUser(System.String password)
		{
			System.String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			User user = ESAPI.authenticator().createUser(username, password, password);
			return user;
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
		
		/// <summary> Test of testAddRole method, of class org.owasp.esapi.User.</summary>
		public virtual void  testAddRole()
		{
			System.Console.Out.WriteLine("addRole");
			IAuthenticator instance = ESAPI.authenticator();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String password = ESAPI.authenticator().generateStrongPassword();
			System.String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
			User user = instance.createUser(accountName, password, password);
			user.addRole(role);
			assertTrue(user.isInRole(role));
			assertFalse(user.isInRole("ridiculous"));
		}
		
		/// <summary> Test of addRoles method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testAddRoles()
		{
			System.Console.Out.WriteLine("addRoles");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport set_Renamed = new SupportClass.HashSetSupport();
			set_Renamed.Add("rolea");
			set_Renamed.Add("roleb");
			user.addRoles(set_Renamed);
			assertTrue(user.isInRole("rolea"));
			assertTrue(user.isInRole("roleb"));
			assertFalse(user.isInRole("ridiculous"));
		}
		
		/// <summary> Test of changePassword method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testChangePassword()
		{
			System.Console.Out.WriteLine("changePassword");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			System.String password1 = instance.generateStrongPassword();
			user.changePassword(oldPassword, password1, password1);
			assertTrue(user.verifyPassword(password1));
			System.String password2 = instance.generateStrongPassword();
			user.changePassword(password1, password2, password2);
			try
			{
				user.changePassword(password2, password1, password1);
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertTrue(user.verifyPassword(password2));
			assertFalse(user.verifyPassword("badpass"));
		}
		
		/// <summary> Test of disable method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testDisable()
		{
			System.Console.Out.WriteLine("disable");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.enable();
			assertTrue(user.Enabled);
			user.disable();
			assertFalse(user.Enabled);
		}
		
		/// <summary> Test of enable method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testEnable()
		{
			System.Console.Out.WriteLine("enable");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.enable();
			assertTrue(user.Enabled);
			user.disable();
			assertFalse(user.Enabled);
		}
		
		/// <summary> Test equals.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testEquals()
		{
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			User a = new User("userA", password, password);
			User b = new User("userA", "differentPass", "differentPass");
			a.enable();
			assertTrue(a.Equals(b));
		}
		
		/// <summary> Test of failedLoginCount lockout, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testFailedLoginLockout()
		{
			System.Console.Out.WriteLine("failedLoginLockout");
			IAuthenticator instance = ESAPI.authenticator();
			User user = createTestUser("failedLoginLockout");
			System.String password = instance.generateStrongPassword();
			user.unlock();
			user.changePassword("failedLoginLockout", password, password);
			user.verifyPassword(password);
			user.verifyPassword("ridiculous");
			System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
			assertFalse(user.Locked);
			user.verifyPassword("ridiculous");
			System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
			assertFalse(user.Locked);
			user.verifyPassword("ridiculous");
			System.Console.Out.WriteLine("FAILED: " + user.FailedLoginCount);
			assertTrue(user.Locked);
		}
		
		/// <summary> Test of getAccountName method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetAccountName()
		{
			System.Console.Out.WriteLine("getAccountName");
			User user = createTestUser("getAccountName");
			System.String accountName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
			user.AccountName = accountName;
			assertEquals(accountName.ToLower(), user.AccountName);
			assertFalse("ridiculous".Equals(user.AccountName));
		}
		
		/// <summary> Test get last failed login time.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testGetLastFailedLoginTime()
		{
			System.Console.Out.WriteLine("getLastLoginTime");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.verifyPassword("ridiculous");
			System.DateTime llt1 = user.getLastFailedLoginTime();
			//UPGRADE_TODO: Method 'java.lang.Thread.sleep' was converted to 'System.Threading.Thread.Sleep' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangThreadsleep_long'"
			System.Threading.Thread.Sleep(new System.TimeSpan((System.Int64) 10000 * 10)); // need a short delay to separate attempts
			user.verifyPassword("ridiculous");
			System.DateTime llt2 = user.getLastFailedLoginTime();
			assertTrue((llt1 < llt2));
		}
		
		/// <summary> Test get last login time.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testGetLastLoginTime()
		{
			System.Console.Out.WriteLine("getLastLoginTime");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.verifyPassword(oldPassword);
			System.DateTime llt1 = user.getLastLoginTime();
			//UPGRADE_TODO: Method 'java.lang.Thread.sleep' was converted to 'System.Threading.Thread.Sleep' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangThreadsleep_long'"
			System.Threading.Thread.Sleep(new System.TimeSpan((System.Int64) 10000 * 10)); // need a short delay to separate attempts
			user.verifyPassword(oldPassword);
			System.DateTime llt2 = user.getLastLoginTime();
			assertTrue((llt1 < llt2));
		}
		
		/// <summary> Test of getLastPasswordChangeTime method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testGetLastPasswordChangeTime()
		{
			System.Console.Out.WriteLine("getLastPasswordChangeTime");
			User user = createTestUser("getLastPasswordChangeTime");
			System.DateTime t1 = user.getLastPasswordChangeTime();
			//UPGRADE_TODO: Method 'java.lang.Thread.sleep' was converted to 'System.Threading.Thread.Sleep' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangThreadsleep_long'"
			System.Threading.Thread.Sleep(new System.TimeSpan((System.Int64) 10000 * 10)); // need a short delay to separate attempts
			System.String newPassword = ESAPI.authenticator().generateStrongPassword("getLastPasswordChangeTime", user);
			user.changePassword("getLastPasswordChangeTime", newPassword, newPassword);
			System.DateTime t2 = user.getLastPasswordChangeTime();
			assertTrue((t2 > t1));
		}
		
		/// <summary> Test of getRoles method, of class org.owasp.esapi.User.</summary>
		public virtual void  testGetRoles()
		{
			System.Console.Out.WriteLine("getRoles");
			IAuthenticator instance = ESAPI.authenticator();
			System.String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			System.String password = ESAPI.authenticator().generateStrongPassword();
			System.String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
			User user = instance.createUser(accountName, password, password);
			user.addRole(role);
			SupportClass.SetSupport roles = user.Roles;
			assertTrue(roles.Count > 0);
		}
		
		/// <summary> Test of xxx method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testGetScreenName()
		{
			System.Console.Out.WriteLine("getScreenName");
			User user = createTestUser("getScreenName");
			System.String screenName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
			user.ScreenName = screenName;
			assertEquals(screenName, user.ScreenName);
			assertFalse("ridiculous".Equals(user.ScreenName));
		}
		
		/// <summary> Test of incrementFailedLoginCount method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIncrementFailedLoginCount()
		{
			System.Console.Out.WriteLine("incrementFailedLoginCount");
			User user = createTestUser("incrementFailedLoginCount");
			user.enable();
			assertEquals(0, user.FailedLoginCount);
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			((Authenticator) ESAPI.authenticator()).setCurrentHTTP(request, response);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertEquals(1, user.FailedLoginCount);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertEquals(2, user.FailedLoginCount);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertEquals(3, user.FailedLoginCount);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertTrue(user.Locked);
		}
		
		/// <summary> Test of isEnabled method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIsEnabled()
		{
			System.Console.Out.WriteLine("isEnabled");
			User user = createTestUser("isEnabled");
			user.disable();
			assertFalse(user.Enabled);
			user.enable();
			assertTrue(user.Enabled);
		}
		
		
		/// <summary> Test of isFirstRequest method, of class org.owasp.esapi.User.</summary>
		public virtual void  testIsFirstRequest()
		{
			System.Console.Out.WriteLine("isFirstRequest");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			IAuthenticator instance = ESAPI.authenticator();
			System.String password = instance.generateStrongPassword();
			User user = instance.createUser("isFirstRequest", password, password);
			user.enable();
			request.addParameter(ESAPI.securityConfiguration().PasswordParameterName, password);
			request.addParameter(ESAPI.securityConfiguration().UsernameParameterName, "isFirstRequest");
			instance.login(request, response);
			assertTrue(user.isFirstRequest());
			instance.login(request, response);
			assertFalse(user.isFirstRequest());
			instance.login(request, response);
			assertFalse(user.isFirstRequest());
		}
		
		
		/// <summary> Test of isInRole method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIsInRole()
		{
			System.Console.Out.WriteLine("isInRole");
			User user = createTestUser("isInRole");
			System.String role = "TestRole";
			assertFalse(user.isInRole(role));
			user.addRole(role);
			assertTrue(user.isInRole(role));
			assertFalse(user.isInRole("Ridiculous"));
		}
		
		/// <summary> Test of xxx method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIsLocked()
		{
			System.Console.Out.WriteLine("isLocked");
			User user = createTestUser("isLocked");
			user.lock_Renamed();
			assertTrue(user.Locked);
			user.unlock();
			assertFalse(user.Locked);
		}
		
		/// <summary> Test of isSessionAbsoluteTimeout method, of class
		/// org.owasp.esapi.IntrusionDetector.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIsSessionAbsoluteTimeout()
		{
			// FIXME: ENHANCE shouldn't this just be one timeout method that does both checks???
			System.Console.Out.WriteLine("isSessionAbsoluteTimeout");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			long now = (System.DateTime.Now.Ticks - 621355968000000000) / 10000;
			TestHttpSession s1 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now);
			assertTrue(user.isSessionAbsoluteTimeout(s1));
			TestHttpSession s2 = new TestHttpSession(now - 1000 * 60 * 60 * 1, now);
			assertFalse(user.isSessionAbsoluteTimeout(s2));
		}
		
		/// <summary> Test of isSessionTimeout method, of class
		/// org.owasp.esapi.IntrusionDetector.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testIsSessionTimeout()
		{
			System.Console.Out.WriteLine("isSessionTimeout");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			long now = (System.DateTime.Now.Ticks - 621355968000000000) / 10000;
			TestHttpSession s1 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now - 1000 * 60 * 30);
			assertTrue(user.isSessionAbsoluteTimeout(s1));
			TestHttpSession s2 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now - 1000 * 60 * 10);
			assertFalse(user.isSessionTimeout(s2));
		}
		
		/// <summary> Test of lockAccount method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testLock()
		{
			System.Console.Out.WriteLine("lock");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.lock_Renamed();
			assertTrue(user.Locked);
			user.unlock();
			assertFalse(user.Locked);
		}
		
		/// <summary> Test of loginWithPassword method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testLoginWithPassword()
		{
			System.Console.Out.WriteLine("loginWithPassword");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpSession session = (TestHttpSession) request.getSession();
			assertFalse(session.Invalidated);
			User user = createTestUser("loginWithPassword");
			user.enable();
			user.loginWithPassword("loginWithPassword");
			assertTrue(user.LoggedIn);
			user.logout();
			assertFalse(user.LoggedIn);
			assertFalse(user.Locked);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertFalse(user.LoggedIn);
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			try
			{
				user.loginWithPassword("ridiculous");
			}
			catch (AuthenticationException e)
			{
				// expected
			}
			assertTrue(user.Locked);
		}
		
		
		/// <summary> Test of logout method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testLogout()
		{
			System.Console.Out.WriteLine("logout");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			TestHttpSession session = (TestHttpSession) request.getSession();
			assertFalse(session.Invalidated);
			IAuthenticator instance = ESAPI.authenticator();
			((Authenticator) instance).setCurrentHTTP(request, response);
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.enable();
			//UPGRADE_TODO: Method 'java.io.PrintStream.println' was converted to 'System.Console.Out.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintStreamprintln_javalangObject'"
			//UPGRADE_TODO: Method 'java.util.Date.toString' was converted to 'System.DateTime.ToString' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDatetoString'"
			System.Console.Out.WriteLine(user.getLastLoginTime().ToString("r"));
			user.loginWithPassword(oldPassword);
			assertTrue(user.LoggedIn);
			// get new session after user logs in
			session = (TestHttpSession) request.getSession();
			assertFalse(session.Invalidated);
			user.logout();
			assertFalse(user.LoggedIn);
			assertTrue(session.Invalidated);
		}
		
		/// <summary> Test of testRemoveRole method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testRemoveRole()
		{
			System.Console.Out.WriteLine("removeRole");
			System.String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
			User user = createTestUser("removeRole");
			user.addRole(role);
			assertTrue(user.isInRole(role));
			user.removeRole(role);
			assertFalse(user.isInRole(role));
		}
		
		/// <summary> Test of testResetCSRFToken method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testResetCSRFToken()
		{
			System.Console.Out.WriteLine("resetCSRFToken");
			User user = createTestUser("resetCSRFToken");
			System.String token1 = user.resetCSRFToken();
			System.String token2 = user.resetCSRFToken();
			assertFalse(token1.Equals(token2));
		}
		
		/// <summary> Test reset password.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testResetPassword()
		{
			System.Console.Out.WriteLine("resetPassword");
			User user = createTestUser("resetPassword");
			for (int i = 0; i < 20; i++)
			{
				assertTrue(user.verifyPassword(user.resetPassword()));
			}
		}
		
		/// <summary> Test of generateRememberMeToken method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testResetRememberToken()
		{
			System.Console.Out.WriteLine("resetRememberToken");
			User user = createTestUser("resetRememberToken");
			System.String token = user.resetRememberToken();
			assertEquals(token, user.RememberToken);
		}
		
		/// <summary> Test of setAccountName method, of class org.owasp.esapi.User.</summary>
		public virtual void  testSetAccountName()
		{
			System.Console.Out.WriteLine("setAccountName");
			User user = createTestUser("setAccountName");
			System.String accountName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
			user.AccountName = accountName;
			assertEquals(accountName.ToLower(), user.AccountName);
			assertFalse("ridiculous".Equals(user.AccountName));
		}
		
		/// <summary> Test of setExpirationTime method, of class org.owasp.esapi.User.</summary>
		public virtual void  testSetExpirationTime()
		{
			System.Console.Out.WriteLine("setAccountName");
			System.String password = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			User user = createTestUser(password);
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			user.ExpirationTime = new System.DateTime(0);
			assertTrue(user.Expired);
		}
		
		
		/// <summary> Test of setRoles method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testSetRoles()
		{
			System.Console.Out.WriteLine("setRoles");
			User user = createTestUser("setRoles");
			user.addRole("user");
			assertTrue(user.isInRole("user"));
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport set_Renamed = new SupportClass.HashSetSupport();
			set_Renamed.Add("rolea");
			set_Renamed.Add("roleb");
			user.Roles = set_Renamed;
			assertFalse(user.isInRole("user"));
			assertTrue(user.isInRole("rolea"));
			assertTrue(user.isInRole("roleb"));
			assertFalse(user.isInRole("ridiculous"));
		}
		
		/// <summary> Test of setScreenName method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testSetScreenName()
		{
			System.Console.Out.WriteLine("setScreenName");
			User user = createTestUser("setScreenName");
			System.String screenName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
			user.ScreenName = screenName;
			assertEquals(screenName, user.ScreenName);
			assertFalse("ridiculous".Equals(user.ScreenName));
		}
		
		/// <summary> Test of unlockAccount method, of class org.owasp.esapi.User.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testUnlock()
		{
			System.Console.Out.WriteLine("unlockAccount");
			IAuthenticator instance = ESAPI.authenticator();
			System.String oldPassword = instance.generateStrongPassword();
			User user = createTestUser(oldPassword);
			user.lock_Renamed();
			assertTrue(user.Locked);
			user.unlock();
			assertFalse(user.Locked);
		}
	}
}