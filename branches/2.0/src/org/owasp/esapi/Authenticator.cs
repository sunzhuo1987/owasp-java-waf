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
using AuthenticationAccountsException = org.owasp.esapi.errors.AuthenticationAccountsException;
using AuthenticationCredentialsException = org.owasp.esapi.errors.AuthenticationCredentialsException;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using AuthenticationLoginException = org.owasp.esapi.errors.AuthenticationLoginException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using IRandomizer = org.owasp.esapi.interfaces.IRandomizer;
using IUser = org.owasp.esapi.interfaces.IUser;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IAuthenticator interface. This reference implementation is backed by a simple text
	/// file that contains serialized information about users. Many organizations will want to create their own
	/// implementation of the methods provided in the IAuthenticator interface backed by their own user repository. This
	/// reference implementation captures information about users in a simple text file format that contains user information
	/// separated by the pipe "|" character. Here's an example of a single line from the users.txt file:
	/// 
	/// <PRE>
	/// 
	/// account name | hashed password | roles | lockout | status | remember token | old password hashes | last
	/// hostname | last change | last login | last failed | expiration | failed
	/// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	/// mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled | token |
	/// u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
	/// 2187200605330 | 1
	/// 
	/// </PRE>
	/// 
	/// </summary>
	/// <author>  <a href="mailto:jeff.williams@aspectsecurity.com?subject=ESAPI question">Jeff Williams</a> at <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IAuthenticator">
	/// </seealso>
	public class Authenticator : org.owasp.esapi.interfaces.IAuthenticator
	{
		virtual public System.Web.HttpRequest CurrentRequest
		{
			/*
			* Returns the current HttpServletRequest.
			* 
			* @see org.owasp.esapi.interfaces.IAuthenticator#getCurrentRequest()
			*/
			
			get
			{
				//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
				return (System.Web.HttpRequest) currentRequest.get_Renamed();
			}
			
		}
		virtual public System.Web.HttpResponse CurrentResponse
		{
			get
			{
				//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
				return (System.Web.HttpResponse) currentResponse.get_Renamed();
			}
			
		}
		/// <summary> Gets the user from session.
		/// 
		/// </summary>
		/// <param name="request">the request
		/// </param>
		/// <returns> the user from session
		/// </returns>
		virtual public User UserFromSession
		{
			/*
			* Get the current user from the session and set it as the current user. (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentUser(javax.servlet.http.HttpServletRequest)
			*/
			
			get
			{
				System.Web.SessionState.HttpSessionState session = System.Web.HttpContext.Current.Session;
				System.String userName = (System.String) session[USER];
				if (userName != null)
				{
					User sessionUser = this.getUser(userName);
					if (sessionUser != null)
					{
						return sessionUser;
					}
				}
				return null;
			}
			
		}
		
		/// <summary>The Constant USER. </summary>
		protected internal const System.String USER = "ESAPIUserSessionKey";
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Authenticator'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary>The file that contains the user db </summary>
		private System.IO.FileInfo userDB = null;
		
		/// <summary>How frequently to check the user db for external modifications </summary>
		private long checkInterval = 60 * 1000;
		
		/// <summary>The last modified time we saw on the user db. </summary>
		private long lastModified = 0;
		
		/// <summary>The last time we checked if the user db had been modified externally </summary>
		private long lastChecked = 0;
		
		/// <summary> Fail safe main program to add or update an account in an emergency.
		/// <P>
		/// Warning: this method does not perform the level of validation and checks
		/// generally required in ESAPI, and can therefore be used to create a username and password that do not comply
		/// with the username and password strength requirements.
		/// <P>
		/// Example: Use this to add the alice account with the admin role to the users file: 
		/// <PRE>
		/// 
		/// java -Dorg.owasp.esapi.resources="/path/resources" -classpath esapi.jar org.owasp.esapi.Authenticator alice password admin
		/// 
		/// </PRE>
		/// 
		/// </summary>
		/// <param name="args">the args
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		[STAThread]
		public static void  Main(System.String[] args)
		{
			if (args.Length != 3)
			{
				System.Console.Out.WriteLine("Usage: Authenticator accountname password role");
				return ;
			}
			Authenticator auth = new Authenticator();
			System.String accountName = args[0].ToLower();
			System.String password = args[1];
			System.String role = args[2];
			User user = auth.getUser(args[0]);
			if (user == null)
			{
				user = new User();
				user.AccountName = accountName;
				auth.userMap[accountName] = user;
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "New user created: " + accountName);
			}
			System.String newHash = auth.hashPassword(password, accountName);
			user.setHashedPassword(newHash);
			user.addRole(role);
			user.enable();
			user.unlock();
			auth.saveUsers();
			System.Console.Out.WriteLine("User account " + user.AccountName + " updated");
		}
		
		// FIXME: ENHANCE consider an impersonation feature
		
		/// <summary>The anonymous user </summary>
		// FIXME: AAA is this whole anonymous user concept right?
		internal static User anonymous = new User("anonymous", "anonymous");
		
		/// <summary>The user map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary userMap = new System.Collections.Hashtable();
		
		
		/*
		* The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
		* application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
		* need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
		* the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
		* framework by adding another ThreadLocal to hold the delegating user identity.
		*/
		private static ThreadLocalUser currentUser = new ThreadLocalUser();
		
		//UPGRADE_ISSUE: Class 'java.lang.InheritableThreadLocal' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
		private class ThreadLocalUser:InheritableThreadLocal
		{
			virtual public IUser User
			{
				get
				{
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					return (IUser) base.get_Renamed();
				}
				
				set
				{
					// System.out.println( "SETTING Thread: " + Thread.currentThread() + " " + (getUser() != null ? getUser().getAccountName() : "null" ) + " --> " + (newUser != null ? (newUser).getAccountName() : "null" ) );
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					base.set_Renamed(value);
				}
				
			}
			
			//UPGRADE_NOTE: The equivalent of method 'java.lang.ThreadLocal.initialValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
			public System.Object initialValue()
			{
				return org.owasp.esapi.Authenticator.anonymous;
			}
		}
		
		
		/*
		* The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
		* application. This enables API's for actions that require the request to be much simpler. For example, the logout()
		* method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
		*/
		private static ThreadLocalRequest currentRequest = new ThreadLocalRequest();
		
		//UPGRADE_ISSUE: Class 'java.lang.InheritableThreadLocal' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
		private class ThreadLocalRequest:InheritableThreadLocal
		{
			virtual public System.Web.HttpRequest Request
			{
				get
				{
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					return (System.Web.HttpRequest) base.get_Renamed();
				}
				
			}
			virtual public System.Web.HttpRequest User
			{
				set
				{
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					base.set_Renamed(value);
				}
				
			}
			
			//UPGRADE_NOTE: The equivalent of method 'java.lang.ThreadLocal.initialValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
			public System.Object initialValue()
			{
				return null;
			}
		}
		
		
		/*
		* The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
		* application. This enables API's for actions that require the response to be much simpler. For example, the logout()
		* method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
		*/
		private static ThreadLocalResponse currentResponse = new ThreadLocalResponse();
		
		//UPGRADE_ISSUE: Class 'java.lang.InheritableThreadLocal' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
		private class ThreadLocalResponse:InheritableThreadLocal
		{
			virtual public System.Web.HttpResponse Response
			{
				get
				{
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					return (System.Web.HttpResponse) base.get_Renamed();
				}
				
			}
			virtual public System.Web.HttpResponse User
			{
				set
				{
					//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
					base.set_Renamed(value);
				}
				
			}
			
			//UPGRADE_NOTE: The equivalent of method 'java.lang.ThreadLocal.initialValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
			public System.Object initialValue()
			{
				return null;
			}
		}
		
		
		
		
		public Authenticator()
		{
		}
		
		/// <summary> Clears all threadlocal variables from the thread. This should ONLY be called after
		/// all possible ESAPI operations have concluded. If you clear too early, many calls will
		/// fail, including logging, which requires the user identity.
		/// </summary>
		public virtual void  clearCurrent()
		{
			currentUser.User = null;
			//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
			currentResponse.set_Renamed(null);
			//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
			currentRequest.set_Renamed(null);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#createAccount(java.lang.String, java.lang.String)
		*/
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'createUser'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual User createUser(System.String accountName, System.String password1, System.String password2)
		{
			lock (this)
			{
				loadUsersIfNecessary();
				if (accountName == null)
				{
					throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName");
				}
				if (userMap.Contains(accountName.ToLower()))
				{
					throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " + accountName);
				}
				User user = new User(accountName, password1, password2);
				userMap[accountName.ToLower()] = user;
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "New user created: " + accountName);
				saveUsers();
				return user;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#exists(java.lang.String)
		*/
		public virtual bool exists(System.String accountName)
		{
			User user = getUser(accountName);
			return user != null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#generateStrongPassword(int, char[])
		*/
		public virtual System.String generateStrongPassword()
		{
			return generateStrongPassword("");
		}
		
		private System.String generateStrongPassword(System.String oldPassword)
		{
			IRandomizer r = ESAPI.randomizer();
			int letters = r.getRandomInteger(4, 6); // inclusive, exclusive
			int digits = 7 - letters;
			System.String passLetters = r.getRandomString(letters, Encoder.CHAR_PASSWORD_LETTERS);
			System.String passDigits = r.getRandomString(digits, Encoder.CHAR_PASSWORD_DIGITS);
			System.String passSpecial = r.getRandomString(1, Encoder.CHAR_PASSWORD_SPECIALS);
			System.String newPassword = passLetters + passSpecial + passDigits;
			return newPassword;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#generateStrongPassword(int, char[])
		*/
		public virtual System.String generateStrongPassword(System.String oldPassword, IUser user)
		{
			System.String newPassword = generateStrongPassword(oldPassword);
			if (newPassword != null)
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Generated strong password for " + user.AccountName);
			return newPassword;
		}
		
		/*
		* Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the
		* logger calls getCurrentUser() and this could cause a loop.
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#getCurrentUser()
		*/
		public virtual User getCurrentUser()
		{
			//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.get' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
			User user = (User) currentUser.get_Renamed();
			if (user == null)
				user = anonymous;
			return user;
		}
		
		/// <summary> Gets the user object with the matching account name or null if there is no match.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// </param>
		/// <returns> the user, or null if not matched.
		/// </returns>
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'getUser'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual User getUser(System.String accountName)
		{
			lock (this)
			{
				loadUsersIfNecessary();
				User user = (User) userMap[accountName.ToLower()];
				return user;
			}
		}
		
		/// <summary> Gets the user names.
		/// 
		/// </summary>
		/// <returns> list of user account names
		/// </returns>
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'getUserNames'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual SupportClass.SetSupport getUserNames()
		{
			lock (this)
			{
				loadUsersIfNecessary();
				//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
				//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
				return new SupportClass.HashSetSupport(new SupportClass.HashSetSupport(userMap.Keys));
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#hashPassword(java.lang.String, java.lang.String)
		*/
		public virtual System.String hashPassword(System.String password, System.String accountName)
		{
			System.String salt = accountName.ToLower();
			return ESAPI.encryptor().hash(password, salt);
		}
		
		/// <summary> Load users.
		/// 
		/// </summary>
		/// <returns> the hash map
		/// </returns>
		/// <throws>  AuthenticationException the authentication exception </throws>
		protected internal virtual void  loadUsersIfNecessary()
		{
			if (userDB == null)
				userDB = new System.IO.FileInfo(((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory.FullName + "\\" + "users.txt");
			
			// We only check at most every checkInterval milliseconds
			long now = (System.DateTime.Now.Ticks - 621355968000000000) / 10000;
			if (now - lastChecked < checkInterval)
			{
				return ;
			}
			lastChecked = now;
			
			//UPGRADE_TODO: The equivalent in .NET for method 'java.io.File.lastModified' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
			long lastModified = ((userDB.LastWriteTime.Ticks - 621355968000000000) / 10000);
			if (this.lastModified == lastModified)
			{
				return ;
			}
			loadUsersImmediately();
		}
		
		protected internal virtual void  loadUsersImmediately()
		{
			// file was touched so reload it
			lock (this)
			{
				logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Loading users from " + userDB.FullName, null);
				
				// FIXME: AAA Necessary?
				// add the Anonymous user to the database
				// map.put(anonymous.getAccountName(), anonymous);
				
				System.IO.StreamReader reader = null;
				try
				{
					//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
					System.Collections.Hashtable map = new System.Collections.Hashtable();
					//UPGRADE_TODO: The differences in the expected value  of parameters for constructor 'java.io.BufferedReader.BufferedReader'  may cause compilation errors.  "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1092'"
					//UPGRADE_WARNING: At least one expression was used more than once in the target code. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1181'"
					//UPGRADE_TODO: Constructor 'java.io.FileReader.FileReader' was converted to 'System.IO.StreamReader' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073'"
					reader = new System.IO.StreamReader(new System.IO.StreamReader(userDB.FullName, System.Text.Encoding.Default).BaseStream, new System.IO.StreamReader(userDB.FullName, System.Text.Encoding.Default).CurrentEncoding);
					System.String line = null;
					while ((line = reader.ReadLine()) != null)
					{
						if (line.Length > 0 && line[0] != '#')
						{
							User user = new User(line);
							if (!user.AccountName.Equals("anonymous"))
							{
								if (map.ContainsKey(user.AccountName))
								{
									logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Problem in user file. Skipping duplicate user: " + user, null);
								}
								map[user.AccountName] = user;
							}
						}
					}
					userMap = map;
					this.lastModified = (System.DateTime.Now.Ticks - 621355968000000000) / 10000;
					logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "User file reloaded: " + map.Count, null);
				}
				catch (System.Exception e)
				{
					logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Failure loading user file: " + userDB.FullName, e);
				}
				finally
				{
					try
					{
						if (reader != null)
						{
							reader.Close();
						}
					}
					catch (System.IO.IOException e)
					{
						logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Failure closing user file: " + userDB.FullName, e);
					}
				}
			}
		}
		
		/// <summary> Utility method to extract credentials and verify them.
		/// 
		/// </summary>
		/// <param name="request">
		/// </param>
		/// <param name="response">
		/// </param>
		/// <returns>
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <throws>  </throws>
		private User loginWithUsernameAndPassword(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			
			// FIXME: AAA the login servlet path should also be a configuration - this
			// should check (if loginrequest && parameters then do
			// loginWithPassword)
			
			//UPGRADE_TODO: Method 'javax.servlet.ServletRequest.getParameter' was converted to 'System.Web.HttpRequest' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletServletRequestgetParameter_javalangString'"
			System.String username = request[ESAPI.securityConfiguration().UsernameParameterName];
			//UPGRADE_TODO: Method 'javax.servlet.ServletRequest.getParameter' was converted to 'System.Web.HttpRequest' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletServletRequestgetParameter_javalangString'"
			System.String password = request[ESAPI.securityConfiguration().PasswordParameterName];
			
			// if a logged-in user is requesting to login, log them out first
			User user = getCurrentUser();
			if (user != null && !user.Anonymous)
			{
				logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "User requested relogin. Performing logout then authentication");
				user.logout();
			}
			
			// now authenticate with username and password
			if (username == null || password == null)
			{
				if (username == null)
					username = "unspecified user";
				throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed for " + username + " because of null username or password");
			}
			user = getUser(username);
			if (user == null)
			{
				throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed because user " + username + " doesn't exist");
			}
			user.loginWithPassword(password);
			return user;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#removeUser(java.lang.String)
		*/
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'removeUser'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual void  removeUser(System.String accountName)
		{
			lock (this)
			{
				loadUsersIfNecessary();
				User user = getUser(accountName);
				if (user == null)
				{
					throw new AuthenticationAccountsException("Remove user failed", "Can't remove invalid accountName " + accountName);
				}
				userMap.Remove(accountName.ToLower());
				saveUsers();
			}
		}
		
		/// <summary> Saves the user database to the file system. In this implementation you must call save to commit any changes to
		/// the user file. Otherwise changes will be lost when the program ends.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException the authentication exception </throws>
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'saveUsers'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		protected internal virtual void  saveUsers()
		{
			lock (this)
			{
				System.IO.StreamWriter writer = null;
				try
				{
					//UPGRADE_WARNING: At least one expression was used more than once in the target code. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1181'"
					//UPGRADE_TODO: Constructor 'java.io.FileWriter.FileWriter' was converted to 'System.IO.StreamWriter' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileWriterFileWriter_javaioFile'"
					//UPGRADE_TODO: Class 'java.io.FileWriter' was converted to 'System.IO.StreamWriter' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileWriter'"
					writer = new System.IO.StreamWriter(new System.IO.StreamWriter(userDB.FullName, false, System.Text.Encoding.Default).BaseStream, new System.IO.StreamWriter(userDB.FullName, false, System.Text.Encoding.Default).Encoding);
					//UPGRADE_TODO: Method 'java.io.PrintWriter.println' was converted to 'System.IO.TextWriter.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintWriterprintln_javalangString'"
					writer.WriteLine("# This is the user file associated with the ESAPI library from http://www.owasp.org");
					//UPGRADE_TODO: Method 'java.io.PrintWriter.println' was converted to 'System.IO.TextWriter.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintWriterprintln_javalangString'"
					writer.WriteLine("# accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
					//UPGRADE_TODO: Method 'java.io.PrintWriter.println' was converted to 'System.IO.TextWriter.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintWriterprintln'"
					writer.WriteLine();
					saveUsers(writer);
					writer.Flush();
					logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "User file written to disk");
				}
				catch (System.IO.IOException e)
				{
					logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Problem saving user file " + userDB.FullName, e);
					throw new AuthenticationException("Internal Error", "Problem saving user file " + userDB.FullName, e);
				}
				finally
				{
					if (writer != null)
					{
						//UPGRADE_NOTE: Exceptions thrown by the equivalent in .NET of method 'java.io.PrintWriter.close' may be different. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1099'"
						writer.Close();
						//UPGRADE_TODO: The equivalent in .NET for method 'java.io.File.lastModified' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
						lastModified = ((userDB.LastWriteTime.Ticks - 621355968000000000) / 10000);
						lastChecked = lastModified;
					}
				}
			}
		}
		
		/// <summary> Save users.
		/// 
		/// </summary>
		/// <param name="writer">the writer
		/// </param>
		/// <throws>  IOException </throws>
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'saveUsers'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		protected internal virtual void  saveUsers(System.IO.StreamWriter writer)
		{
			lock (this)
			{
				System.Collections.IEnumerator i = getUserNames().GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String accountName = (System.String) i.Current;
					User u = getUser(accountName);
					if (u != null && !u.Anonymous)
					{
						//UPGRADE_TODO: Method 'java.io.PrintWriter.println' was converted to 'System.IO.TextWriter.WriteLine' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioPrintWriterprintln_javalangString'"
						writer.WriteLine(u.save());
					}
					else
					{
						new AuthenticationCredentialsException("Problem saving user", "Skipping save of user " + accountName);
					}
				}
			}
		}
		
		/// <summary> This method should be called for every HTTP request, to login the current user either from the session of HTTP
		/// request. This method will set the current user so that getCurrentUser() will work properly. This method also
		/// checks that the user's access is still enabled, unlocked, and unexpired before allowing login. For convenience
		/// this method also returns the current user.
		/// 
		/// </summary>
		/// <param name="request">the request
		/// </param>
		/// <param name="response">the response
		/// </param>
		/// <returns> the user
		/// </returns>
		/// <throws>  AuthenticationException the authentication exception </throws>
		public virtual User login(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			
			if (request == null || response == null)
			{
				throw new AuthenticationCredentialsException("Invalid request", "Request or response objects were null");
			}
			// save the current request and response in the threadlocal variables
			setCurrentHTTP(request, response);
			
			if (!ESAPI.httpUtilities().SecureChannel)
			{
				new AuthenticationCredentialsException("Session exposed", "Authentication attempt made over non-SSL connection. Check web.xml and server configuration");
			}
			User user = null;
			
			// if there's a user in the session then use that
			user = UserFromSession;
			
			if (user != null)
			{
				user.setLastHostAddress(request.Params["HTTP_HOST"]);
				user.setFirstRequest(false);
			}
			else
			{
				// try to verify credentials
				user = loginWithUsernameAndPassword(request, response);
				user.setFirstRequest(true);
			}
			
			// don't let anonymous user log in
			if (user.Anonymous)
			{
				user.logout();
				throw new AuthenticationLoginException("Login failed", "Anonymous user cannot be set to current user");
			}
			
			// don't let disabled users log in
			if (!user.Enabled)
			{
				user.logout();
				System.DateTime tempAux = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				user.setLastFailedLoginTime(ref tempAux);
				throw new AuthenticationLoginException("Login failed", "Disabled user cannot be set to current user: " + user.AccountName);
			}
			
			// don't let locked users log in
			if (user.Locked)
			{
				user.logout();
				System.DateTime tempAux2 = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				user.setLastFailedLoginTime(ref tempAux2);
				throw new AuthenticationLoginException("Login failed", "Locked user cannot be set to current user: " + user.AccountName);
			}
			
			// don't let expired users log in
			if (user.Expired)
			{
				user.logout();
				System.DateTime tempAux3 = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				user.setLastFailedLoginTime(ref tempAux3);
				throw new AuthenticationLoginException("Login failed", "Expired user cannot be set to current user: " + user.AccountName);
			}
			
			setCurrentUser(user);
			return user;
		}
		
		
		/// <summary> Log out the current user.</summary>
		public virtual void  logout()
		{
			User user = getCurrentUser();
			user.logout();
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentUser(org.owasp.esapi.User)
		*/
		public virtual void  setCurrentUser(IUser user)
		{
			currentUser.User = user;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentHTTP(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)
		*/
		public virtual void  setCurrentHTTP(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			if (request == null || response == null)
			{
				new AuthenticationCredentialsException("Invalid request or response", "Request or response objects were null");
				return ;
			}
			//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
			currentRequest.set_Renamed(request);
			//UPGRADE_ISSUE: Method 'java.lang.InheritableThreadLocal.set' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangInheritableThreadLocal'"
			currentResponse.set_Renamed(response);
		}
		
		
		
		/*
		* This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
		* brute force attack, however the real strength comes from the name length and complexity.
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#validateAccountNameStrength(java.lang.String)
		*/
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#verifyAccountNameStrength(java.lang.String)
		*/
		public virtual void  verifyAccountNameStrength(System.String context, System.String newAccountName)
		{
			if (newAccountName == null)
			{
				throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null account name");
			}
			// FIXME: ENHANCE make the lengths configurable?
			if (!ESAPI.validator().isValidDataFromBrowser(context, "AccountName", newAccountName))
			{
				throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " + newAccountName);
			}
		}
		
		/*
		* This implementation checks: - for any 3 character substrings of the old password - for use of a length *
		* character sets > 16 (where character sets are upper, lower, digit, and special (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAuthenticator#validatePasswordStrength(java.lang.String)
		*/
		public virtual void  verifyPasswordStrength(System.String newPassword, System.String oldPassword)
		{
			System.String oPassword = (oldPassword == null)?"":oldPassword;
			
			// can't change to a password that contains any 3 character substring of old password
			int length = oPassword.Length;
			for (int i = 0; i < length - 2; i++)
			{
				System.String sub = oPassword.Substring(i, (i + 3) - (i));
				if (newPassword.IndexOf(sub) > - 1)
					throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password");
			}
			
			// new password must have enough character sets and length
			int charsets = 0;
			for (int i = 0; i < newPassword.Length; i++)
				if (System.Array.BinarySearch(Encoder.CHAR_LOWERS, (System.Object) newPassword[i]) > 0)
				{
					charsets++;
					break;
				}
			for (int i = 0; i < newPassword.Length; i++)
				if (System.Array.BinarySearch(Encoder.CHAR_UPPERS, (System.Object) newPassword[i]) > 0)
				{
					charsets++;
					break;
				}
			for (int i = 0; i < newPassword.Length; i++)
				if (System.Array.BinarySearch(Encoder.CHAR_DIGITS, (System.Object) newPassword[i]) > 0)
				{
					charsets++;
					break;
				}
			for (int i = 0; i < newPassword.Length; i++)
				if (System.Array.BinarySearch(Encoder.CHAR_SPECIALS, (System.Object) newPassword[i]) > 0)
				{
					charsets++;
					break;
				}
			int strength = newPassword.Length * charsets;
			
			System.Console.Out.WriteLine(" >>> PW: " + newPassword + "-->" + strength);
			
			if (strength < 16)
			{
				// FIXME: enhance - make password strength configurable
				throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
			}
		}
		static Authenticator()
		{
			logger = Logger.getLogger("ESAPI", "Authenticator");
		}
	}
}