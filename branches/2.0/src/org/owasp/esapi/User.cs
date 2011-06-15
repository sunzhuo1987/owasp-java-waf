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
using AuthenticationHostException = org.owasp.esapi.errors.AuthenticationHostException;
using AuthenticationLoginException = org.owasp.esapi.errors.AuthenticationLoginException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ILogger = org.owasp.esapi.interfaces.ILogger;
using IUser = org.owasp.esapi.interfaces.IUser;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IUser interface. This implementation is serialized into a flat file in a simple format.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IUser">
	/// </seealso>
	[Serializable]
	public class User : IUser
	{
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the account name.
		/// 
		/// </summary>
		/// <returns> the accountName
		/// </returns>
		/// <summary> Sets the account name.
		/// 
		/// </summary>
		/// <param name="accountName">the accountName to set
		/// </param>
		virtual public System.String AccountName
		{
			get
			{
				return accountName;
			}
			
			set
			{
				System.String old = value;
				this.accountName = value.ToLower();
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Account name changed from " + old + " to " + AccountName);
			}
			
		}
		/// <summary> Gets the CSRF token. Use the HTTPUtilities.checkCSRFToken( request ) to verify the token.
		/// 
		/// </summary>
		/// <returns> the csrfToken
		/// </returns>
		virtual public System.String CSRFToken
		{
			get
			{
				return csrfToken;
			}
			
		}
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the expiration time.
		/// 
		/// </summary>
		/// <returns> The expiration time of the current user.
		/// </returns>
		/// <summary> Sets the expiration time.
		/// 
		/// </summary>
		/// <param name="expirationTime">the expirationTime to set
		/// </param>
		virtual public System.DateTime ExpirationTime
		{
			get
			{
				//UPGRADE_ISSUE: Method 'java.util.Date.clone' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilDateclone'"
				return (System.DateTime) expirationTime.clone();
			}
			
			set
			{
				//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
				//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
				this.expirationTime = new System.DateTime(value.Ticks);
				//UPGRADE_TODO: Method 'java.util.Date.toString' was converted to 'System.DateTime.ToString' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDatetoString'"
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Account expiration time set to " + value.ToString("r") + " for " + AccountName);
			}
			
		}
		/// <summary> Gets the failed login count.
		/// 
		/// </summary>
		/// <returns> the failedLoginCount
		/// </returns>
		virtual public int FailedLoginCount
		{
			get
			{
				return failedLoginCount;
			}
			
		}
		/// <summary> Gets the remember token.
		/// 
		/// </summary>
		/// <returns> the rememberToken
		/// </returns>
		virtual public System.String RememberToken
		{
			get
			{
				return rememberToken;
			}
			
		}
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the roles.
		/// 
		/// </summary>
		/// <returns> the roles
		/// </returns>
		/// <summary> Sets the roles.
		/// 
		/// </summary>
		/// <param name="roles">the roles to set
		/// </param>
		virtual public SupportClass.SetSupport Roles
		{
			get
			{
				//UPGRADE_ISSUE: Method 'java.util.Collections.unmodifiableSet' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilCollections'"
				return Collections.unmodifiableSet(roles);
			}
			
			set
			{
				//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
				this.roles = new SupportClass.HashSetSupport();
				addRoles(value);
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Adding roles " + SupportClass.CollectionToString(value) + " to " + AccountName);
			}
			
		}
		virtual public System.String ScreenName
		{
			/*
			* (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IUser#getScreenName()
			*/
			
			get
			{
				return screenName;
			}
			
			/*
			* (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IUser#setScreenName(java.lang.String)
			*/
			
			set
			{
				this.screenName = value;
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "ScreenName changed to " + value + " for " + AccountName);
			}
			
		}
		virtual public bool Anonymous
		{
			/* (non-Javadoc)
			* @see org.owasp.esapi.interfaces.IUser#isAnonymous()
			*/
			
			get
			{
				return AccountName.Equals("anonymous");
			}
			
		}
		/// <summary> Checks if is enabled.
		/// 
		/// </summary>
		/// <returns> the enabled
		/// </returns>
		virtual public bool Enabled
		{
			get
			{
				return enabled;
			}
			
		}
		virtual public bool Expired
		{
			/* (non-Javadoc)
			* @see org.owasp.esapi.interfaces.IUser#isExpired()
			*/
			
			get
			{
				return (ExpirationTime < System.DateTime.Now);
				
				// FIXME: ENHANCE should expiration happen automatically?  Or based on lastPasswordChangeTime?
				//		long from = lastPasswordChangeTime.getTime();
				//		long to = new Date().getTime();
				//		double difference = to - from;
				//		long days = Math.round((difference / (1000 * 60 * 60 * 24)));
				//		return days > 60;
			}
			
		}
		virtual public bool Locked
		{
			/*
			* (non-Javadoc)
			* 
			* @see org.owasp.esapi.interfaces.IUser#isLocked()
			*/
			
			get
			{
				return locked;
			}
			
		}
		virtual public bool LoggedIn
		{
			/* (non-Javadoc)
			* @see org.owasp.esapi.interfaces.IUser#isLoggedIn()
			*/
			
			get
			{
				return loggedIn;
			}
			
		}
		
		
		/// <summary>The Constant serialVersionUID. </summary>
		private const long serialVersionUID = 1L;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.User'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary>true only for the first HTTP request, false afterwards </summary>
		private bool isFirstRequest_Renamed_Field = true;
		
		/// <summary>The account name. </summary>
		private System.String accountName = "";
		
		/// <summary>The screen name. </summary>
		private System.String screenName = "";
		
		/// <summary>The hashed password. </summary>
		private System.String hashedPassword = "";
		
		/// <summary>The old password hashes. </summary>
		private System.Collections.IList oldPasswordHashes = new System.Collections.ArrayList();
		
		/// <summary>The remember token. </summary>
		private System.String rememberToken = "";
		
		/// <summary>The csrf token. </summary>
		private System.String csrfToken = "";
		
		/// <summary>The roles. </summary>
		//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
		private SupportClass.SetSupport roles = new SupportClass.HashSetSupport();
		
		/// <summary>The locked. </summary>
		private bool locked = false;
		
		/// <summary>The logged in. </summary>
		private bool loggedIn = true;
		
		/// <summary>The enabled. </summary>
		private bool enabled = false;
		
		/// <summary>The last host address used. </summary>
		private System.String lastHostAddress;
		
		/// <summary>The last password change time. </summary>
		private System.DateTime lastPasswordChangeTime = System.DateTime.Now;
		
		/// <summary>The last login time. </summary>
		private System.DateTime lastLoginTime = System.DateTime.Now;
		
		/// <summary>The last failed login time. </summary>
		private System.DateTime lastFailedLoginTime = System.DateTime.Now;
		
		/// <summary>The expiration time. </summary>
		//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
		private System.DateTime expirationTime = new System.DateTime(System.Int64.MaxValue);
		
		/// <summary>A flag to indicate that the password must be changed before the account can be used. </summary>
		// FIXME: ENHANCE enable this required password change feature?
		// private boolean requiresPasswordChange = true;
		
		/// <summary>The failed login count. </summary>
		private int failedLoginCount = 0;
		
		/// <summary>Intrusion detection events </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary events = new System.Collections.Hashtable();
		
		
		// FIXME: ENHANCE consider adding these for access control support
		//
		//private String authenticationMethod = null;
		//
		//private String connectionChannel = null;
		
		/// <summary> Instantiates a new user.</summary>
		protected internal User()
		{
			// hidden
		}
		
		/// <summary> Instantiates a new user.
		/// 
		/// </summary>
		/// <param name="line">the line
		/// </param>
		protected internal User(System.String line)
		{
			System.String[] parts = line.split("\\|");
			this.accountName = parts[0].Trim().ToLower();
			// FIXME: AAA validate account name
			this.hashedPassword = parts[1].Trim();
			
			this.roles.addAll(Arrays.asList(parts[2].Trim().ToLower().split(" *, *")));
			this.locked = !"unlocked".ToUpper().Equals(parts[3].Trim().ToUpper());
			this.enabled = "enabled".ToUpper().Equals(parts[4].Trim().ToUpper());
			this.rememberToken = parts[5].Trim();
			
			// generate a new csrf token
			this.resetCSRFToken();
			
			this.oldPasswordHashes.addAll(Arrays.asList(parts[6].Trim().split(" *, *")));
			this.lastHostAddress = parts[7].Trim();
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			this.lastPasswordChangeTime = new System.DateTime(System.Int64.Parse(parts[8].Trim()));
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			this.lastLoginTime = new System.DateTime(System.Int64.Parse(parts[9].Trim()));
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			this.lastFailedLoginTime = new System.DateTime(System.Int64.Parse(parts[10].Trim()));
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			this.expirationTime = new System.DateTime(System.Int64.Parse(parts[11].Trim()));
			this.failedLoginCount = System.Int32.Parse(parts[12].Trim());
		}
		
		/// <summary> Only for use in creating the Anonymous user.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// </param>
		/// <param name="password">the password
		/// </param>
		protected internal User(System.String accountName, System.String password)
		{
			this.accountName = accountName.ToLower();
		}
		
		/// <summary> Instantiates a new user.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// </param>
		/// <param name="password1">the password1
		/// </param>
		/// <param name="password2">the password2
		/// 
		/// </param>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		internal User(System.String accountName, System.String password1, System.String password2)
		{
			
			ESAPI.authenticator().verifyAccountNameStrength("Create User", accountName);
			
			if (password1 == null)
			{
				throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account " + accountName + " with a null password");
			}
			ESAPI.authenticator().verifyPasswordStrength(password1, null);
			
			if (!password1.Equals(password2))
				throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " + accountName + " do not match");
			
			this.accountName = accountName.ToLower();
			try
			{
				setHashedPassword(ESAPI.encryptor().hash(password1, this.accountName));
			}
			catch (EncryptionException ee)
			{
				throw new AuthenticationException("Internal error", "Error hashing password for " + this.accountName, ee);
			}
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			expirationTime = new System.DateTime((System.DateTime.Now.Ticks - 621355968000000000) / 10000 + (long) 1000 * 60 * 60 * 24 * 90); // 90 days
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Account created successfully: " + accountName);
		}
		
		/* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IUser#addRole(java.lang.String)
		*/
		public virtual void  addRole(System.String role)
		{
			System.String roleName = role.ToLower();
			if (ESAPI.validator().isValidDataFromBrowser("addRole", "RoleName", roleName))
			{
				roles.Add(roleName);
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Role " + roleName + " added to " + AccountName);
			}
			else
			{
				throw new AuthenticationAccountsException("Add role failed", "Attempt to add invalid role " + roleName + " to " + AccountName);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#addRoles(java.util.Set)
		*/
		public virtual void  addRoles(SupportClass.SetSupport newRoles)
		{
			System.Collections.IEnumerator i = newRoles.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				addRole((System.String) i.Current);
			}
		}
		
		/// <summary> Adds a security event to the user.
		/// 
		/// </summary>
		/// <param name="event">the event
		/// </param>
		public virtual void  addSecurityEvent(System.String eventName)
		{
			Event event_Renamed = (Event) events[eventName];
			if (event_Renamed == null)
			{
				event_Renamed = new Event(this, eventName);
				events[eventName] = event_Renamed;
			}
			
			Threshold q = ESAPI.securityConfiguration().getQuota(eventName);
			if (q.count > 0)
			{
				event_Renamed.increment(q.count, q.interval);
			}
		}
		
		// FIXME: ENHANCE - make admin only methods separate from public API
		/// <summary> Change password.
		/// 
		/// </summary>
		/// <param name="newPassword1">the new password1
		/// </param>
		/// <param name="newPassword2">the new password2
		/// </param>
		protected internal virtual void  changePassword(System.String newPassword1, System.String newPassword2)
		{
			System.DateTime tempAux = System.DateTime.Now;
			//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
			setLastPasswordChangeTime(ref tempAux);
			System.String newHash = ESAPI.authenticator().hashPassword(newPassword1, AccountName);
			setHashedPassword(newHash);
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Password changed for user: " + AccountName);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#setPassword(java.lang.String, java.lang.String)
		*/
		public virtual void  changePassword(System.String oldPassword, System.String newPassword1, System.String newPassword2)
		{
			if (!hashedPassword.Equals(ESAPI.authenticator().hashPassword(oldPassword, AccountName)))
			{
				throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password change on user: " + AccountName);
			}
			if (newPassword1 == null || newPassword2 == null || !newPassword1.Equals(newPassword2))
			{
				throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " + AccountName);
			}
			ESAPI.authenticator().verifyPasswordStrength(newPassword1, oldPassword);
			System.DateTime tempAux = System.DateTime.Now;
			//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
			setLastPasswordChangeTime(ref tempAux);
			System.String newHash = ESAPI.authenticator().hashPassword(newPassword1, accountName);
			if (oldPasswordHashes.Contains(newHash))
			{
				throw new AuthenticationCredentialsException("Password change failed", "Password change matches a recent password for user: " + AccountName);
			}
			setHashedPassword(newHash);
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Password changed for user: " + AccountName);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#disable()
		*/
		public virtual void  disable()
		{
			// FIXME: ENHANCE what about disabling for a short time period - to address DOS attack?
			enabled = false;
			logger.logSpecial("Account disabled: " + AccountName, null);
		}
		
		/// <summary> Dump a collection as a comma-separated list.</summary>
		/// <returns> the string
		/// </returns>
		protected internal virtual System.String dump(System.Collections.ICollection c)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			System.Collections.IEnumerator i = c.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String s = (System.String) i.Current;
				sb.Append(s);
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				if (i.MoveNext())
					sb.Append(",");
			}
			return sb.ToString();
		}
		
		/// <summary> Enable the account
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IUser.enable()">
		/// </seealso>
		public virtual void  enable()
		{
			this.enabled = true;
			logger.logSpecial("Account enabled: " + AccountName, null);
		}
		
		/* (non-Javadoc)
		* @see java.lang.Object#equals(java.lang.Object)
		*/
		public  override bool Equals(System.Object obj)
		{
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (!GetType().Equals(obj.GetType()))
				return false;
			//UPGRADE_NOTE: Final was removed from the declaration of 'other '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
			User other = (User) obj;
			return accountName.Equals(other.accountName);
		}
		
		/*
		* Gets the hashed password.
		* 
		* @return the hashedPassword
		*/
		protected internal virtual System.String getHashedPassword()
		{
			return hashedPassword;
		}
		
		/// <summary> Gets the last failed login time.
		/// 
		/// </summary>
		/// <returns> the lastFailedLoginTime
		/// </returns>
		public virtual System.DateTime getLastFailedLoginTime()
		{
			//UPGRADE_ISSUE: Method 'java.util.Date.clone' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilDateclone'"
			return (System.DateTime) lastFailedLoginTime.clone();
		}
		
		public virtual System.String getLastHostAddress()
		{
			return lastHostAddress;
		}
		
		/// <summary> Gets the last login time.
		/// 
		/// </summary>
		/// <returns> the lastLoginTime
		/// </returns>
		public virtual System.DateTime getLastLoginTime()
		{
			//UPGRADE_ISSUE: Method 'java.util.Date.clone' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilDateclone'"
			return (System.DateTime) lastLoginTime.clone();
		}
		
		/// <summary> Gets the last password change time.
		/// 
		/// </summary>
		/// <returns> the lastPasswordChangeTime
		/// </returns>
		public virtual System.DateTime getLastPasswordChangeTime()
		{
			//UPGRADE_ISSUE: Method 'java.util.Date.clone' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilDateclone'"
			return (System.DateTime) lastPasswordChangeTime.clone();
		}
		
		/* (non-Javadoc)
		* @see java.lang.Object#hashCode()
		*/
		public override int GetHashCode()
		{
			return accountName.GetHashCode();
		}
		
		/* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IUser#incrementFailedLoginCount()
		*/
		public virtual void  incrementFailedLoginCount()
		{
			failedLoginCount++;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#isInRole(java.lang.String)
		*/
		public virtual bool isInRole(System.String role)
		{
			return roles.Contains(role.ToLower());
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IIntrusionDetector#isSessionAbsoluteTimeout(java.lang.String)
		*/
		public virtual bool isSessionAbsoluteTimeout(System.Web.SessionState.HttpSessionState session)
		{
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			//UPGRADE_ISSUE: Method 'javax.servlet.http.HttpSession.getCreationTime' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservlethttpHttpSessiongetCreationTime'"
			System.DateTime deadline = new System.DateTime(session.getCreationTime() + 1000 * 60 * 60 * 2);
			System.DateTime now = System.DateTime.Now;
			return (now > deadline);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IIntrusionDetector#isSessionTimeout(java.lang.String)
		*/
		public virtual bool isSessionTimeout(System.Web.SessionState.HttpSessionState session)
		{
			//UPGRADE_TODO: Constructor 'java.util.Date.Date' was converted to 'System.DateTime.DateTime' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDateDate_long'"
			//UPGRADE_ISSUE: Method 'javax.servlet.http.HttpSession.getLastAccessedTime' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservlethttpHttpSessiongetLastAccessedTime'"
			System.DateTime deadline = new System.DateTime(session.getLastAccessedTime() + 1000 * 60 * 20);
			System.DateTime now = System.DateTime.Now;
			return (now > deadline);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#lock()
		*/
		public virtual void  lock_Renamed()
		{
			this.locked = true;
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Account locked: " + AccountName);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#login(java.lang.String)
		*/
		public virtual void  loginWithPassword(System.String password)
		{
			if (password == null || password.Equals(""))
			{
				System.DateTime tempAux = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				setLastFailedLoginTime(ref tempAux);
				incrementFailedLoginCount();
				throw new AuthenticationLoginException("Login failed", "Missing password: " + accountName);
			}
			
			// don't let disabled users log in
			if (!Enabled)
			{
				System.DateTime tempAux2 = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				setLastFailedLoginTime(ref tempAux2);
				incrementFailedLoginCount();
				throw new AuthenticationLoginException("Login failed", "Disabled user attempt to login: " + accountName);
			}
			
			// don't let locked users log in
			if (Locked)
			{
				System.DateTime tempAux3 = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				setLastFailedLoginTime(ref tempAux3);
				incrementFailedLoginCount();
				throw new AuthenticationLoginException("Login failed", "Locked user attempt to login: " + accountName);
			}
			
			// don't let expired users log in
			if (Expired)
			{
				System.DateTime tempAux4 = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				setLastFailedLoginTime(ref tempAux4);
				incrementFailedLoginCount();
				throw new AuthenticationLoginException("Login failed", "Expired user attempt to login: " + accountName);
			}
			
			// if this user is already logged in, log them out and reauthenticate
			if (!Anonymous)
			{
				logout();
			}
			
			try
			{
				if (verifyPassword(password))
				{
					// FIXME: AAA verify loggedIn is properly maintained
					loggedIn = true;
					System.Web.SessionState.HttpSessionState session = ((HTTPUtilities) ESAPI.httpUtilities()).changeSessionIdentifier();
					session.Add(Authenticator.USER, AccountName);
					ESAPI.authenticator().setCurrentUser(this);
					System.DateTime tempAux5 = System.DateTime.Now;
					//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
					setLastLoginTime(ref tempAux5);
					setLastHostAddress(((Authenticator) ESAPI.authenticator()).CurrentRequest.Params["HTTP_HOST"]);
					logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "User logged in: " + accountName);
				}
				else
				{
					throw new AuthenticationLoginException("Login failed", "Login attempt as " + AccountName + " failed");
				}
			}
			catch (EncryptionException ee)
			{
				throw new AuthenticationException("Internal error", "Error verifying password for " + accountName, ee);
			}
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#logout()
		*/
		public virtual void  logout()
		{
			Authenticator authenticator = ((Authenticator) ESAPI.authenticator());
			if (!authenticator.getCurrentUser().Anonymous)
			{
				System.Web.HttpRequest request = authenticator.CurrentRequest;
				//UPGRADE_TODO: Method 'javax.servlet.http.HttpServletRequest.getSession' was converted to 'System.Web.HttpContext.Current.Session' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservlethttpHttpServletRequestgetSession_boolean'"
				System.Web.SessionState.HttpSessionState session = System.Web.HttpContext.Current.Session;
				if (session != null)
				{
					//UPGRADE_TODO: Method 'javax.servlet.http.HttpSession.invalidate' was converted to 'System.Web.SessionState.HttpSessionState.Abandon' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservlethttpHttpSessioninvalidate'"
					session.Abandon();
				}
				ESAPI.httpUtilities().killCookie("JSESSIONID");
				loggedIn = false;
				logger.logSuccess(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Logout successful");
				authenticator.setCurrentUser(org.owasp.esapi.Authenticator.anonymous);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#removeRole(java.lang.String)
		*/
		public virtual void  removeRole(System.String role)
		{
			roles.Remove(role.ToLower());
			logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Role " + role + " removed from " + AccountName);
		}
		
		/// <summary> In this implementation, we have chosen to use a random token that is
		/// stored in the User object. Note that it is possible to avoid the use of
		/// server side state by using either the hash of the users's session id or
		/// an encrypted token that includes a timestamp and the user's IP address.
		/// user's IP address. A relatively short 8 character string has been chosen
		/// because this token will appear in all links and forms.
		/// 
		/// </summary>
		/// <returns> the string
		/// 
		/// </returns>
		/// <seealso cref="org.owasp.esapi.interfaces.IUser.resetCSRFToken()">
		/// </seealso>
		public virtual System.String resetCSRFToken()
		{
			// user.csrfToken = ESAPI.encryptor().hash( session.getId(),user.name );
			// user.csrfToken = ESAPI.encryptor().encrypt( address + ":" + ESAPI.encryptor().getTimeStamp();
			csrfToken = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			return csrfToken;
		}
		
		/// <summary> Reset password.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IUser.setPassword(java.lang.String, java.lang.String)">
		/// </seealso>
		/// <returns> the string
		/// </returns>
		public virtual System.String resetPassword()
		{
			System.String newPassword = ESAPI.authenticator().generateStrongPassword();
			changePassword(newPassword, newPassword);
			return newPassword;
		}
		
		/// <summary> Returns new remember token.
		/// 
		/// </summary>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual System.String resetRememberToken()
		{
			rememberToken = ESAPI.randomizer().getRandomString(20, Encoder.CHAR_ALPHANUMERICS);
			logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "New remember token generated for: " + AccountName);
			return rememberToken;
		}
		
		/// <summary> Save.
		/// 
		/// </summary>
		/// <returns> the string
		/// </returns>
		protected internal virtual System.String save()
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			sb.Append(accountName);
			sb.Append(" | ");
			sb.Append(getHashedPassword());
			sb.Append(" | ");
			sb.Append(dump(Roles));
			sb.Append(" | ");
			sb.Append(Locked?"locked":"unlocked");
			sb.Append(" | ");
			sb.Append(Enabled?"enabled":"disabled");
			sb.Append(" | ");
			sb.Append(RememberToken);
			sb.Append(" | ");
			sb.Append(dump(oldPasswordHashes));
			sb.Append(" | ");
			sb.Append(getLastHostAddress());
			sb.Append(" | ");
			//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
			sb.Append(getLastPasswordChangeTime().Ticks);
			sb.Append(" | ");
			//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
			sb.Append(getLastLoginTime().Ticks);
			sb.Append(" | ");
			//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
			sb.Append(getLastFailedLoginTime().Ticks);
			sb.Append(" | ");
			//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
			sb.Append(ExpirationTime.Ticks);
			sb.Append(" | ");
			sb.Append(failedLoginCount);
			return sb.ToString();
		}
		
		/// <summary> Sets the hashed password.
		/// 
		/// </summary>
		/// <param name="hash">the hash
		/// </param>
		internal virtual void  setHashedPassword(System.String hash)
		{
			oldPasswordHashes.Add(hashedPassword);
			if (oldPasswordHashes.Count > ESAPI.securityConfiguration().MaxOldPasswordHashes)
				oldPasswordHashes.RemoveAt(0);
			hashedPassword = hash;
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "New hashed password stored for " + AccountName);
		}
		
		/// <summary> Sets the last failed login time.
		/// 
		/// </summary>
		/// <param name="lastFailedLoginTime">the lastFailedLoginTime to set
		/// </param>
		//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
		protected internal virtual void  setLastFailedLoginTime(ref System.DateTime lastFailedLoginTime)
		{
			this.lastFailedLoginTime = lastFailedLoginTime;
			//UPGRADE_TODO: Method 'java.util.Date.toString' was converted to 'System.DateTime.ToString' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDatetoString'"
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Set last failed login time to " + lastFailedLoginTime.ToString("r") + " for " + AccountName);
		}
		
		
		/// <summary> Sets the last remote host address used by this User.</summary>
		/// <param name="remoteHost">
		/// </param>
		public virtual void  setLastHostAddress(System.String remoteHost)
		{
			User user = ((Authenticator) ESAPI.authenticator()).getCurrentUser();
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			remoteHost = request.UserHostAddress;
			if (lastHostAddress != null && !lastHostAddress.Equals(remoteHost) && user != null && request != null)
			{
				// returning remote address not remote hostname to prevent DNS lookup
				new AuthenticationHostException("Host change", "User session just jumped from " + lastHostAddress + " to " + remoteHost);
				lastHostAddress = remoteHost;
			}
		}
		
		/// <summary> Sets the last login time.
		/// 
		/// </summary>
		/// <param name="lastLoginTime">the lastLoginTime to set
		/// </param>
		//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
		protected internal virtual void  setLastLoginTime(ref System.DateTime lastLoginTime)
		{
			this.lastLoginTime = lastLoginTime;
			//UPGRADE_TODO: Method 'java.util.Date.toString' was converted to 'System.DateTime.ToString' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDatetoString'"
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Set last successful login time to " + lastLoginTime.ToString("r") + " for " + AccountName);
		}
		
		/// <summary> Sets the last password change time.
		/// 
		/// </summary>
		/// <param name="lastPasswordChangeTime">the lastPasswordChangeTime to set
		/// </param>
		//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
		protected internal virtual void  setLastPasswordChangeTime(ref System.DateTime lastPasswordChangeTime)
		{
			this.lastPasswordChangeTime = lastPasswordChangeTime;
			//UPGRADE_TODO: Method 'java.util.Date.toString' was converted to 'System.DateTime.ToString' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDatetoString'"
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Set last password change time to " + lastPasswordChangeTime.ToString("r") + " for " + AccountName);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see java.lang.Object#toString()
		*/
		public override System.String ToString()
		{
			return "USER:" + accountName;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#unlock()
		*/
		public virtual void  unlock()
		{
			this.locked = false;
			logger.logSpecial("Account unlocked: " + AccountName, null);
		}
		
		//FIXME:Enhance - think about having a second "transaction" password for each user
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IUser#verifyPassword(java.lang.String)
		*/
		public virtual bool verifyPassword(System.String password)
		{
			System.String hash = ESAPI.authenticator().hashPassword(password, accountName);
			if (hash.Equals(hashedPassword))
			{
				System.DateTime tempAux = System.DateTime.Now;
				//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
				setLastLoginTime(ref tempAux);
				failedLoginCount = 0;
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Password verified for " + AccountName);
				return true;
			}
			logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Password verification failed for " + AccountName);
			System.DateTime tempAux2 = System.DateTime.Now;
			//UPGRADE_NOTE: ref keyword was added to struct-type parameters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1303'"
			setLastFailedLoginTime(ref tempAux2);
			incrementFailedLoginCount();
			if (FailedLoginCount >= ESAPI.securityConfiguration().AllowedLoginAttempts)
			{
				lock_Renamed();
			}
			return false;
		}
		
		protected internal virtual void  setFirstRequest(bool b)
		{
			isFirstRequest_Renamed_Field = b;
		}
		
		public virtual bool isFirstRequest()
		{
			return isFirstRequest_Renamed_Field;
		}
		
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'Event' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		// FIXME: AAA this is a strange place for the event class to live.  Move to somewhere more appropriate.
		private class Event
		{
			private void  InitBlock(User enclosingInstance)
			{
				this.enclosingInstance = enclosingInstance;
			}
			private User enclosingInstance;
			public User Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			public System.String key;
			public System.Collections.ArrayList times = new System.Collections.ArrayList();
			public long count = 0;
			public Event(User enclosingInstance, System.String key)
			{
				InitBlock(enclosingInstance);
				this.key = key;
			}
			public virtual void  increment(int count, long interval)
			{
				System.DateTime now = System.DateTime.Now;
				times.Insert(0, now);
				while (times.Count > count)
					times.RemoveAt(times.Count - 1);
				if (times.Count == count)
				{
					System.DateTime past = (System.DateTime) times[count - 1];
					//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
					long plong = past.Ticks;
					//UPGRADE_TODO: Method 'java.util.Date.getTime' was converted to 'System.DateTime.Ticks' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilDategetTime'"
					long nlong = now.Ticks;
					if (nlong - plong < interval * 1000)
					{
						// FIXME: ENHANCE move all this event stuff inside IntrusionDetector?
						throw new IntrusionException();
					}
				}
			}
		}
		static User()
		{
			logger = Logger.getLogger("ESAPI", "User");
		}
	}
}