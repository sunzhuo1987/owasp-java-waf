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
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IUser interface represents an application user or user account. There is quite a lot of information that an
	/// application must store for each user in order to enforce security properly. There are also many rules that govern
	/// authentication and identity management.
	/// <P>
	/// <img src="doc-files/Authenticator.jpg" height="600">
	/// <P>
	/// A user account can be in one of several states. When first created, a User should be disabled, not expired, and
	/// unlocked. To start using the account, an administrator should enable the account. The account can be locked for a
	/// number of reasons, most commonly because they have failed login for too many times. Finally, the account can expire
	/// after the expiration date has been reached. The User must be enabled, not expired, and unlocked in order to pass
	/// authentication.
	/// 
	/// </summary>
	/// <author>  <a href="mailto:jeff.williams@aspectsecurity.com?subject=ESAPI question">Jeff Williams</a> at <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	
	public interface IUser
	{
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the account name.
		/// 
		/// </summary>
		/// <returns> the account name
		/// </returns>
		/// <summary> Sets the account name.
		/// 
		/// </summary>
		/// <param name="accountName">the new account name
		/// </param>
		System.String AccountName
		{
			get;
			
			set;
			
		}
		/// <summary> Gets the CSRF token.
		/// 
		/// </summary>
		/// <returns> the CSRF token
		/// </returns>
		System.String CSRFToken
		{
			get;
			
		}
		/// <summary> Returns the number of failed login attempts since the last successful login for an account. This method is
		/// intended to be used as a part of the account lockout feature, to help protect against brute force attacks.
		/// However, the implementor should be aware that lockouts can be used to prevent access to an application by a
		/// legitimate user, and should consider the risk of denial of service.
		/// 
		/// </summary>
		/// <returns> the number of failed login attempts since the last successful login
		/// </returns>
		int FailedLoginCount
		{
			get;
			
		}
		/// <summary> Gets the remember token.
		/// 
		/// </summary>
		/// <returns> the remember token
		/// </returns>
		System.String RememberToken
		{
			get;
			
		}
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the roles assigned to a particular account.
		/// 
		/// </summary>
		/// <returns> an immutable set of roles
		/// </returns>
		/// <summary> Sets the roles.
		/// 
		/// </summary>
		/// <param name="roles">the new roles
		/// </param>
		SupportClass.SetSupport Roles
		{
			get;
			
			set;
			
		}
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the screen name.
		/// 
		/// </summary>
		/// <returns> the screen name
		/// </returns>
		/// <summary> Sets the screen name.
		/// 
		/// </summary>
		/// <param name="screenName">the new screen name
		/// </param>
		System.String ScreenName
		{
			get;
			
			set;
			
		}
		/// <summary> Checks if is anonymous.
		/// 
		/// </summary>
		/// <returns> true, if is anonymous
		/// </returns>
		bool Anonymous
		{
			get;
			
		}
		/// <summary> Checks if an account is currently enabled.
		/// 
		/// </summary>
		/// <returns> true, if is enabled account
		/// </returns>
		bool Enabled
		{
			get;
			
		}
		/// <summary> Checks if an account is expired.
		/// 
		/// </summary>
		/// <returns> true, account is expired
		/// </returns>
		bool Expired
		{
			get;
			
		}
		/// <summary> Checks if an account is unlocked.
		/// 
		/// </summary>
		/// <returns> true, account is unlocked
		/// </returns>
		bool Locked
		{
			get;
			
		}
		/// <summary> Tests to see if the user is currently logged in.
		/// 
		/// </summary>
		/// <returns> true if the user is logged out
		/// </returns>
		bool LoggedIn
		{
			get;
			
		}
		
		/// <summary> Adds a role to an account.
		/// 
		/// </summary>
		/// <param name="role">the role
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		void  addRole(System.String role);
		
		/// <summary> Adds the roles.
		/// 
		/// </summary>
		/// <param name="newRoles">the new roles
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		void  addRoles(SupportClass.SetSupport newRoles);
		
		/// <summary> Sets the user's password, performing a verification of the user's old password, the equality of the two new
		/// passwords, and the strength of the new password.
		/// 
		/// </summary>
		/// <param name="oldPassword">the old password
		/// </param>
		/// <param name="newPassword1">the new password1
		/// </param>
		/// <param name="newPassword2">the new password2
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		/// <throws>  EncryptionException  </throws>
		void  changePassword(System.String oldPassword, System.String newPassword1, System.String newPassword2);
		
		/// <summary> Disable account.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException the authentication exception </throws>
		void  disable();
		
		/// <summary> Enable account.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException the authentication exception </throws>
		void  enable();
		
		/// <summary> Returns the last host address used by the user. This will be used in any log messages generated by the processing
		/// of this request.
		/// 
		/// </summary>
		/// <returns>
		/// </returns>
		System.String getLastHostAddress();
		
		/// <summary> Returns the date of the last failed login time for a user. This date should be used in a message to users after a
		/// successful login, to notify them of potential attack activity on their account.
		/// 
		/// </summary>
		/// <returns> date of the last failed login
		/// </returns>
		/// <throws>  AuthenticationException the authentication exception </throws>
		System.DateTime getLastFailedLoginTime();
		
		/// <summary> Returns the date of the last successful login time for a user. This date should be used in a message to users
		/// after a successful login, to notify them of potential attack activity on their account.
		/// 
		/// </summary>
		/// <returns> date of the last successful login
		/// </returns>
		System.DateTime getLastLoginTime();
		
		/// <summary> Gets the last password change time.
		/// 
		/// </summary>
		/// <returns> the last password change time
		/// </returns>
		System.DateTime getLastPasswordChangeTime();
		
		/// <summary> Increment failed login count.</summary>
		void  incrementFailedLoginCount();
		
		/// <summary> Checks if an account has been assigned a particular role.
		/// 
		/// </summary>
		/// <param name="role">the role
		/// </param>
		/// <returns> true, if is user in role
		/// </returns>
		bool isInRole(System.String role);
		
		/// <summary> Returns true if the request is the first one of a new login session. This is intended to be used as a flag to
		/// display a message about the user's last successful login time.
		/// 
		/// </summary>
		/// <returns>
		/// </returns>
		bool isFirstRequest();
		
		/// <summary> Tests to see if the user's session has exceeded the absolute time out.
		/// 
		/// </summary>
		/// <param name="session">the session
		/// </param>
		/// <returns> whether user's session has exceeded the absolute time out
		/// </returns>
		bool isSessionAbsoluteTimeout(System.Web.SessionState.HttpSessionState session);
		
		/// <summary> Tests to see if the user's session has timed out from inactivity.
		/// 
		/// </summary>
		/// <param name="session">the session
		/// </param>
		/// <returns> whether user's session has timed out from inactivity
		/// </returns>
		bool isSessionTimeout(System.Web.SessionState.HttpSessionState session);
		
		/// <summary> Lock the user's account.</summary>
		void  lock_Renamed();
		
		/// <summary> Login with password.
		/// 
		/// </summary>
		/// <param name="password">the password
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		void  loginWithPassword(System.String password);
		
		/// <summary> Logout this user.</summary>
		void  logout();
		
		/// <summary> Removes a role from an account.
		/// 
		/// </summary>
		/// <param name="role">the role
		/// </param>
		/// <throws>  AuthenticationException the authentication exception </throws>
		
		void  removeRole(System.String role);
		
		/// <summary> Returns a token to be used as a prevention against CSRF attacks. This token should be added to all links and
		/// forms. The application should verify that all requests contain the token, or they may have been generated by a
		/// CSRF attack. It is generally best to perform the check in a centralized location, either a filter or controller.
		/// See the verifyCSRFToken method.
		/// 
		/// </summary>
		/// <returns> the string
		/// </returns>
		/// <throws>  AuthenticationException the authentication exception </throws>
		System.String resetCSRFToken();
		
		/// <summary> Returns a token to be used as a "remember me" cookie. The cookie is not seen by the user and can be fairly long,
		/// at least 20 digits is suggested to prevent brute force attacks. See loginWithRememberToken.
		/// 
		/// </summary>
		/// <returns> the string
		/// </returns>
		/// <throws>  AuthenticationException the authentication exception </throws>
		System.String resetRememberToken();
		
		/// <summary> Unlock account.</summary>
		void  unlock();
		
		/// <summary> Verify that the supplied password matches the password for this user. This method
		/// is typically used for "reauthentication" for the most sensitive functions, such
		/// as transactions, changing email address, and changing other account information.
		/// 
		/// </summary>
		/// <param name="password">
		/// </param>
		/// <returns>
		/// </returns>
		/// <throws>  EncryptionException  </throws>
		bool verifyPassword(System.String password);
	}
}