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
using User = org.owasp.esapi.User;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IAuthenticator interface defines a set of methods for generating and
	/// handling account credentials and session identifiers. The goal of this
	/// interface is to encourage developers to protect credentials from disclosure
	/// to the maximum extent possible.
	/// <P>
	/// <img src="doc-files/Authenticator.jpg" height="600">
	/// <P>
	/// Once possible implementation relies on the use of a thread local variable to
	/// store the current user's identity. The application is responsible for calling
	/// setCurrentUser() as soon as possible after each HTTP request is received. The
	/// value of getCurrentUser() is used in several other places in this API. This
	/// eliminates the need to pass a user object to methods throughout the library.
	/// For example, all of the logging, access control, and exception calls need
	/// access to the currently logged in user.
	/// <P>
	/// The goal is to minimize the responsibility of the developer for
	/// authentication. In this example, the user simply calls authenticate with the
	/// current request and the name of the parameters containing the username and
	/// password. The implementation should verify the password if necessary, create
	/// a session if necessary, and set the user as the current user.
	/// 
	/// <pre>
	/// public void doPost(ServletRequest request, ServletResponse response) {
	/// try {
	/// ESAPI.authenticator().authenticate(request, response, &quot;username&quot;,&quot;password&quot;);
	/// // continue with authenticated user
	/// } catch (AuthenticationException e) {
	/// // handle failed authentication (it's already been logged)
	/// }
	/// </pre>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IAuthenticator
	{
		
		/// <summary> Clear the current user, request, and response. This allows the thread to be reused safely.</summary>
		void  clearCurrent();
		
		/// <summary> Authenticates the user's credentials from the HttpServletRequest if
		/// necessary, creates a session if necessary, and sets the user as the
		/// current user.
		/// 
		/// </summary>
		/// <param name="request">the current HTTP request
		/// </param>
		/// <param name="response">the response
		/// 
		/// </param>
		/// <returns> the user
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		User login(System.Web.HttpRequest request, System.Web.HttpResponse response); // FIXME: Future - Should return IUser, works in Java 1.5+ but hacked here for Java 1.4
		
		
		/// <summary> Logs out the current user.</summary>
		void  logout();
		
		/// <summary> Creates the user.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// </param>
		/// <param name="password1">the password
		/// </param>
		/// <param name="password2">copy of the password
		/// 
		/// </param>
		/// <returns> the new User object
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		User createUser(System.String accountName, System.String password1, System.String password2); // FIXME: Future - Should return IUser, works in Java 1.5+ but hacked here for Java 1.4
		
		/// <summary> Generate a strong password.
		/// 
		/// </summary>
		/// <returns> the string
		/// </returns>
		System.String generateStrongPassword();
		
		/// <summary> Generate strong password that takes into account the user's information and old password.
		/// 
		/// </summary>
		/// <param name="oldPassword">the old password
		/// </param>
		/// <param name="user">the user
		/// 
		/// </param>
		/// <returns> the string
		/// </returns>
		System.String generateStrongPassword(System.String oldPassword, IUser user);
		
		/// <summary> Returns the User matching the provided accountName.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// 
		/// </param>
		/// <returns> the matching User object, or null if no match exists
		/// </returns>
		User getUser(System.String accountName); // FIXME: Future - Should return IUser, works in Java 1.5+ but hacked here for Java 1.4
		
		/// <summary> Gets the user names.
		/// 
		/// </summary>
		/// <returns> the user names
		/// </returns>
		SupportClass.SetSupport getUserNames();
		
		/// <summary> Returns the currently logged in User.
		/// 
		/// </summary>
		/// <returns> the matching User object, or the Anonymous user if no match
		/// exists
		/// </returns>
		User getCurrentUser(); // FIXME: Future - Should return IUser, works in Java 1.5+ but hacked here for Java 1.4
		
		/// <summary> Sets the currently logged in User.
		/// 
		/// </summary>
		/// <param name="user">the current user
		/// </param>
		void  setCurrentUser(IUser user);
		
		/// <summary> Returns a string representation of the hashed password, using the
		/// accountName as the salt. The salt helps to prevent against "rainbow"
		/// table attacks where the attacker pre-calculates hashes for known strings.
		/// 
		/// </summary>
		/// <param name="password">the password
		/// </param>
		/// <param name="accountName">the account name
		/// 
		/// </param>
		/// <returns> the string
		/// </returns>
		System.String hashPassword(System.String password, System.String accountName);
		
		/// <summary> Removes the account.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// 
		/// </param>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		void  removeUser(System.String accountName);
		
		/// <summary> Validate password strength.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// 
		/// </param>
		/// <returns> true, if successful
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		void  verifyAccountNameStrength(System.String context, System.String accountName);
		
		/// <summary> Validate password strength.
		/// 
		/// </summary>
		/// <param name="oldPassword">the old password
		/// </param>
		/// <param name="newPassword">the new password
		/// 
		/// </param>
		/// <returns> true, if successful
		/// 
		/// </returns>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		void  verifyPasswordStrength(System.String oldPassword, System.String newPassword);
		
		/// <summary> Verifies the account exists.
		/// 
		/// </summary>
		/// <param name="accountName">the account name
		/// 
		/// </param>
		/// <returns> true, if successful
		/// </returns>
		bool exists(System.String accountName);
	}
}