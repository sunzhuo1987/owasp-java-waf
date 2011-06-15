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
using AccessControlException = org.owasp.esapi.errors.AccessControlException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using EnterpriseSecurityException = org.owasp.esapi.errors.EnterpriseSecurityException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IHTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
	/// responses, sessions, cookies, headers, and logging.
	/// <P>
	/// <img src="doc-files/HTTPUtilities.jpg" height="600">
	/// <P>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IHTTPUtilities
	{
		/// <summary> Returns true if the request and response are using an SSL-enabled connection. This check should be made on
		/// every request from the login page through the logout confirmation page. Essentially, any page that uses the
		/// Authenticator.login() call should call this. Implementers should consider calling this method directly in
		/// their Authenticator.login() method. If this method returns true for a page that requires SSL, there must be a
		/// misconfiguration, an AuthenticationException is warranted. 
		/// 
		/// </summary>
		/// <param name="request">
		/// </param>
		/// <returns>
		/// </returns>
		bool SecureChannel
		{
			get;
			
		}
		
		/// <summary> Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks.
		/// This method should be used on all URLs to be put into all links and forms the application generates.
		/// 
		/// </summary>
		/// <param name="url">
		/// </param>
		/// <returns> the updated href with the CSRF token parameter
		/// </returns>
		System.String addCSRFToken(System.String href);
		
		/// <summary> Adds a cookie to the specified HttpServletResponse and adds the Http-Only flag.
		/// 
		/// </summary>
		/// <param name="name">the name
		/// </param>
		/// <param name="value">the value
		/// </param>
		/// <param name="domain">the domain
		/// </param>
		/// <param name="path">the path
		/// </param>
		/// <param name="response">the response
		/// </param>
		/// <param name="maxAge">the max age
		/// </param>
		void  safeAddCookie(System.String name, System.String value_Renamed, int maxAge, System.String domain, System.String path);
		
		/// <summary> Adds a header to an HttpServletResponse after checking for special characters (such as CRLF injection) that could enable 
		/// attacks like response splitting and other header-based attacks that nobody has thought of yet. 
		/// 
		/// </summary>
		/// <param name="name">the name
		/// </param>
		/// <param name="value">the value
		/// </param>
		/// <param name="response">the response
		/// </param>
		void  safeAddHeader(System.String name, System.String value_Renamed);
		
		/// <summary> Invalidate the old session after copying all of its contents to a newly created session with a new session id.
		/// Note that this is different from logging out and creating a new session identifier that does not contain the
		/// existing session contents. Care should be taken to use this only when the existing session does not contain
		/// hazardous contents.
		/// 
		/// </summary>
		/// <param name="request">the request
		/// </param>
		/// <returns> the http session
		/// </returns>
		/// <throws>  EnterpriseSecurityException the enterprise security exception </throws>
		System.Web.SessionState.HttpSessionState changeSessionIdentifier();
		
		/// <summary> Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and
		/// throws an IntrusionException if it is missing.
		/// 
		/// </summary>
		/// <param name="request">
		/// </param>
		/// <throws>  IntrusionException </throws>
		void  verifyCSRFToken();
		
		/// <summary> Decrypts an encrypted hidden field value and returns the cleartest. If the field does not decrypt properly,
		/// an IntrusionException is thrown to indicate tampering.
		/// </summary>
		/// <param name="encrypted">
		/// </param>
		/// <returns>
		/// </returns>
		System.String decryptHiddenField(System.String encrypted);
		
		/// <summary> Encrypts a hidden field value for use in HTML.</summary>
		/// <param name="value">
		/// </param>
		/// <returns>
		/// </returns>
		/// <throws>  EncryptionException </throws>
		System.String encryptHiddenField(System.String value_Renamed);
		
		
		/// <summary> Takes a querystring (i.e. everything after the ? in the URL) and returns an encrypted string containing the parameters.</summary>
		/// <param name="href">
		/// </param>
		/// <returns>
		/// </returns>
		System.String encryptQueryString(System.String query);
		
		/// <summary> Takes an encrypted querystring and returns a Map containing the original parameters.</summary>
		/// <param name="encrypted">
		/// </param>
		/// <returns>
		/// </returns>
		System.Collections.IDictionary decryptQueryString(System.String encrypted);
		
		/// <summary> Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
		/// is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
		/// possibly virus checking, and path and name checks. Refer to the file checking methods in IValidator for more
		/// information.
		/// 
		/// </summary>
		/// <param name="request">the request
		/// </param>
		/// <param name="tempDir">the temp dir
		/// </param>
		/// <param name="finalDir">the final dir
		/// </param>
		/// <throws>  ValidationException the validation exception </throws>
		void  getSafeFileUploads(System.IO.FileInfo tempDir, System.IO.FileInfo finalDir);
		
		/// <summary> Retrieves a map of data from the encrypted cookie. </summary>
		System.Collections.IDictionary decryptStateFromCookie();
		
		/// <summary> Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
		/// this response may not be killed by this method.
		/// 
		/// </summary>
		/// <param name="request">the request
		/// </param>
		/// <param name="response">the response
		/// </param>
		void  killAllCookies();
		
		/// <summary> Kills the specified cookie by setting a new cookie that expires immediately.
		/// 
		/// </summary>
		/// <param name="name">the cookie name
		/// </param>
		void  killCookie(System.String name);
		
		/// <summary> Stores a Map of data in an encrypted cookie.</summary>
		void  encryptStateInCookie(System.Collections.IDictionary cleartext);
		
		
		/// <summary> This method generates a redirect response that can only be used to redirect the browser to safe locations.
		/// Importantly, redirect requests can be modified by attackers, so do not rely information contained within redirect
		/// requests, and do not include sensitive information in a redirect.
		/// 
		/// </summary>
		/// <param name="location">the URL to redirect to
		/// </param>
		/// <param name="response">the current HttpServletResponse
		/// </param>
		/// <throws>  ValidationException the validation exception </throws>
		/// <throws>  IOException Signals that an I/O exception has occurred. </throws>
		void  safeSendRedirect(System.String context, System.String location);
		
		/// <summary> This method perform a forward to any resource located inside the WEB-INF directory. Forwarding to
		/// publically accessible resources can be dangerous, as the request will have already passed the URL
		/// based access control check. This method ensures that you can only forward to non-publically
		/// accessible resources.
		/// 
		/// </summary>
		/// <param name="context">
		/// </param>
		/// <param name="location">
		/// </param>
		/// <throws>  AccessControlException </throws>
		/// <throws>  ServletException </throws>
		/// <throws>  IOException </throws>
		void  safeSendForward(System.String context, System.String location);
		
		
		/// <summary> Sets the content type on each HTTP response, to help protect against cross-site scripting attacks and other types
		/// of injection into HTML documents.
		/// 
		/// </summary>
		/// <param name="response">
		/// </param>
		void  safeSetContentType();
		
		
		/// <summary> Set headers to protect sensitive information against being cached in the browser. Developers should make this
		/// call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any
		/// intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach
		/// is to set all relevant headers to their most restrictive setting. These include:
		/// 
		/// <PRE>
		/// 
		/// Cache-Control: no-store<BR>
		/// Cache-Control: no-cache<BR>
		/// Cache-Control: must-revalidate<BR>
		/// Expires: -1<BR>
		/// 
		/// </PRE>
		/// 
		/// Note that the header "pragma: no-cache" is only useful in HTTP requests, not HTTP responses. So even though there
		/// are many articles recommending the use of this header, it is not helpful for preventing browser caching. For more
		/// information, please refer to the relevant standards:
		/// <UL>
		/// <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">HTTP/1.1 Cache-Control "no-cache"</a>
		/// <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1">HTTP/1.1 Cache-Control "no-store"</a>
		/// <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2">HTTP/1.0 Pragma "no-cache"</a>
		/// <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32">HTTP/1.0 Expires</a>
		/// <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21">IE6 Caching Issues</a>
		/// <LI><a href="http://support.microsoft.com/kb/937479">Firefox browser.cache.disk_cache_ssl</a>
		/// <LI><a href="http://www.mozilla.org/quality/networking/docs/netprefs.html">Mozilla</a>
		/// </UL>
		/// 
		/// </summary>
		/// <param name="response">the current HttpServletResponse
		/// </param>
		void  setNoCacheHeaders();
	}
}