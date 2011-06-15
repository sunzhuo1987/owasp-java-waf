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
//UPGRADE_TODO: The type 'java.util.regex.Pattern' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Pattern = java.util.regex.Pattern;
//UPGRADE_TODO: The type 'org.apache.commons.fileupload.FileItem' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using FileItem = org.apache.commons.fileupload.FileItem;
//UPGRADE_TODO: The type 'org.apache.commons.fileupload.ProgressListener' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using ProgressListener = org.apache.commons.fileupload.ProgressListener;
//UPGRADE_TODO: The type 'org.apache.commons.fileupload.disk.DiskFileItemFactory' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using DiskFileItemFactory = org.apache.commons.fileupload.disk.DiskFileItemFactory;
//UPGRADE_TODO: The type 'org.apache.commons.fileupload.servlet.ServletFileUpload' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using ServletFileUpload = org.apache.commons.fileupload.servlet.ServletFileUpload;
using AccessControlException = org.owasp.esapi.errors.AccessControlException;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using EncodingException = org.owasp.esapi.errors.EncodingException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
using ValidationUploadException = org.owasp.esapi.errors.ValidationUploadException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IHTTPUtilities interface. This implementation
	/// uses the Apache Commons FileUploader library, which in turn uses the Apache
	/// Commons IO library.
	/// <P>
	/// To simplify the interface, this class uses the current request and response that
	/// are tracked by ThreadLocal variables in the Authenticator. This means that you
	/// must have called ESAPI.authenticator().setCurrentHTTP(null, response) before
	/// calling these methods. This is done automatically by the Authenticator.login() method.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities">
	/// </seealso>
	public class HTTPUtilities : org.owasp.esapi.interfaces.IHTTPUtilities
	{
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'AnonymousClassProgressListener' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		private class AnonymousClassProgressListener : ProgressListener
		{
			public AnonymousClassProgressListener(System.Web.SessionState.HttpSessionState session, HTTPUtilities enclosingInstance)
			{
				InitBlock(session, enclosingInstance);
			}
			private void  InitBlock(System.Web.SessionState.HttpSessionState session, HTTPUtilities enclosingInstance)
			{
				this.session = session;
				this.enclosingInstance = enclosingInstance;
			}
			//UPGRADE_NOTE: Final variable session was copied into class AnonymousClassProgressListener. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1023'"
			private System.Web.SessionState.HttpSessionState session;
			private HTTPUtilities enclosingInstance;
			public HTTPUtilities Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			private long megaBytes = - 1;
			private long progress = 0;
			
			public virtual void  update(long pBytesRead, long pContentLength, int pItems)
			{
				if (pItems == 0)
					return ;
				long mBytes = pBytesRead / 1000000;
				if (megaBytes == mBytes)
					return ;
				megaBytes = mBytes;
				//UPGRADE_WARNING: Data types in Visual C# might be different.  Verify the accuracy of narrowing conversions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1042'"
				progress = (long) (((double) pBytesRead / (double) pContentLength) * 100);
				session.Add("progress", System.Convert.ToString(progress));
				// logger.logSuccess(Logger.SECURITY, "   Item " + pItems + " (" + progress + "% of " + pContentLength + " bytes]");
			}
		}
		private void  InitBlock()
		{
			maxBytes = ESAPI.securityConfiguration().AllowedFileUploadSize;
		}
		/// <summary> Returns true if the request was transmitted over an SSL enabled
		/// connection. This implementation ignores the built-in isSecure() method
		/// and uses the URL to determine if the request was transmitted over SSL.
		/// </summary>
		virtual public bool SecureChannel
		{
			get
			{
				System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
				return (SupportClass.GetRequestURL(request)[4] == 's');
			}
			
		}
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.HTTPUtilities'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary>The max bytes. </summary>
		//UPGRADE_NOTE: The initialization of  'maxBytes' was moved to method 'InitBlock'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		internal int maxBytes;
		
		public HTTPUtilities()
		{
			InitBlock();
		}
		
		// FIXME: Enhance - consider adding addQueryChecksum(String href) that would just verify that none of the parameters in the querystring have changed.  Could do the same for forms.
		// FIXME: Enhance - also verifyQueryChecksum()
		
		
		
		// FIXME: need to make this easier to add to forms.
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.addCSRFToken(java.lang.String)">
		/// </seealso>
		public virtual System.String addCSRFToken(System.String href)
		{
			User user = ESAPI.authenticator().getCurrentUser();
			
			// FIXME: AAA getCurrentUser should never return null
			if (user.Anonymous || user == null)
			{
				return href;
			}
			
			if ((href.IndexOf('?') != - 1) || (href.IndexOf('&') != - 1))
			{
				return href + "&" + user.CSRFToken;
			}
			else
			{
				return href + "?" + user.CSRFToken;
			}
		}
		
		
		/// <summary> Adds a cookie to the HttpServletResponse that uses Secure and HttpOnly
		/// flags. This implementation does not use the addCookie method because
		/// it does not support HttpOnly, so it just creates a cookie header manually.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.safeAddCookie(java.lang.String,">
		/// java.lang.String, java.util.Date, java.lang.String,
		/// java.lang.String, javax.servlet.http.HttpServletResponse)
		/// </seealso>
		public virtual void  safeAddCookie(System.String name, System.String value_Renamed, int maxAge, System.String domain, System.String path)
		{
			// verify name matches
			Pattern cookieName = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("HTTPCookieName");
			if (!cookieName.matcher(name).matches())
			{
				throw new ValidationException("Invalid cookie", "Attempt to set a cookie name (" + name + ") that violates the global rule in ESAPI.properties (" + cookieName.pattern() + ")");
			}
			
			// verify value matches
			Pattern cookieValue = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("HTTPCookieValue");
			if (!cookieValue.matcher(value_Renamed).matches())
			{
				throw new ValidationException("Invalid cookie", "Attempt to set a cookie value (" + value_Renamed + ") that violates the global rule in ESAPI.properties (" + cookieValue.pattern() + ")");
			}
			
			// FIXME: AAA need to validate domain and path! Otherwise response splitting etc..  Can use Cookie object?
			
			// create the special cookie header
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			// Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
			// domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
			// FIXME: AAA test if setting a separate set-cookie header for each cookie works!
			System.String header = name + "=" + value_Renamed;
			if (maxAge != - 1)
				header += ("; Max-Age=" + maxAge);
			if (domain != null)
				header += ("; Domain=" + domain);
			if (path != null)
				header += ("; Path=" + path);
			header += "; Secure; HttpOnly";
			response.AppendHeader("Set-Cookie", header);
		}
		
		/*
		* Adds a header to an HttpServletResponse after checking for special
		* characters (such as CRLF injection) that could enable attacks like
		* response splitting and other header-based attacks that nobody has thought
		* of yet.
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#safeAddHeader(java.lang.String,
		*      java.lang.String, java.lang.String,
		*      javax.servlet.http.HttpServletResponse)
		*/
		public virtual void  safeAddHeader(System.String name, System.String value_Renamed)
		{
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			// FIXME: AAA consider using the regex for header names and header values here
			Pattern headerName = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("HTTPHeaderName");
			if (!headerName.matcher(name).matches())
			{
				throw new ValidationException("Invalid header", "Attempt to set a header name that violates the global rule in ESAPI.properties: " + name);
			}
			Pattern headerValue = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("HTTPHeaderValue");
			if (!headerValue.matcher(value_Renamed).matches())
			{
				throw new ValidationException("Invalid header", "Attempt to set a header value that violates the global rule in ESAPI.properties: " + value_Renamed);
			}
			response.AppendHeader(name, value_Renamed);
		}
		
		//FIXME: AAA add these to the interface
		/// <summary> Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
		/// scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
		/// favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
		/// more dangerous than the evil cookies it was intended to replace.
		/// 
		/// </summary>
		/// <param name="url">
		/// </param>
		/// <returns>
		/// </returns>
		public virtual System.String safeEncodeURL(System.String url)
		{
			return url;
		}
		
		/// <summary> Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
		/// scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
		/// favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
		/// more dangerous than the evil cookies it was intended to replace.
		/// 
		/// </summary>
		/// <param name="url">
		/// </param>
		/// <returns>
		/// </returns>
		public virtual System.String safeEncodeRedirectURL(System.String url)
		{
			return url;
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#changeSessionIdentifier(javax.servlet.http.HttpServletRequest)
		*/
		public virtual System.Web.SessionState.HttpSessionState changeSessionIdentifier()
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			System.Collections.IDictionary temp = new System.Collections.Hashtable();
			System.Web.SessionState.HttpSessionState session = System.Web.HttpContext.Current.Session;
			
			// make a copy of the session content
			System.Collections.IEnumerator e = Session.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Enumeration.hasMoreElements' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationhasMoreElements'"
			while (e != null && e.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Enumeration.nextElement' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationnextElement'"
				System.String name = (System.String) e.Current;
				System.Object value_Renamed = session[name];
				temp[name] = value_Renamed;
			}
			
			// invalidate the old session and create a new one
			//UPGRADE_TODO: Method 'javax.servlet.http.HttpSession.invalidate' was converted to 'System.Web.SessionState.HttpSessionState.Abandon' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservlethttpHttpSessioninvalidate'"
			session.Abandon();
			//UPGRADE_TODO: Method 'javax.servlet.http.HttpServletRequest.getSession' was converted to 'System.Web.HttpContext.Current.Session' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservlethttpHttpServletRequestgetSession_boolean'"
			System.Web.SessionState.HttpSessionState newSession = System.Web.HttpContext.Current.Session;
			
			// copy back the session content
			//UPGRADE_TODO: Method 'java.util.Map.entrySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapentrySet'"
			System.Collections.IEnumerator i = new SupportClass.HashSetSupport(temp).GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.Collections.DictionaryEntry entry = (System.Collections.DictionaryEntry) i.Current;
				newSession.Add((System.String) entry.Key, entry.Value);
			}
			return newSession;
		}
		
		
		
		// FIXME: ENHANCE - add configuration for entry pages that don't require a token 
		/*
		* This implementation uses the parameter name to store the token.
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#verifyCSRFToken()
		*/
		public virtual void  verifyCSRFToken()
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			User user = ESAPI.authenticator().getCurrentUser();
			// FIXME: AAA this is a bad test - need a way to not enforce CSRF token on entry points
			// if this is the first request after logging in, let them pass
			if (user.isFirstRequest())
				return ;
			
			//UPGRADE_TODO: Method 'javax.servlet.ServletRequest.getParameter' was converted to 'System.Web.HttpRequest' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletServletRequestgetParameter_javalangString'"
			if (request[user.CSRFToken] == null)
			{
				throw new IntrusionException("Authentication failed", "Attempt to access application without appropriate token");
			}
		}
		
		/*
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#decryptHiddenField(java.lang.String)
		*/
		public virtual System.String decryptHiddenField(System.String encrypted)
		{
			try
			{
				return ESAPI.encryptor().decrypt(encrypted);
			}
			catch (EncryptionException e)
			{
				throw new IntrusionException("Invalid request", "Tampering detected. Hidden field data did not decrypt properly.", e);
			}
		}
		
		
		/*
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#decryptQuueryString(java.lang.String)
		*/
		public virtual System.Collections.IDictionary decryptQueryString(System.String encrypted)
		{
			// FIXME: AAA needs test cases
			System.String plaintext = ESAPI.encryptor().decrypt(encrypted);
			return queryToMap(plaintext);
		}
		
		/// <throws>  EncryptionException  </throws>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.decryptStateFromCookie()">
		/// </seealso>
		public virtual System.Collections.IDictionary decryptStateFromCookie()
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			System.Web.HttpCookie[] cookies = SupportClass.GetCookies(request);
			System.Web.HttpCookie c = null;
			for (int i = 0; i < cookies.Length; i++)
			{
				if (cookies[i].Name.Equals("state"))
				{
					c = cookies[i];
				}
			}
			System.String encrypted = c.Value;
			System.String plaintext = ESAPI.encryptor().decrypt(encrypted);
			
			return queryToMap(plaintext);
		}
		
		/*
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#encryptHiddenField(java.lang.String)
		*/
		public virtual System.String encryptHiddenField(System.String value_Renamed)
		{
			return ESAPI.encryptor().encrypt(value_Renamed);
		}
		
		/*
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#encryptQueryString(java.lang.String)
		*/
		public virtual System.String encryptQueryString(System.String query)
		{
			return ESAPI.encryptor().encrypt(query);
		}
		
		/// <throws>  EncryptionException  </throws>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.encryptStateInCookie(java.util.Map)">
		/// </seealso>
		public virtual void  encryptStateInCookie(System.Collections.IDictionary cleartext)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			//UPGRADE_TODO: Method 'java.util.Map.entrySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapentrySet'"
			System.Collections.IEnumerator i = new SupportClass.HashSetSupport(cleartext).GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				try
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.Collections.DictionaryEntry entry = (System.Collections.DictionaryEntry) i.Current;
					//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Object.toString' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
					System.String name = ESAPI.encoder().encodeForURL(entry.Key.ToString());
					//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Object.toString' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
					System.String value_Renamed = ESAPI.encoder().encodeForURL(entry.Value.ToString());
					sb.Append(name + "=" + value_Renamed);
					//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
					if (i.MoveNext())
						sb.Append("&");
				}
				catch (EncodingException e)
				{
					logger.logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Problem encrypting state in cookie - skipping entry", e);
				}
			}
			// FIXME: AAA - add a check to see if cookie length will exceed 2K limit
			System.String encrypted = ESAPI.encryptor().encrypt(sb.ToString());
			try
			{
				this.safeAddCookie("state", encrypted, - 1, null, null);
			}
			catch (ValidationException e)
			{
				throw new EncryptionException("Error generating encrypted cookie", e.LogMessage, e);
			}
		}
		
		/// <summary> Uses the Apache Commons FileUploader to parse the multipart HTTP request
		/// and extract any files therein. Note that the progress of any uploads is
		/// put into a session attribute, where it can be retrieved with a simple
		/// JSP.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.safeGetFileUploads(javax.servlet.http.HttpServletRequest,">
		/// java.io.File, java.io.File, int)
		/// </seealso>
		public virtual void  getSafeFileUploads(System.IO.FileInfo tempDir, System.IO.FileInfo finalDir)
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			try
			{
				//UPGRADE_NOTE: Final was removed from the declaration of 'session '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
				System.Web.SessionState.HttpSessionState session = System.Web.HttpContext.Current.Session;
				if (!ServletFileUpload.isMultipartContent(request))
				{
					throw new ValidationUploadException("Upload failed", "Not a multipart request");
				}
				
				// this factory will store ALL files in the temp directory,
				// regardless of size
				DiskFileItemFactory factory = new DiskFileItemFactory(0, tempDir);
				ServletFileUpload upload = new ServletFileUpload(factory);
				upload.setSizeMax(maxBytes);
				
				// Create a progress listener
				ProgressListener progressListener = new AnonymousClassProgressListener(session, this);
				upload.setProgressListener(progressListener);
				
				System.Collections.IList items = upload.parseRequest(request);
				System.Collections.IEnumerator i = items.GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					FileItem item = (FileItem) i.Current;
					if (!item.isFormField() && item.getName() != null && !(item.getName().equals("")))
					{
						System.String[] fparts = item.getName().split("[\\/\\\\]");
						System.String filename = fparts[fparts.Length - 1];
						
						if (!ESAPI.validator().isValidFileName("upload", filename))
						{
							throw new ValidationUploadException("Upload only simple filenames with the following extensions " + SupportClass.CollectionToString(ESAPI.securityConfiguration().AllowedFileExtensions), "Upload failed isValidFileName check");
						}
						
						logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "File upload requested: " + filename);
						System.IO.FileInfo f = new System.IO.FileInfo(finalDir.FullName + "\\" + filename);
						bool tmpBool;
						if (System.IO.File.Exists(f.FullName))
							tmpBool = true;
						else
							tmpBool = System.IO.Directory.Exists(f.FullName);
						if (tmpBool)
						{
							System.String[] parts = filename.split("\\.");
							System.String extension = "";
							if (parts.Length > 1)
							{
								extension = parts[parts.Length - 1];
							}
							System.String filenm = filename.Substring(0, (filename.Length - extension.Length) - (0));
							//UPGRADE_ISSUE: Method 'java.io.File.createTempFile' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaioFilecreateTempFile_javalangString_javalangString_javaioFile'"
							f = File.createTempFile(filenm, "." + extension, finalDir);
						}
						item.write(f);
						// delete temporary file
						item.delete();
						logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "File successfully uploaded: " + f);
						session.Add("progress", System.Convert.ToString(0));
					}
				}
			}
			catch (System.Exception e)
			{
				if (e is ValidationUploadException)
					throw (ValidationException) e;
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				throw new ValidationUploadException("Upload failure", "Problem during upload:" + e.Message, e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#killAllCookies(javax.servlet.http.HttpServletRequest,
		*      javax.servlet.http.HttpServletResponse)
		*/
		public virtual void  killAllCookies()
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			System.Web.HttpCookie[] cookies = SupportClass.GetCookies(request);
			if (cookies != null)
			{
				for (int i = 0; i < cookies.Length; i++)
				{
					System.Web.HttpCookie cookie = cookies[i];
					killCookie(cookie.Name);
				}
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#killCookie(javax.servlet.http.HttpServletRequest,
		*      javax.servlet.http.HttpServletResponse)
		*/
		public virtual void  killCookie(System.String name)
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			System.Web.HttpCookie[] cookies = SupportClass.GetCookies(request);
			if (cookies != null)
			{
				for (int i = 0; i < cookies.Length; i++)
				{
					System.Web.HttpCookie cookie = cookies[i];
					if (cookie.Name.Equals(name))
					{
						System.String path = request.ApplicationPath;
						System.String header = name + "=deleted; Max-Age=0; Path=" + path;
						response.AppendHeader("Set-Cookie", header);
					}
				}
			}
		}
		
		private System.Collections.IDictionary queryToMap(System.String query)
		{
			//UPGRADE_ISSUE: Class hierarchy differences between 'java.util.TreeMap' and 'System.Collections.SortedList' may cause compilation errors. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1186'"
			//UPGRADE_TODO: Constructor 'java.util.TreeMap.TreeMap' was converted to 'System.Collections.SortedList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilTreeMapTreeMap'"
			System.Collections.SortedList map = new System.Collections.SortedList();
			System.String[] parts = query.split("&");
			for (int j = 0; j < parts.Length; j++)
			{
				try
				{
					System.String[] nvpair = parts[j].split("=");
					System.String name = ESAPI.encoder().decodeFromURL(nvpair[0]);
					System.String value_Renamed = ESAPI.encoder().decodeFromURL(nvpair[1]);
					map[name] = value_Renamed;
				}
				catch (EncodingException e)
				{
					// skip and continue
				}
			}
			return map;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#safeSendForward(java.lang.String)
		*/
		public virtual void  safeSendForward(System.String context, System.String location)
		{
			// FIXME: should this be configurable?  What is a good forward policy?
			// I think not allowing forwards to public URLs is good, as it bypasses many access controls
			
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			if (!location.StartsWith("WEB-INF"))
			{
				throw new AccessControlException("Forward failed", "Bad forward location: " + location);
			}
			//UPGRADE_TODO: Interface 'javax.servlet.RequestDispatcher' was converted to 'System.Web.HttpServerUtility' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcher'"
			//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getRequestDispatcher' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetRequestDispatcher_javalangString'"
			System.Web.HttpServerUtility dispatcher = request.getRequestDispatcher(location);
			//UPGRADE_TODO: Method 'javax.servlet.RequestDispatcher.forward' was converted to 'System.Web.HttpServerUtility.Transfer' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcherforward_javaxservletServletRequest_javaxservletServletResponse'"
			//UPGRADE_TODO: Reference conversion may require user modification. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1202'"
			Server.Transfer();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IHTTPUtilities#safeSendRedirect(java.lang.String)
		*/
		public virtual void  safeSendRedirect(System.String context, System.String location)
		{
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			if (!ESAPI.validator().isValidRedirectLocation(context, location))
			{
				throw new ValidationException("Redirect failed", "Bad redirect location: " + location);
			}
			//UPGRADE_TODO: Reference conversion may require user modification. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1202'"
			response.Redirect(SupportClass.GetRealPath(location, "MyVROOT"));
		}
		
		/// <summary> Set the character encoding on every HttpServletResponse in order to limit
		/// the ways in which the input data can be represented. This prevents
		/// malicious users from using encoding and multi-byte escape sequences to
		/// bypass input validation routines. The default is text/html; charset=UTF-8
		/// character encoding, which is the default in early versions of HTML and
		/// HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more
		/// information about character encoding and MIME.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.safeSetContentType(java.lang.String)">
		/// </seealso>
		public virtual void  safeSetContentType()
		{
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			response.ContentType = ((SecurityConfiguration) ESAPI.securityConfiguration()).ResponseContentType;
		}
		
		/// <summary> Set headers to protect sensitive information against being cached in the
		/// browser.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IHTTPUtilities.setNoCacheHeaders(javax.servlet.http.HttpServletResponse)">
		/// </seealso>
		public virtual void  setNoCacheHeaders()
		{
			System.Web.HttpResponse response = ((Authenticator) ESAPI.authenticator()).CurrentResponse;
			
			// HTTP 1.1
			response.AppendHeader("Cache-Control", "no-store");
			response.AppendHeader("Cache-Control", "no-cache");
			response.AppendHeader("Cache-Control", "must-revalidate");
			
			// HTTP 1.0
			response.AppendHeader("Pragma", "no-cache");
			//UPGRADE_TODO: Method 'javax.servlet.http.HttpServletResponse.setDateHeader' was converted to 'System.Web.HttpResponse.AppendHeader' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservlethttpHttpServletResponsesetDateHeader_javalangString_long'"
			response.AppendHeader("Expires", new System.DateTime(- 1).ToString("r"));
		}
		static HTTPUtilities()
		{
			logger = Logger.getLogger("ESAPI", "HTTPUtilities");
		}
	}
}