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
using EnterpriseSecurityException = org.owasp.esapi.errors.EnterpriseSecurityException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
using TestHttpServletRequest = org.owasp.esapi.http.TestHttpServletRequest;
using TestHttpServletResponse = org.owasp.esapi.http.TestHttpServletResponse;
using TestHttpSession = org.owasp.esapi.http.TestHttpSession;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
using IHTTPUtilities = org.owasp.esapi.interfaces.IHTTPUtilities;
namespace org.owasp.esapi
{
	
	/// <summary> The Class HTTPUtilitiesTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class HTTPUtilitiesTest:TestCase
	{
		
		/// <summary> Suite.
		/// 
		/// </summary>
		/// <returns> the test
		/// </returns>
		public static Test suite()
		{
			TestSuite suite = new TestSuite(typeof(HTTPUtilitiesTest));
			return suite;
		}
		
		/// <summary> Instantiates a new HTTP utilities test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public HTTPUtilitiesTest(System.String testName):base(testName)
		{
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see junit.framework.TestCase#setUp()
		*/
		protected internal virtual void  setUp()
		{
			// none
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see junit.framework.TestCase#tearDown()
		*/
		protected internal virtual void  tearDown()
		{
			// none
		}
		
		/// <summary> Test of addCSRFToken method, of class org.owasp.esapi.HTTPUtilities.</summary>
		/// <throws>  AuthenticationException  </throws>
		public virtual void  testAddCSRFToken()
		{
			IAuthenticator instance = ESAPI.authenticator();
			System.String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
			User user = instance.createUser(username, "addCSRFToken", "addCSRFToken");
			instance.setCurrentUser(user);
			
			System.Console.Out.WriteLine("addCSRFToken");
			System.String csrf1 = ESAPI.httpUtilities().addCSRFToken("/test1");
			System.Console.Out.WriteLine("CSRF1:" + csrf1);
			assertTrue(csrf1.IndexOf("?") > - 1);
			
			System.String csrf2 = ESAPI.httpUtilities().addCSRFToken("/test1?one=two");
			System.Console.Out.WriteLine("CSRF1:" + csrf1);
			assertTrue(csrf2.IndexOf("&") > - 1);
		}
		
		/// <summary> Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
		/// 
		/// </summary>
		/// <throws>  ValidationException the validation exception </throws>
		/// <throws>  IOException Signals that an I/O exception has occurred. </throws>
		/// <throws>  AuthenticationException the authentication exception </throws>
		public virtual void  testChangeSessionIdentifier()
		{
			System.Console.Out.WriteLine("changeSessionIdentifier");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			TestHttpSession session = (TestHttpSession) request.getSession();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			session.setAttribute("one", "one");
			session.setAttribute("two", "two");
			session.setAttribute("three", "three");
			System.String id1 = session.getId();
			session = (TestHttpSession) ESAPI.httpUtilities().changeSessionIdentifier();
			System.String id2 = session.getId();
			assertTrue(!id1.Equals(id2));
			assertEquals("one", (System.String) session.getAttribute("one"));
		}
		
		/// <summary> Test of formatHttpRequestForLog method, of class org.owasp.esapi.HTTPUtilities.</summary>
		/// <throws>  IOException  </throws>
		public virtual void  testGetFileUploads()
		{
			System.Console.Out.WriteLine("getFileUploads");
			System.IO.FileInfo home = ((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory;
			sbyte[] bytes = getBytesFromFile(new System.IO.FileInfo(home.FullName + "\\" + "multipart.txt"));
			System.Console.Out.WriteLine("===========\n" + new System.String(SupportClass.ToCharArray(SupportClass.ToByteArray(bytes))) + "\n===========");
			TestHttpServletRequest request = new TestHttpServletRequest("/test", bytes);
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			try
			{
				ESAPI.httpUtilities().getSafeFileUploads(home, home);
			}
			catch (ValidationException e)
			{
				fail();
			}
		}
		
		private sbyte[] getBytesFromFile(System.IO.FileInfo file)
		{
			//UPGRADE_TODO: Constructor 'java.io.FileInputStream.FileInputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileInputStreamFileInputStream_javaioFile'"
			System.IO.Stream is_Renamed = new System.IO.FileStream(file.FullName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
			long length = SupportClass.FileLength(file);
			sbyte[] bytes = new sbyte[(int) length];
			
			int offset = 0;
			int numRead = 0;
			while (offset < bytes.Length && (numRead = SupportClass.ReadInput(is_Renamed, bytes, offset, bytes.Length - offset)) >= 0)
			{
				offset += numRead;
			}
			
			if (offset < bytes.Length)
			{
				throw new System.IO.IOException("Could not completely read file " + file.Name);
			}
			is_Renamed.Close();
			return bytes;
		}
		
		/// <summary> Test of isValidHTTPRequest method, of class org.owasp.esapi.HTTPUtilities.</summary>
		public virtual void  testIsValidHTTPRequest()
		{
			System.Console.Out.WriteLine("isValidHTTPRequest");
			TestHttpServletRequest request = new TestHttpServletRequest();
			request.addParameter("p1", "v1");
			request.addParameter("p2", "v3");
			request.addParameter("p3", "v2");
			request.addHeader("h1", "v1");
			request.addHeader("h2", "v1");
			request.addHeader("h3", "v1");
			System.Collections.ArrayList list = new System.Collections.ArrayList();
			list.Add(new System.Web.HttpCookie("c1", "v1"));
			list.Add(new System.Web.HttpCookie("c2", "v2"));
			list.Add(new System.Web.HttpCookie("c3", "v3"));
			request.setCookies(list);
			assertTrue(ESAPI.validator().isValidHTTPRequest(request));
			request.addParameter("bad_name", "bad*value");
			request.addHeader("bad_name", "bad*value");
			list.Add(new System.Web.HttpCookie("bad_name", "bad*value"));
			assertFalse(ESAPI.validator().isValidHTTPRequest(request));
		}
		
		
		/// <summary> Test of killAllCookies method, of class org.owasp.esapi.HTTPUtilities.</summary>
		public virtual void  testKillAllCookies()
		{
			System.Console.Out.WriteLine("killAllCookies");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			assertTrue((response.getCookies().Count == 0));
			System.Collections.ArrayList list = new System.Collections.ArrayList();
			list.Add(new System.Web.HttpCookie("test1", "1"));
			list.Add(new System.Web.HttpCookie("test2", "2"));
			list.Add(new System.Web.HttpCookie("test3", "3"));
			request.setCookies(list);
			ESAPI.httpUtilities().killAllCookies();
			// this tests getHeaders because we're using addHeader in our setCookie method
			assertTrue(response.HeaderNames.Count == 3);
		}
		
		/// <summary> Test of killCookie method, of class org.owasp.esapi.HTTPUtilities.</summary>
		public virtual void  testKillCookie()
		{
			System.Console.Out.WriteLine("killCookie");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			assertTrue((response.getCookies().Count == 0));
			System.Collections.ArrayList list = new System.Collections.ArrayList();
			list.Add(new System.Web.HttpCookie("test1", "1"));
			list.Add(new System.Web.HttpCookie("test2", "2"));
			list.Add(new System.Web.HttpCookie("test3", "3"));
			request.setCookies(list);
			ESAPI.httpUtilities().killCookie("test1");
			// this tests getHeaders because we're using addHeader in our setCookie method
			assertTrue(response.HeaderNames.Count == 1);
		}
		
		/// <summary> Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
		/// 
		/// </summary>
		/// <throws>  ValidationException the validation exception </throws>
		/// <throws>  IOException Signals that an I/O exception has occurred. </throws>
		public virtual void  testSendSafeRedirect()
		{
			System.Console.Out.WriteLine("sendSafeRedirect");
			try
			{
				ESAPI.httpUtilities().safeSendRedirect("test", "/test1/abcdefg");
				ESAPI.httpUtilities().safeSendRedirect("test", "/test2/1234567");
			}
			catch (ValidationException e)
			{
				fail();
			}
			try
			{
				ESAPI.httpUtilities().safeSendRedirect("test", "http://www.aspectsecurity.com");
				fail();
			}
			catch (ValidationException e)
			{
				// expected
			}
			try
			{
				ESAPI.httpUtilities().safeSendRedirect("test", "/ridiculous");
				fail();
			}
			catch (ValidationException e)
			{
				// expected
			}
		}
		
		/// <summary> Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.</summary>
		public virtual void  testSetCookie()
		{
			System.Console.Out.WriteLine("setCookie");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			assertTrue((response.getCookies().Count == 0));
			try
			{
				ESAPI.httpUtilities().safeAddCookie("test1", "test1", 10000, "test", "/");
			}
			catch (ValidationException e)
			{
				fail();
			}
			try
			{
				ESAPI.httpUtilities().safeAddCookie("test2", "test2", 10000, "test", "/");
			}
			catch (ValidationException e)
			{
				fail();
			}
			try
			{
				ESAPI.httpUtilities().safeAddCookie("tes\nt3", "test3", 10000, "test", "/");
				fail();
			}
			catch (ValidationException e)
			{
				// expected
			}
			try
			{
				ESAPI.httpUtilities().safeAddCookie("test3", "te\nst3", 10000, "test", "/");
				fail();
			}
			catch (ValidationException e)
			{
				// expected
			}
			assertTrue(response.HeaderNames.Count == 2);
		}
		
		public virtual void  testGetStateFromEncryptedCookie()
		{
			System.Console.Out.WriteLine("getStateFromEncryptedCookie");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			System.Collections.Hashtable map = new System.Collections.Hashtable();
			map["one"] = "aspect";
			map["two"] = "ridiculous";
			map["test_hard"] = "&(@#*!^|;,.";
			try
			{
				ESAPI.httpUtilities().encryptStateInCookie(map);
				System.String value_Renamed = response.getHeader("Set-Cookie");
				System.String encrypted = value_Renamed.Substring(value_Renamed.IndexOf("=") + 1, (value_Renamed.IndexOf(";")) - (value_Renamed.IndexOf("=") + 1));
				// String encrypted = response.getCookie("state").getValue();
				request.setCookie("state", encrypted);
				System.Collections.IDictionary state = ESAPI.httpUtilities().decryptStateFromCookie();
				//UPGRADE_TODO: Method 'java.util.HashMap.entrySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapentrySet'"
				System.Collections.IEnumerator i = new SupportClass.HashSetSupport(map).GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.Collections.DictionaryEntry entry = (System.Collections.DictionaryEntry) i.Current;
					System.String origname = (System.String) entry.Key;
					System.String origvalue = (System.String) entry.Value;
					if (!state[origname].Equals(origvalue))
					{
						fail();
					}
				}
			}
			catch (EncryptionException e)
			{
				fail();
			}
		}
		
		public virtual void  testSaveStateInEncryptedCookie()
		{
			System.Console.Out.WriteLine("saveStateInEncryptedCookie");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator instance = (Authenticator) ESAPI.authenticator();
			instance.setCurrentHTTP(request, response);
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			System.Collections.Hashtable map = new System.Collections.Hashtable();
			map["one"] = "aspect";
			map["two"] = "ridiculous";
			map["test_hard"] = "&(@#*!^|;,.";
			try
			{
				ESAPI.httpUtilities().encryptStateInCookie(map);
				System.String value_Renamed = response.getHeader("Set-Cookie");
				System.String encrypted = value_Renamed.Substring(value_Renamed.IndexOf("=") + 1, (value_Renamed.IndexOf(";")) - (value_Renamed.IndexOf("=") + 1));
				ESAPI.encryptor().decrypt(encrypted);
			}
			catch (EncryptionException e)
			{
				fail();
			}
		}
		
		/// <summary> Test set no cache headers.</summary>
		public virtual void  testSetNoCacheHeaders()
		{
			System.Console.Out.WriteLine("setNoCacheHeaders");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			Authenticator auth = (Authenticator) ESAPI.authenticator();
			auth.setCurrentHTTP(request, response);
			assertTrue((response.HeaderNames.Count == 0));
			response.addHeader("test1", "1");
			response.addHeader("test2", "2");
			response.addHeader("test3", "3");
			assertFalse((response.HeaderNames.Count == 0));
			IHTTPUtilities instance = ESAPI.httpUtilities();
			instance.setNoCacheHeaders();
			assertTrue(response.containsHeader("Cache-Control"));
			assertTrue(response.containsHeader("Expires"));
		}
	}
}