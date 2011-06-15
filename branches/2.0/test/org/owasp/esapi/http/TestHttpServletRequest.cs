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
namespace org.owasp.esapi.http
{
	
	/// <summary> The Class TestHttpServletRequest.
	/// 
	/// </summary>
	/// <author>  jwilliams
	/// </author>
	//UPGRADE_TODO: The class 'HttpRequest' is marked as Sealed. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1147'"
	public class TestHttpServletRequest : System.Web.HttpRequest
	{
		virtual public System.String LocalAddr
		{
			/*
			* (non-Javadoc)
			* 
			* @see javax.servlet.ServletRequest#getLocalAddr()
			*/
			
			get
			{
				
				return null;
			}
			
		}
		virtual public System.String LocalName
		{
			/*
			* (non-Javadoc)
			* 
			* @see javax.servlet.ServletRequest#getLocalName()
			*/
			
			get
			{
				
				return null;
			}
			
		}
		virtual public int LocalPort
		{
			/*
			* (non-Javadoc)
			* 
			* @see javax.servlet.ServletRequest#getLocalPort()
			*/
			
			get
			{
				
				return 0;
			}
			
		}
		virtual public int RemotePort
		{
			/*
			* (non-Javadoc)
			* 
			* @see javax.servlet.ServletRequest#getRemotePort()
			*/
			
			get
			{
				
				return 0;
			}
			
		}
		
		/// <summary>The session. </summary>
		private TestHttpSession session = null;
		
		/// <summary>The cookies. </summary>
		private System.Collections.ArrayList cookies = new System.Collections.ArrayList();
		
		/// <summary>The parameters. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary parameters = new System.Collections.Hashtable();
		
		/// <summary>The headers. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary headers = new System.Collections.Hashtable();
		
		private sbyte[] body;
		
		private System.String uri = null;
		
		public TestHttpServletRequest()
		{
		}
		
		public TestHttpServletRequest(System.String uri, sbyte[] body)
		{
			this.body = body;
			this.uri = uri;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getAuthType()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getAuthType' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getAuthType()
		{
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getContextPath()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getContextPath' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getContextPath()
		{
			
			return null;
		}
		
		/// <summary> Adds the parameter.
		/// 
		/// </summary>
		/// <param name="name">the name
		/// </param>
		/// <param name="value">the value
		/// </param>
		public virtual void  addParameter(System.String name, System.String value_Renamed)
		{
			System.String[] old = (System.String[]) parameters[name];
			if (old == null)
			{
				old = new System.String[0];
			}
			System.String[] updated = new System.String[old.Length + 1];
			for (int i = 0; i < old.Length; i++)
				updated[i] = old[i];
			updated[old.Length] = value_Renamed;
			parameters[name] = updated;
		}
		
		public virtual void  removeParameter(System.String name)
		{
			parameters.Remove(name);
		}
		
		/// <summary> Adds the header.
		/// 
		/// </summary>
		/// <param name="name">the name
		/// </param>
		/// <param name="value">the value
		/// </param>
		public virtual void  addHeader(System.String name, System.String value_Renamed)
		{
			headers[name] = value_Renamed;
		}
		
		/// <summary> Sets the cookies.
		/// 
		/// </summary>
		/// <param name="list">the new cookies
		/// </param>
		public virtual void  setCookies(System.Collections.ArrayList list)
		{
			cookies = list;
		}
		
		public virtual void  setCookie(System.String name, System.String value_Renamed)
		{
			System.Web.HttpCookie c = new System.Web.HttpCookie(name, value_Renamed);
			cookies.Add(c);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getCookies()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getCookies' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.HttpCookie[] getCookies()
		{
			return (System.Web.HttpCookie[]) SupportClass.ICollectionSupport.ToArray(cookies, new System.Web.HttpCookie[0]);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getDateHeader(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getDateHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual long getDateHeader(System.String name)
		{
			
			return 0;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getHeader(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getHeader(System.String name)
		{
			if (name.Equals("Content-type"))
			{
				return "multipart/form-data; boundary=xxx";
			}
			return (System.String) headers[name];
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getHeaderNames()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getHeaderNames' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getHeaderNames()
		{
			//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
			System.Collections.ArrayList v = System.Collections.ArrayList.Synchronized(new System.Collections.ArrayList(new SupportClass.HashSetSupport(headers.Keys)));
			return v.GetEnumerator();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getHeaders(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getHeaders' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getHeaders(System.String name)
		{
			System.Collections.ArrayList v = System.Collections.ArrayList.Synchronized(new System.Collections.ArrayList(10));
			v.Add(getHeader(name));
			return v.GetEnumerator();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getIntHeader(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getIntHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual int getIntHeader(System.String name)
		{
			
			return 0;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getMethod()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getMethod' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getMethod()
		{
			return "POST";
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getPathInfo()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getPathInfo' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getPathInfo()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getPathTranslated()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getPathTranslated' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getPathTranslated()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getQueryString()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getQueryString' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getQueryString()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getRemoteUser()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getRemoteUser' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRemoteUser()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getRequestURI()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getRequestURI' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRequestURI()
		{
			return uri;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getRequestURL()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getRequestURL' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Text.StringBuilder getRequestURL()
		{
			return new System.Text.StringBuilder("https://localhost" + uri);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getRequestedSessionId()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getRequestedSessionId' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRequestedSessionId()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getServletPath()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getServletPath' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getServletPath()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getSession()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getSession' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.SessionState.HttpSessionState getSession()
		{
			if (session != null)
			{
				return getSession(false);
			}
			return getSession(true);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getSession(boolean)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getSession' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.SessionState.HttpSessionState getSession(bool create)
		{
			if (session == null && create)
			{
				session = new TestHttpSession();
			}
			else if (session != null && session.Invalidated)
			{
				session = new TestHttpSession();
			}
			return session;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#getUserPrincipal()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.getUserPrincipal' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Security.Principal.GenericPrincipal getUserPrincipal()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromCookie()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.isRequestedSessionIdFromCookie' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isRequestedSessionIdFromCookie()
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromURL()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.isRequestedSessionIdFromURL' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isRequestedSessionIdFromURL()
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromUrl()
		*/
		public virtual bool isRequestedSessionIdFromUrl()
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdValid()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.isRequestedSessionIdValid' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isRequestedSessionIdValid()
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.http.HttpServletRequest#isUserInRole(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletRequest.isUserInRole' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isUserInRole(System.String role)
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getAttribute(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Object getAttribute(System.String name)
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getAttributeNames()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getAttributeNames' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getAttributeNames()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getCharacterEncoding()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getCharacterEncoding' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getCharacterEncoding()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getContentLength()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getContentLength' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual int getContentLength()
		{
			return body.Length;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getContentType()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getContentType' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getContentType()
		{
			return "multipart/form-data; boundary=xxx";
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getInputStream()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getInputStream' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.IO.Stream getInputStream()
		{
			return new TestServletInputStream(body);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getLocale()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getLocale' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Globalization.CultureInfo getLocale()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getLocales()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getLocales' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getLocales()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getParameter(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getParameter' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getParameter(System.String name)
		{
			System.String[] values = (System.String[]) parameters[name];
			return values[0];
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getParameterMap()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getParameterMap' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IDictionary getParameterMap()
		{
			return parameters;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getParameterNames()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getParameterNames' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getParameterNames()
		{
			//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
			System.Collections.ArrayList v = System.Collections.ArrayList.Synchronized(new System.Collections.ArrayList(new SupportClass.HashSetSupport(parameters.Keys)));
			return v.GetEnumerator();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getParameterValues(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getParameterValues' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String[] getParameterValues(System.String name)
		{
			return (System.String[]) parameters[name];
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getProtocol()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getProtocol' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getProtocol()
		{
			return "HTTP/1.1";
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getReader()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getReader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.IO.StreamReader getReader()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getRealPath(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getRealPath' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRealPath(System.String path)
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getRemoteAddr()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getRemoteAddr' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRemoteAddr()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getRemoteHost()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getRemoteHost' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getRemoteHost()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getRequestDispatcher(java.lang.String)
		*/
		//UPGRADE_TODO: Interface 'javax.servlet.RequestDispatcher' was converted to 'System.Web.HttpServerUtility' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcher'"
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getRequestDispatcher' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.HttpServerUtility getRequestDispatcher(System.String path)
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getScheme()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getScheme' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getScheme()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getServerName()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getServerName' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getServerName()
		{
			
			return null;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#getServerPort()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.getServerPort' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual int getServerPort()
		{
			
			return 0;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#isSecure()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.isSecure' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isSecure()
		{
			
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#removeAttribute(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.removeAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  removeAttribute(System.String name)
		{
			
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#setAttribute(java.lang.String, java.lang.Object)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.setAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setAttribute(System.String name, System.Object o)
		{
			
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see javax.servlet.ServletRequest#setCharacterEncoding(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletRequest.setCharacterEncoding' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setCharacterEncoding(System.String env)
		{
			
		}
	}
}