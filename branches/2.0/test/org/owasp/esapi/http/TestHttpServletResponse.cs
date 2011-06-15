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
	
	/// <summary> The Class TestHttpServletResponse.
	/// 
	/// </summary>
	/// <author>  jwilliams
	/// </author>
	//UPGRADE_TODO: The class 'HttpResponse' is marked as Sealed. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1147'"
	public class TestHttpServletResponse : System.Web.HttpResponse
	{
		/// <summary> Gets the header names.
		/// 
		/// </summary>
		/// <returns> the header names
		/// </returns>
		virtual public System.Collections.IList HeaderNames
		{
			get
			{
				return headerNames;
			}
			
		}
		
		/// <summary>The cookies. </summary>
		internal System.Collections.IList cookies = new System.Collections.ArrayList();
		
		/// <summary>The header names. </summary>
		internal System.Collections.IList headerNames = new System.Collections.ArrayList();
		
		/// <summary>The header values. </summary>
		internal System.Collections.IList headerValues = new System.Collections.ArrayList();
		
		/// <summary>The status. </summary>
		internal int status = 200;
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#addCookie(javax.servlet.http.Cookie)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.addCookie' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  addCookie(System.Web.HttpCookie cookie)
		{
			cookies.Add(cookie);
		}
		
		/// <summary> Gets the cookies.
		/// 
		/// </summary>
		/// <returns> the cookies
		/// </returns>
		public virtual System.Collections.IList getCookies()
		{
			return cookies;
		}
		
		public virtual System.Web.HttpCookie getCookie(System.String name)
		{
			System.Collections.IEnumerator i = cookies.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.Web.HttpCookie c = (System.Web.HttpCookie) i.Current;
				if (c.Name.Equals(name))
				{
					return c;
				}
			}
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#addDateHeader(java.lang.String, long)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.addDateHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  addDateHeader(System.String name, long date)
		{
			headerNames.Add(name);
			headerValues.Add("" + date);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#addHeader(java.lang.String, java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.addHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  addHeader(System.String name, System.String value_Renamed)
		{
			headerNames.Add(name);
			headerValues.Add(value_Renamed);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#addIntHeader(java.lang.String, int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.addIntHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  addIntHeader(System.String name, int value_Renamed)
		{
			headerNames.Add(name);
			headerValues.Add("" + value_Renamed);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#containsHeader(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.containsHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool containsHeader(System.String name)
		{
			return headerNames.Contains(name);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#containsHeader(java.lang.String)
		*/
		/// <summary> Gets the header.
		/// 
		/// </summary>
		/// <param name="name">the name
		/// 
		/// </param>
		/// <returns> the header
		/// </returns>
		public virtual System.String getHeader(System.String name)
		{
			int index = headerNames.IndexOf(name);
			return (System.String) headerValues[index];
		}
		
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#encodeRedirectURL(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.encodeRedirectURL' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String encodeRedirectURL(System.String url)
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#encodeRedirectUrl(java.lang.String)
		*/
		public virtual System.String encodeRedirectUrl(System.String url)
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#encodeURL(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.encodeURL' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String encodeURL(System.String url)
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#encodeUrl(java.lang.String)
		*/
		public virtual System.String encodeUrl(System.String url)
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#sendError(int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.sendError' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  sendError(int sc)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#sendError(int, java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.sendError' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  sendError(int sc, System.String msg)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#sendRedirect(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.sendRedirect' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  sendRedirect(System.String location)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#setDateHeader(java.lang.String, long)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.setDateHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setDateHeader(System.String name, long date)
		{
			headerNames.Add(name);
			headerValues.Add("" + date);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#setHeader(java.lang.String, java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.setHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setHeader(System.String name, System.String value_Renamed)
		{
			headerNames.Add(name);
			headerValues.Add(value_Renamed);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#setIntHeader(java.lang.String, int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.setIntHeader' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setIntHeader(System.String name, int value_Renamed)
		{
			headerNames.Add(name);
			headerValues.Add("" + value_Renamed);
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#setStatus(int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.setStatus' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setStatus(int sc)
		{
			status = sc;
		}
		
		/// <summary> Gets the status.
		/// 
		/// </summary>
		/// <returns> the status
		/// </returns>
		public virtual int getStatus()
		{
			return status;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpServletResponse#setStatus(int, java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpServletResponse.setStatus' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setStatus(int sc, System.String sm)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#flushBuffer()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.flushBuffer' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  flushBuffer()
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getBufferSize()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.getBufferSize' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual int getBufferSize()
		{
			
			return 0;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getCharacterEncoding()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.getCharacterEncoding' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getCharacterEncoding()
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getContentType()
		*/
		public virtual System.String getContentType()
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getLocale()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.getLocale' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Globalization.CultureInfo getLocale()
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getOutputStream()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.getOutputStream' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.HttpResponse getOutputStream()
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#getWriter()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.getWriter' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.IO.StreamWriter getWriter()
		{
			
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#isCommitted()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.isCommitted' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isCommitted()
		{
			
			return false;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#reset()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.reset' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  reset()
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#resetBuffer()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.resetBuffer' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  resetBuffer()
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#setBufferSize(int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.setBufferSize' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setBufferSize(int size)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#setCharacterEncoding(java.lang.String)
		*/
		public virtual void  setCharacterEncoding(System.String charset)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#setContentLength(int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.setContentLength' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setContentLength(int len)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#setContentType(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.setContentType' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setContentType(System.String type)
		{
			
			
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.ServletResponse#setLocale(java.util.Locale)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.ServletResponse.setLocale' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setLocale(System.Globalization.CultureInfo loc)
		{
			
			
		}
	}
}