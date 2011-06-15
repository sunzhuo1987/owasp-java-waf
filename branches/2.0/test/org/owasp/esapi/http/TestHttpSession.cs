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
	
	/// <summary> The Class TestHttpSession.
	/// 
	/// </summary>
	/// <author>  jwilliams
	/// </author>
	//UPGRADE_TODO: The class 'HttpSessionState' is marked as Sealed. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1147'"
	public class TestHttpSession : System.Web.SessionState.HttpSessionState
	{
		/// <summary> Gets the invalidated.
		/// 
		/// </summary>
		/// <returns> the invalidated
		/// </returns>
		virtual public bool Invalidated
		{
			get
			{
				return invalidated;
			}
			
		}
		
		/// <summary>The invalidated. </summary>
		internal bool invalidated = false;
		
		/// <summary>The creation time. </summary>
		private long creationTime = 0;
		
		/// <summary>The accessed time. </summary>
		private long accessedTime = 0;
		
		/// <summary>The count. </summary>
		private static int count = 1;
		
		/// <summary>The sessionid. </summary>
		private int sessionid = count++;
		
		/// <summary>The attributes. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary attributes = new System.Collections.Hashtable();
		
		/// <summary> Instantiates a new test http session.</summary>
		public TestHttpSession()
		{
			// to replace synthetic accessor method
		}
		
		/// <summary> Instantiates a new test http session.
		/// 
		/// </summary>
		/// <param name="creationTime">the creation time
		/// </param>
		/// <param name="accessedTime">the accessed time
		/// </param>
		public TestHttpSession(long creationTime, long accessedTime)
		{
			this.creationTime = creationTime;
			this.accessedTime = accessedTime;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getAttribute(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Object getAttribute(System.String string_Renamed)
		{
			return attributes[string_Renamed];
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getAttributeNames()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getAttributeNames' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Collections.IEnumerator getAttributeNames()
		{
			//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
			System.Collections.ArrayList v = System.Collections.ArrayList.Synchronized(new System.Collections.ArrayList(new SupportClass.HashSetSupport(attributes.Keys)));
			return v.GetEnumerator();
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getCreationTime()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getCreationTime' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual long getCreationTime()
		{
			return creationTime;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getId()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getId' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String getId()
		{
			return "" + sessionid;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getLastAccessedTime()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getLastAccessedTime' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual long getLastAccessedTime()
		{
			return accessedTime;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getMaxInactiveInterval()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getMaxInactiveInterval' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual int getMaxInactiveInterval()
		{
			return 0;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getServletContext()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getServletContext' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Web.HttpApplicationState getServletContext()
		{
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getSessionContext()
		*/
		//UPGRADE_ISSUE: Interface 'javax.servlet.http.HttpSessionContext' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservlethttpHttpSessionContext'"
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getSessionContext' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual HttpSessionContext getSessionContext()
		{
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getValue(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.Object getValue(System.String string_Renamed)
		{
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#getValueNames()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.getValueNames' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual System.String[] getValueNames()
		{
			return null;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#invalidate()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.invalidate' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  invalidate()
		{
			invalidated = true;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#isNew()
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.isNew' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual bool isNew()
		{
			return true;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#putValue(java.lang.String, java.lang.Object)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.putValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  putValue(System.String string_Renamed, System.Object object_Renamed)
		{
			// stub
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#removeAttribute(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.removeAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  removeAttribute(System.String string_Renamed)
		{
			// stub
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#removeValue(java.lang.String)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.removeValue' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  removeValue(System.String string_Renamed)
		{
			// stub
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#setAttribute(java.lang.String, java.lang.Object)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.setAttribute' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setAttribute(System.String string_Renamed, System.Object object_Renamed)
		{
			attributes[string_Renamed] = object_Renamed;
		}
		
		/* (non-Javadoc)
		* @see javax.servlet.http.HttpSession#setMaxInactiveInterval(int)
		*/
		//UPGRADE_NOTE: The equivalent of method 'javax.servlet.http.HttpSession.setMaxInactiveInterval' is not an override method. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1143'"
		public virtual void  setMaxInactiveInterval(int i)
		{
			// stub
		}
	}
}