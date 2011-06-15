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
using Authenticator = org.owasp.esapi.Authenticator;
using ESAPI = org.owasp.esapi.ESAPI;
using Logger = org.owasp.esapi.Logger;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using IHTTPUtilities = org.owasp.esapi.interfaces.IHTTPUtilities;
namespace org.owasp.esapi.filters
{
	
	//UPGRADE_TODO: Verify list of registered servlet filters. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1236'"
	public class ESAPIFilter : SupportClass.ServletFilter
	{
		
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.filters.ESAPIFilter'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		//UPGRADE_NOTE: Final was removed from the declaration of 'ignore'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly System.String[] ignore = new System.String[]{"password"};
		
		/// <summary> Called by the web container to indicate to a filter that it is being
		/// placed into service. The servlet container calls the init method exactly
		/// once after instantiating the filter. The init method must complete
		/// successfully before the filter is asked to do any filtering work.
		/// 
		/// </summary>
		/// <param name="filterConfig">configuration object
		/// </param>
		//UPGRADE_ISSUE: Interface 'javax.servlet.FilterConfig' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletFilterConfig'"
		public virtual void  init()
		{
		}
		
		/// <summary> The doFilter method of the Filter is called by the container each time a
		/// request/response pair is passed through the chain due to a client request
		/// for a resource at the end of the chain. The FilterChain passed in to this
		/// method allows the Filter to pass on the request and response to the next
		/// entity in the chain.
		/// 
		/// </summary>
		/// <param name="request">Request object to be processed
		/// </param>
		/// <param name="response">Response object
		/// </param>
		/// <param name="chain">current FilterChain
		/// </param>
		/// <exception cref="IOException">if any occurs
		/// </exception>
		/// <throws>  ServletException </throws>
		public override void  doFilter(System.Web.HttpRequest req, System.Web.HttpResponse resp, SupportClass.ServletFilterChain chain)
		{
			System.Web.HttpRequest request = (System.Web.HttpRequest) req;
			System.Web.HttpResponse response = (System.Web.HttpResponse) resp;
			
			try
			{
				// figure out who the current user is
				try
				{
					ESAPI.authenticator().login(request, response);
				}
				catch (AuthenticationException e)
				{
					((Authenticator) ESAPI.authenticator()).logout();
					// FIXME: use safeforward!
					// FIXME: make configurable with servletconfig
					SupportClass.SetAttribute(Application, request, "message", "Authentication failed");
					//UPGRADE_TODO: Interface 'javax.servlet.RequestDispatcher' was converted to 'System.Web.HttpServerUtility' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcher'"
					//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getRequestDispatcher' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetRequestDispatcher_javalangString'"
					System.Web.HttpServerUtility dispatcher = request.getRequestDispatcher("WEB-INF/login.jsp");
					//UPGRADE_TODO: Method 'javax.servlet.RequestDispatcher.forward' was converted to 'System.Web.HttpServerUtility.Transfer' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcherforward_javaxservletServletRequest_javaxservletServletResponse'"
					//UPGRADE_TODO: Reference conversion may require user modification. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1202'"
					Server.Transfer("WEB-INF/login.aspx");
					return ;
				}
				
				// log this request, obfuscating any parameter named password
				//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
				logger.logHTTPRequest(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, request, new System.Collections.ArrayList(ignore));
				
				// check access to this URL
				if (!ESAPI.accessController().isAuthorizedForURL(request.Url.AbsolutePath.ToString()))
				{
					SupportClass.SetAttribute(Application, request, "message", "Unauthorized");
					//UPGRADE_TODO: Interface 'javax.servlet.RequestDispatcher' was converted to 'System.Web.HttpServerUtility' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcher'"
					//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getRequestDispatcher' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetRequestDispatcher_javalangString'"
					System.Web.HttpServerUtility dispatcher = request.getRequestDispatcher("WEB-INF/index.jsp");
					//UPGRADE_TODO: Method 'javax.servlet.RequestDispatcher.forward' was converted to 'System.Web.HttpServerUtility.Transfer' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcherforward_javaxservletServletRequest_javaxservletServletResponse'"
					//UPGRADE_TODO: Reference conversion may require user modification. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1202'"
					Server.Transfer("WEB-INF/index.aspx");
					return ;
				}
				
				// verify if this request meets the baseline input requirements
				if (!ESAPI.validator().isValidHTTPRequest(request))
				{
					SupportClass.SetAttribute(Application, request, "message", "Validation error");
					//UPGRADE_TODO: Interface 'javax.servlet.RequestDispatcher' was converted to 'System.Web.HttpServerUtility' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcher'"
					//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getRequestDispatcher' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetRequestDispatcher_javalangString'"
					System.Web.HttpServerUtility dispatcher = request.getRequestDispatcher("WEB-INF/index.jsp");
					//UPGRADE_TODO: Method 'javax.servlet.RequestDispatcher.forward' was converted to 'System.Web.HttpServerUtility.Transfer' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaxservletRequestDispatcherforward_javaxservletServletRequest_javaxservletServletResponse'"
					//UPGRADE_TODO: Reference conversion may require user modification. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1202'"
					Server.Transfer("WEB-INF/index.aspx");
					return ;
				}
				
				// check for CSRF attacks and set appropriate caching headers
				IHTTPUtilities utils = ESAPI.httpUtilities();
				// utils.checkCSRFToken();
				utils.setNoCacheHeaders();
				utils.safeSetContentType();
				
				// forward this request on to the web application
				chain.doFilter(request, response);
			}
			catch (System.Exception e)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				logger.logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Error in security filter: " + e.Message, e);
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				SupportClass.SetAttribute(Application, request, "message", e.Message);
			}
			finally
			{
				// VERY IMPORTANT
				// clear out the ThreadLocal variables in the authenticator
				// some containers could possibly reuse this thread without clearing the User
				ESAPI.authenticator().clearCurrent();
			}
		}
		
		/// <summary> Called by the web container to indicate to a filter that it is being
		/// taken out of service. This method is only called once all threads within
		/// the filter's doFilter method have exited or after a timeout period has
		/// passed. After the web container calls this method, it will not call the
		/// doFilter method again on this instance of the filter.
		/// </summary>
		public virtual void  destroy()
		{
			// finalize
		}
		static ESAPIFilter()
		{
			logger = Logger.getLogger("ESAPIFilter", "ESAPIFilter");
		}
	}
}