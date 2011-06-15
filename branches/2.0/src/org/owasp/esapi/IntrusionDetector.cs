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
using EnterpriseSecurityException = org.owasp.esapi.errors.EnterpriseSecurityException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IIntrusionDetector interface. This
	/// implementation monitors EnterpriseSecurityExceptions to see if any user
	/// exceeds a configurable threshold in a configurable time period. For example,
	/// it can monitor to see if a user exceeds 10 input validation issues in a 1
	/// minute period. Or if there are more than 3 authentication problems in a 10
	/// second period. More complex implementations are certainly possible, such as
	/// one that establishes a baseline of expected behavior, and then detects
	/// deviations from that baseline.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IIntrusionDetector">
	/// </seealso>
	public class IntrusionDetector : org.owasp.esapi.interfaces.IIntrusionDetector
	{
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.IntrusionDetector'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		public IntrusionDetector()
		{
		}
		
		// FIXME: ENHANCE consider allowing both per-user and per-application quotas
		// e.g. number of failed logins per hour is a per-application quota
		
		
		/// <summary> This implementation uses an exception store in each User object to track
		/// exceptions.
		/// 
		/// </summary>
		/// <param name="e">the e
		/// 
		/// </param>
		/// <throws>  IntrusionException </throws>
		/// <summary>             the intrusion exception
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IIntrusionDetector.addException(org.owasp.esapi.errors.EnterpriseSecurityException)">
		/// </seealso>
		public virtual void  addException(System.Exception e)
		{
			if (e is EnterpriseSecurityException)
			{
				logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, ((EnterpriseSecurityException) e).LogMessage, e);
			}
			else
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, e.Message, e);
			}
			
			// add the exception to the current user, which may trigger a detector 
			User user = ESAPI.authenticator().getCurrentUser();
			//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Class.getName' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
			System.String eventName = e.GetType().FullName;
			
			// FIXME: AAA Rethink this - IntrusionExceptions which shouldn't get added to the IntrusionDetector
			if (e is IntrusionException)
			{
				return ;
			}
			
			// add the exception to the user's store, handle IntrusionException if thrown
			try
			{
				user.addSecurityEvent(eventName);
			}
			catch (IntrusionException ex)
			{
				Threshold quota = ESAPI.securityConfiguration().getQuota(eventName);
				System.Collections.IEnumerator i = quota.actions.GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String action = (System.String) i.Current;
					System.String message = "User exceeded quota of " + quota.count + " per " + quota.interval + " seconds for event " + eventName + ". Taking actions " + SupportClass.CollectionToString(quota.actions);
					takeSecurityAction(action, message);
				}
			}
		}
		
		/// <summary> Adds the event to the IntrusionDetector.
		/// 
		/// </summary>
		/// <param name="event">the event
		/// </param>
		/// <throws>  IntrusionException the intrusion exception </throws>
		public virtual void  addEvent(System.String eventName)
		{
			logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Security event " + eventName + " received");
			
			// add the event to the current user, which may trigger a detector 
			User user = ESAPI.authenticator().getCurrentUser();
			try
			{
				user.addSecurityEvent("event." + eventName);
			}
			catch (IntrusionException ex)
			{
				Threshold quota = ESAPI.securityConfiguration().getQuota("event." + eventName);
				System.Collections.IEnumerator i = quota.actions.GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String action = (System.String) i.Current;
					System.String message = "User exceeded quota of " + quota.count + " per " + quota.interval + " seconds for event " + eventName + ". Taking actions " + SupportClass.CollectionToString(quota.actions);
					takeSecurityAction(action, message);
				}
			}
		}
		
		
		/*
		* FIXME: Enhance - future actions might include SNMP traps, email, pager, etc...
		*/
		private void  takeSecurityAction(System.String action, System.String message)
		{
			if (action.Equals("log"))
			{
				logger.logCritical(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "INTRUSION - " + message);
			}
			if (action.Equals("disable"))
			{
				ESAPI.authenticator().getCurrentUser().disable();
			}
			if (action.Equals("logout"))
			{
				((Authenticator) ESAPI.authenticator()).logout();
			}
		}
		static IntrusionDetector()
		{
			logger = Logger.getLogger("ESAPI", "IntrusionDetector");
		}
	}
}