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
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IIntrusionDetector interface is intended to track security relevant events and identify attack behavior. The
	/// implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden
	/// your system.
	/// <P>
	/// <img src="doc-files/IntrusionDetector.jpg" height="600">
	/// <P>
	/// <P>
	/// The interface is currently designed to accept exceptions as well as custom events. Implementations can use this
	/// stream of information to detect both normal and abnormal behavior.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IIntrusionDetector
	{
		
		/// <summary> Adds the exception to the IntrusionDetector.
		/// 
		/// </summary>
		/// <param name="exception">the exception
		/// </param>
		/// <throws>  IntrusionException the intrusion exception </throws>
		void  addException(System.Exception exception);
		
		/// <summary> Adds the event to the IntrusionDetector.
		/// 
		/// </summary>
		/// <param name="event">the event
		/// </param>
		/// <throws>  IntrusionException the intrusion exception </throws>
		void  addEvent(System.String eventName);
	}
}