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
using ExecutorException = org.owasp.esapi.errors.ExecutorException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The Executor interface is used to run an OS command with less security risk.
	/// Implementations should do as much as possible to minimize the risk of
	/// injection into either the command or parameters. In addition, implementations
	/// should timeout after a specified time period in order to help prevent denial
	/// of service attacks. The class should perform logging and error handling as
	/// well. Finally, implementation should handle errors and generate an
	/// ExecutorException with all the necessary information.
	/// <P>
	/// <img src="doc-files/Executor.jpg" height="600">
	/// <P>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IExecutor
	{
		
		/// <summary> Executes a system command after checking that the executable exists and
		/// that the parameters have not been subject to injection with untrusted
		/// user data. Implementations shall change to the specified working
		/// directory before invoking the command. Also, processes should be
		/// interrupted after the specified timeout period has elapsed.
		/// 
		/// </summary>
		/// <param name="command">the command
		/// </param>
		/// <param name="params">the params
		/// </param>
		/// <param name="workdir">the workdir
		/// </param>
		/// <param name="timeoutSeconds">the timeout seconds
		/// 
		/// </param>
		/// <returns> the string
		/// 
		/// </returns>
		/// <throws>  ExecutorException </throws>
		/// <summary>             the service exception
		/// </summary>
		System.String executeSystemCommand(System.IO.FileInfo executable, System.Collections.IList params_Renamed, System.IO.FileInfo workdir, int timeoutSeconds);
	}
}