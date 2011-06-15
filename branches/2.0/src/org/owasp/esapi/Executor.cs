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
using IValidator = org.owasp.esapi.interfaces.IValidator;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the Executor interface. This implementation is very restrictive. Commands must exactly
	/// equal the canonical path to an executable on the system. Valid characters for parameters are alphanumeric,
	/// forward-slash, and dash.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IExecutor">
	/// </seealso>
	public class Executor : org.owasp.esapi.interfaces.IExecutor
	{
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Executor'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		public Executor()
		{
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IExecutor#executeSystemCommand(java.lang.String, java.util.List, java.io.File,
		* int)
		*/
		public virtual System.String executeSystemCommand(System.IO.FileInfo executable, System.Collections.IList params_Renamed, System.IO.FileInfo workdir, int timeoutSeconds)
		{
			System.IO.StreamReader br = null;
			try
			{
				logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Initiating executable: " + executable + " " + SupportClass.CollectionToString(params_Renamed) + " in " + workdir);
				IValidator validator = ESAPI.validator();
				
				// command must exactly match the canonical path and must actually exist on the file system
				if (!executable.FullName.Equals(executable.FullName))
				{
					throw new ExecutorException("Execution failure", "Invalid path to executable file: " + executable);
				}
				bool tmpBool;
				if (System.IO.File.Exists(executable.FullName))
					tmpBool = true;
				else
					tmpBool = System.IO.Directory.Exists(executable.FullName);
				if (!tmpBool)
				{
					throw new ExecutorException("Execution failure", "No such executable: " + executable);
				}
				
				// parameters must only contain alphanumerics, dash, and forward slash
				// FIXME: ENHANCE make configurable regexes? Update comments!
				System.Collections.IEnumerator i = params_Renamed.GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String param = (System.String) i.Current;
					if (!validator.isValidDataFromBrowser("fixme", "SystemCommand", param))
					{
						throw new ExecutorException("Execution failure", "Illegal characters in parameter to executable: " + param);
					}
				}
				
				// working directory must exist
				bool tmpBool2;
				if (System.IO.File.Exists(workdir.FullName))
					tmpBool2 = true;
				else
					tmpBool2 = System.IO.Directory.Exists(workdir.FullName);
				if (!tmpBool2)
				{
					throw new ExecutorException("Execution failure", "No such working directory for running executable: " + workdir.FullName);
				}
				
				params_Renamed.Insert(0, executable.FullName);
				System.String[] command = (System.String[]) SupportClass.ICollectionSupport.ToArray(params_Renamed, new System.String[0]);
				//UPGRADE_ISSUE: Method 'java.lang.Runtime.exec' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangRuntimeexec_javalangString[]_javalangString[]_javaioFile'"
				System.Diagnostics.Process process = System.Diagnostics.Process.GetCurrentProcess().exec(command, new System.String[0], workdir);
				
				// FIXME: Future - this is how to implement this in Java 1.5+
				// ProcessBuilder pb = new ProcessBuilder(params);
				// Map env = pb.environment();
				// Security check - clear environment variables!
				// env.clear();
				// pb.directory(workdir);
				// pb.redirectErrorStream(true);
				// FIXME: ENHANCE need a timer
				// Process process = pb.start();
				System.IO.Stream is_Renamed = process.StandardInput.BaseStream;
				System.IO.StreamReader isr = new System.IO.StreamReader(is_Renamed, System.Text.Encoding.Default);
				//UPGRADE_TODO: The differences in the expected value  of parameters for constructor 'java.io.BufferedReader.BufferedReader'  may cause compilation errors.  "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1092'"
				br = new System.IO.StreamReader(isr.BaseStream, isr.CurrentEncoding);
				System.Text.StringBuilder sb = new System.Text.StringBuilder();
				System.String line;
				while ((line = br.ReadLine()) != null)
				{
					sb.Append(line + "\n");
				}
				logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "System command successful: " + SupportClass.CollectionToString(params_Renamed));
				return sb.ToString();
			}
			catch (System.Exception e)
			{
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Throwable.getMessage' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				throw new ExecutorException("Execution failure", "Exception thrown during execution of system command: " + e.Message, e);
			}
			finally
			{
				try
				{
					if (br != null)
					{
						br.Close();
					}
				}
				catch (System.IO.IOException e)
				{
					// give up
				}
			}
		}
		static Executor()
		{
			logger = Logger.getLogger("ESAPI", "Executor");
		}
	}
}