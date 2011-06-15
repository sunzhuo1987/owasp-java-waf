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
using IExecutor = org.owasp.esapi.interfaces.IExecutor;
namespace org.owasp.esapi
{
	
	/// <summary> The Class ExecutorTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class ExecutorTest:TestCase
	{
		
		/// <summary> Instantiates a new executor test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public ExecutorTest(System.String testName):base(testName)
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
		
		/// <summary> Suite.
		/// 
		/// </summary>
		/// <returns> the test
		/// </returns>
		public static Test suite()
		{
			TestSuite suite = new TestSuite(typeof(ExecutorTest));
			return suite;
		}
		
		/// <summary> Test of executeOSCommand method, of class org.owasp.esapi.Executor
		/// 
		/// </summary>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		public virtual void  testExecuteSystemCommand()
		{
			System.Console.Out.WriteLine("executeSystemCommand");
			IExecutor instance = ESAPI.executor();
			System.IO.FileInfo executable = new System.IO.FileInfo("C:\\Windows\\System32\\cmd.exe");
			System.IO.FileInfo working = new System.IO.FileInfo("C:\\");
			System.Collections.IList params_Renamed = new System.Collections.ArrayList();
			try
			{
				params_Renamed.Add("/C");
				params_Renamed.Add("dir");
				System.String result = instance.executeSystemCommand(executable, new System.Collections.ArrayList(params_Renamed), working, 10);
				assertTrue(result.Length > 0);
			}
			catch (System.Exception e)
			{
				fail();
			}
			try
			{
				System.IO.FileInfo exec2 = new System.IO.FileInfo(executable.FullName + ";inject.exe");
				instance.executeSystemCommand(exec2, new System.Collections.ArrayList(params_Renamed), working, 10);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
			try
			{
				System.IO.FileInfo exec2 = new System.IO.FileInfo(executable.FullName + "\\..\\cmd.exe");
				instance.executeSystemCommand(exec2, new System.Collections.ArrayList(params_Renamed), working, 10);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
			try
			{
				System.IO.FileInfo workdir = new System.IO.FileInfo("ridiculous");
				instance.executeSystemCommand(executable, new System.Collections.ArrayList(params_Renamed), workdir, 10);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
			try
			{
				params_Renamed.Add("&dir");
				instance.executeSystemCommand(executable, new System.Collections.ArrayList(params_Renamed), working, 10);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
	}
}