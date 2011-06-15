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
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
namespace org.owasp.esapi
{
	
	/// <summary> The Class EncryptedPropertiesTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class EncryptedPropertiesTest:TestCase
	{
		
		/// <summary> Instantiates a new encrypted properties test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public EncryptedPropertiesTest(System.String testName):base(testName)
		{
		}
		
		/* (non-Javadoc)
		* @see junit.framework.TestCase#setUp()
		*/
		protected internal virtual void  setUp()
		{
			// none
		}
		
		/* (non-Javadoc)
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
			TestSuite suite = new TestSuite(typeof(EncryptedPropertiesTest));
			
			return suite;
		}
		
		/// <summary> Test of getProperty method, of class org.owasp.esapi.EncryptedProperties.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testGetProperty()
		{
			System.Console.Out.WriteLine("getProperty");
			EncryptedProperties instance = new EncryptedProperties();
			System.String name = "name";
			System.String value_Renamed = "value";
			instance.setProperty(name, value_Renamed);
			System.String result = instance.getProperty(name);
			assertEquals(value_Renamed, result);
			try
			{
				instance.getProperty("ridiculous");
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
		
		/// <summary> Test of setProperty method, of class org.owasp.esapi.EncryptedProperties.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testSetProperty()
		{
			System.Console.Out.WriteLine("setProperty");
			EncryptedProperties instance = new EncryptedProperties();
			System.String name = "name";
			System.String value_Renamed = "value";
			instance.setProperty(name, value_Renamed);
			System.String result = instance.getProperty(name);
			assertEquals(value_Renamed, result);
			try
			{
				instance.setProperty(null, null);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
		
		
		/// <summary> Test of keySet method, of class org.owasp.esapi.EncryptedProperties.</summary>
		public virtual void  testKeySet()
		{
			System.Console.Out.WriteLine("keySet");
			EncryptedProperties instance = new EncryptedProperties();
			instance.setProperty("one", "two");
			instance.setProperty("two", "three");
			System.Collections.IEnumerator i = instance.keySet().GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
			assertEquals("two", (System.String) i.Current);
			//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
			assertEquals("one", (System.String) i.Current);
			try
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.Object generatedAux2 = i.Current;
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
		
		/// <summary> Test of load method, of class org.owasp.esapi.EncryptedProperties.</summary>
		public virtual void  testLoad()
		{
			System.Console.Out.WriteLine("load");
			EncryptedProperties instance = new EncryptedProperties();
			System.IO.FileInfo f = new System.IO.FileInfo(((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory.FullName + "\\" + "test.properties");
			//UPGRADE_TODO: Constructor 'java.io.FileInputStream.FileInputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileInputStreamFileInputStream_javaioFile'"
			instance.load(new System.IO.FileStream(f.FullName, System.IO.FileMode.Open, System.IO.FileAccess.Read));
			assertEquals("two", instance.getProperty("one"));
			assertEquals("three", instance.getProperty("two"));
		}
		
		/// <summary> Test of store method, of class org.owasp.esapi.EncryptedProperties.</summary>
		public virtual void  testStore()
		{
			System.Console.Out.WriteLine("store");
			EncryptedProperties instance = new EncryptedProperties();
			instance.setProperty("one", "two");
			instance.setProperty("two", "three");
			System.IO.FileInfo f = new System.IO.FileInfo(((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory.FullName + "\\" + "test.properties");
			//UPGRADE_TODO: Constructor 'java.io.FileOutputStream.FileOutputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileOutputStreamFileOutputStream_javaioFile'"
			instance.store(new System.IO.FileStream(f.FullName, System.IO.FileMode.Create), "testStore");
		}
		
		/// <summary> Test of store method, of class org.owasp.esapi.EncryptedProperties.</summary>
		public virtual void  testMain()
		{
			System.Console.Out.WriteLine("main");
			System.IO.FileInfo f = new System.IO.FileInfo(((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory.FullName + "\\" + "test.properties");
			System.String[] args1 = new System.String[]{f.FullName};
			System.IO.Stream orig = System.Console.OpenStandardInput();
			System.String input = "key\r\nvalue\r\n";
			//UPGRADE_TODO: Method 'java.lang.System.setIn' was converted to 'System.Console.SetIn' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangSystemsetIn_javaioInputStream'"
			System.Console.SetIn(new System.IO.StringReader(input));
			EncryptedProperties.main(args1);
			//UPGRADE_TODO: Method 'java.lang.System.setIn' was converted to 'System.Console.SetIn' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javalangSystemsetIn_javaioInputStream'"
			System.Console.SetIn(orig);
			System.String[] args2 = new System.String[]{"ridiculous.properties"};
			try
			{
				EncryptedProperties.main(args2);
				fail();
			}
			catch (System.Exception e)
			{
				// expected
			}
		}
	}
}