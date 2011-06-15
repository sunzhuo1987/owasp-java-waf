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
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
using TestHttpServletRequest = org.owasp.esapi.http.TestHttpServletRequest;
using TestHttpServletResponse = org.owasp.esapi.http.TestHttpServletResponse;
using IValidator = org.owasp.esapi.interfaces.IValidator;
namespace org.owasp.esapi
{
	
	/// <summary> The Class ValidatorTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class ValidatorTest:TestCase
	{
		
		/// <summary> Instantiates a new validator test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public ValidatorTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(ValidatorTest));
			
			return suite;
		}
		
		/// <summary> Test of isValidCreditCard method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidCreditCard()
		{
			System.Console.Out.WriteLine("isValidCreditCard");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidCreditCard("test", "1234 9876 0000 0008"));
			assertTrue(instance.isValidCreditCard("test", "1234987600000008"));
			assertFalse(instance.isValidCreditCard("test", "12349876000000081"));
			assertFalse(instance.isValidCreditCard("test", "4417 1234 5678 9112"));
		}
		
		/// <summary> Test of isValidEmailAddress method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidDataFromBrowser()
		{
			System.Console.Out.WriteLine("isValidDataFromBrowser");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidDataFromBrowser("test", "Email", "jeff.williams@aspectsecurity.com"));
			assertFalse(instance.isValidDataFromBrowser("test", "Email", "jeff.williams@@aspectsecurity.com"));
			assertFalse(instance.isValidDataFromBrowser("test", "Email", "jeff.williams@aspectsecurity"));
			assertTrue(instance.isValidDataFromBrowser("test", "IPAddress", "123.168.100.234"));
			assertTrue(instance.isValidDataFromBrowser("test", "IPAddress", "192.168.1.234"));
			assertFalse(instance.isValidDataFromBrowser("test", "IPAddress", "..168.1.234"));
			assertFalse(instance.isValidDataFromBrowser("test", "IPAddress", "10.x.1.234"));
			assertTrue(instance.isValidDataFromBrowser("test", "URL", "http://www.aspectsecurity.com"));
			assertFalse(instance.isValidDataFromBrowser("test", "URL", "http:///www.aspectsecurity.com"));
			assertFalse(instance.isValidDataFromBrowser("test", "URL", "http://www.aspect security.com"));
			assertTrue(instance.isValidDataFromBrowser("test", "SSN", "078-05-1120"));
			assertTrue(instance.isValidDataFromBrowser("test", "SSN", "078 05 1120"));
			assertTrue(instance.isValidDataFromBrowser("test", "SSN", "078051120"));
			assertFalse(instance.isValidDataFromBrowser("test", "SSN", "987-65-4320"));
			assertFalse(instance.isValidDataFromBrowser("test", "SSN", "000-00-0000"));
			assertFalse(instance.isValidDataFromBrowser("test", "SSN", "(555) 555-5555"));
			assertFalse(instance.isValidDataFromBrowser("test", "SSN", "test"));
		}
		
		/// <summary> Test of isValidSafeHTML method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidSafeHTML()
		{
			System.Console.Out.WriteLine("isValidSafeHTML");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>"));
			assertTrue(instance.isValidSafeHTML("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>"));
			assertFalse(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>"));
			assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
		}
		
		/// <summary> Test of getValidSafeHTML method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testGetValidSafeHTML()
		{
			System.Console.Out.WriteLine("getValidSafeHTML");
			IValidator instance = ESAPI.validator();
			System.String test1 = "<b>Jeff</b>";
			System.String result1 = instance.getValidSafeHTML("test", test1);
			assertEquals(test1, result1);
			
			System.String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
			System.String result2 = instance.getValidSafeHTML("test", test2);
			assertEquals(test2, result2);
			
			System.String test3 = "Test. <script>alert(document.cookie)</script>";
			System.String result3 = instance.getValidSafeHTML("test", test3);
			assertEquals("Test.", result3);
			
			// FIXME: ENHANCE waiting for a way to validate text headed for an attribute for scripts		
			//		String test4 = "\" onload=\"alert(document.cookie)\" ";
			//		String result4 = instance.getValidSafeHTML("test", test4);
			//		assertEquals("", result4);
		}
		
		/// <summary> Test of isValidListItem method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidListItem()
		{
			System.Console.Out.WriteLine("isValidListItem");
			IValidator instance = ESAPI.validator();
			System.Collections.IList list = new System.Collections.ArrayList();
			list.Add("one");
			list.Add("two");
			assertTrue(instance.isValidListItem(list, "one"));
			assertFalse(instance.isValidListItem(list, "three"));
		}
		
		/// <summary> Test of isValidNumber method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidNumber()
		{
			System.Console.Out.WriteLine("isValidNumber");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidNumber("4"));
			assertTrue(instance.isValidNumber("400"));
			assertTrue(instance.isValidNumber("4000000000000"));
			assertFalse(instance.isValidNumber("alsdkf"));
			assertFalse(instance.isValidNumber("--10"));
			assertFalse(instance.isValidNumber("14.1414234x"));
			assertFalse(instance.isValidNumber("Infinity"));
			assertFalse(instance.isValidNumber("-Infinity"));
			assertFalse(instance.isValidNumber("NaN"));
			assertFalse(instance.isValidNumber("-NaN"));
			assertFalse(instance.isValidNumber("+NaN"));
			assertTrue(instance.isValidNumber("1e-6"));
			assertTrue(instance.isValidNumber("-1e-6"));
		}
		
		/// <summary> Test of getValidDate method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testGetValidDate()
		{
			System.Console.Out.WriteLine("getValidDate");
			IValidator instance = ESAPI.validator();
			//UPGRADE_TODO: The 'System.DateTime' structure does not have an equivalent to NULL. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1291'"
			assertTrue(instance.getValidDate("test", "June 23, 1967", SupportClass.GetDateTimeFormatInstance(2, -1, System.Globalization.CultureInfo.CurrentCulture)) != null);
			try
			{
				instance.getValidDate("test", "freakshow", SupportClass.GetDateTimeFormatInstance(2, -1, System.Globalization.CultureInfo.CurrentCulture));
			}
			catch (ValidationException e)
			{
				// expected
			}
			
			// FIXME: AAA This test case fails due to an apparent bug in SimpleDateFormat
			try
			{
				instance.getValidDate("test", "June 32, 2008", SupportClass.GetDateTimeFormatInstance(2, -1, System.Globalization.CultureInfo.CurrentCulture));
			}
			catch (ValidationException e)
			{
				// expected
			}
		}
		
		/// <summary> Test of isValidFileName method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidFileName()
		{
			System.Console.Out.WriteLine("isValidFileName");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidFileName("test", "aspect.jar"));
			assertFalse(instance.isValidFileName("test", ""));
			try
			{
				instance.isValidFileName("test", "abc/def");
			}
			catch (IntrusionException e)
			{
				// expected
			}
		}
		
		/// <summary> Test of isValidDirectoryPath method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidDirectoryPath()
		{
			System.Console.Out.WriteLine("isValidDirectoryPath");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidDirectoryPath("test", "/"));
			assertTrue(instance.isValidDirectoryPath("test", "c:\\temp"));
			assertTrue(instance.isValidDirectoryPath("test", "/etc/config"));
			// FIXME: ENHANCE doesn't accept filenames, just directories - should it?
			// assertTrue( instance.isValidDirectoryPath(
			// "c:\\Windows\\System32\\cmd.exe" ) );
			assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc"));
		}
		
		public virtual void  testIsValidPrintable()
		{
			System.Console.Out.WriteLine("isValidPrintable");
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidPrintable("abcDEF"));
			assertTrue(instance.isValidPrintable("!@#R()*$;><()"));
			sbyte[] bytes = new sbyte[]{(sbyte) (0x60), (sbyte) SupportClass.Identity(0xFF), (sbyte) (0x10), (sbyte) (0x25)};
			assertFalse(instance.isValidPrintable(bytes));
			assertFalse(instance.isValidPrintable("%08"));
		}
		
		/// <summary> Test of isValidFileContent method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidFileContent()
		{
			System.Console.Out.WriteLine("isValidFileContent");
			sbyte[] content = SupportClass.ToSByteArray(SupportClass.ToByteArray("This is some file content"));
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidFileContent("test", content));
		}
		
		/// <summary> Test of isValidFileUpload method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidFileUpload()
		{
			System.Console.Out.WriteLine("isValidFileUpload");
			
			System.String filepath = "/etc";
			System.String filename = "aspect.jar";
			sbyte[] content = SupportClass.ToSByteArray(SupportClass.ToByteArray("Thisi is some file content"));
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidFileUpload("test", filepath, filename, content));
		}
		
		/// <summary> Test of isValidParameterSet method, of class org.owasp.esapi.Validator.</summary>
		public virtual void  testIsValidParameterSet()
		{
			System.Console.Out.WriteLine("isValidParameterSet");
			
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport requiredNames = new SupportClass.HashSetSupport();
			requiredNames.Add("p1");
			requiredNames.Add("p2");
			requiredNames.Add("p3");
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport optionalNames = new SupportClass.HashSetSupport();
			optionalNames.Add("p4");
			optionalNames.Add("p5");
			optionalNames.Add("p6");
			TestHttpServletRequest request = new TestHttpServletRequest();
			TestHttpServletResponse response = new TestHttpServletResponse();
			request.addParameter("p1", "value");
			request.addParameter("p2", "value");
			request.addParameter("p3", "value");
			((Authenticator) ESAPI.authenticator()).setCurrentHTTP(request, response);
			IValidator instance = ESAPI.validator();
			assertTrue(instance.isValidParameterSet(requiredNames, optionalNames));
			request.addParameter("p4", "value");
			request.addParameter("p5", "value");
			request.addParameter("p6", "value");
			assertTrue(instance.isValidParameterSet(requiredNames, optionalNames));
			request.removeParameter("p1");
			assertFalse(instance.isValidParameterSet(requiredNames, optionalNames));
		}
		
		/// <summary> Test safe read line.</summary>
		public virtual void  testSafeReadLine()
		{
			System.IO.MemoryStream s = new System.IO.MemoryStream(SupportClass.ToByteArray("testString"));
			IValidator instance = ESAPI.validator();
			try
			{
				instance.safeReadLine(s, - 1);
				fail();
			}
			catch (ValidationException e)
			{
				// Expected
			}
			s.Position = SupportClass.ByteArrayInputManager.manager.ResetMark(s);
			try
			{
				instance.safeReadLine(s, 4);
				fail();
			}
			catch (ValidationException e)
			{
				// Expected
			}
			s.Position = SupportClass.ByteArrayInputManager.manager.ResetMark(s);
			try
			{
				System.String u = instance.safeReadLine(s, 20);
				assertEquals("testString", u);
			}
			catch (ValidationException e)
			{
				fail();
			}
		}
	}
}