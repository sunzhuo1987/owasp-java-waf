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
using EncodingException = org.owasp.esapi.errors.EncodingException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
using IEncoder = org.owasp.esapi.interfaces.IEncoder;
namespace org.owasp.esapi
{
	
	/// <summary> The Class EncoderTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class EncoderTest:TestCase
	{
		
		/// <summary> Instantiates a new encoder test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public EncoderTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(EncoderTest));
			return suite;
		}
		
		
		/// <summary> Test of canonicalize method, of class org.owasp.esapi.Validator.
		/// 
		/// </summary>
		/// <throws>  ValidationException </throws>
		public virtual void  testCanonicalize()
		{
			System.Console.Out.WriteLine("canonicalize");
			IEncoder instance = ESAPI.encoder();
			assertEquals("<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
			try
			{
				assertEquals("<script", instance.canonicalize("%253Cscript"));
			}
			catch (IntrusionException e)
			{
				// expected
			}
			try
			{
				assertEquals("<script", instance.canonicalize("&#37;3Cscript"));
			}
			catch (IntrusionException e)
			{
				// expected
			}
		}
		
		/// <summary> Test of normalize method, of class org.owasp.esapi.Validator.
		/// 
		/// </summary>
		/// <throws>  ValidationException </throws>
		/// <summary>             the validation exception
		/// </summary>
		public virtual void  testNormalize()
		{
			System.Console.Out.WriteLine("normalize");
			assertEquals(ESAPI.encoder().normalize("é à î _ @ \" < > \u20A0"), "e a i _ @ \" < > ");
		}
		
		public virtual void  testEntityEncode()
		{
			System.Console.Out.WriteLine("entityEncode");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&lt;script&gt;", instance.encodeForHTML("&lt;script&gt;"));
			assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTML("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;"));
		}
		
		/// <summary> Test of encodeForHTML method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForHTML()
		{
			System.Console.Out.WriteLine("encodeForHTML");
			IEncoder instance = ESAPI.encoder();
			assertEquals("", instance.encodeForHTML(null));
			assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
			assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
			assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTML("!@$%()=+{}[]"));
			assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
			assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
		}
		
		/// <summary> Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForHTMLAttribute()
		{
			System.Console.Out.WriteLine("encodeForHTMLAttribute");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
			assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
			assertEquals("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
		}
		
		/// <summary> Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForJavascript()
		{
			System.Console.Out.WriteLine("encodeForJavascript");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&lt;script&gt;", instance.encodeForJavascript("<script>"));
			assertEquals(",.-_ ", instance.encodeForJavascript(",.-_ "));
			assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForJavascript("!@$%()=+{}[]"));
		}
		
		/// <summary> Test of encodeForVisualBasicScript method, of class
		/// org.owasp.esapi.Encoder.
		/// </summary>
		public virtual void  testEncodeForVBScript()
		{
			System.Console.Out.WriteLine("encodeForVBScript");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&lt;script&gt;", instance.encodeForVBScript("<script>"));
			assertEquals(",.-_ ", instance.encodeForVBScript(",.-_ "));
			assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForVBScript("!@$%()=+{}[]"));
		}
		
		/// <summary> Test of encodeForXPath method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForXPath()
		{
			System.Console.Out.WriteLine("encodeForXPath");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&#39;or 1&#61;1", instance.encodeForXPath("'or 1=1"));
		}
		
		
		
		/// <summary> Test of encodeForSQL method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForSQL()
		{
			System.Console.Out.WriteLine("encodeForSQL");
			IEncoder instance = ESAPI.encoder();
			assertEquals("Single quote", "Jeff'' or ''1''=''1", instance.encodeForSQL("Jeff' or '1'='1"));
		}
		
		
		/// <summary> Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForLDAP()
		{
			System.Console.Out.WriteLine("encodeForLDAP");
			IEncoder instance = ESAPI.encoder();
			assertEquals("No special characters to escape", "Hi This is a test #çà", instance.encodeForLDAP("Hi This is a test #çà"));
			assertEquals("Zeros", "Hi \\00", instance.encodeForLDAP("Hi \u0000"));
			assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # ç à ô", instance.encodeForLDAP("Hi (This) = is * a \\ test # ç à ô"));
		}
		
		/// <summary> Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForDN()
		{
			System.Console.Out.WriteLine("encodeForDN");
			IEncoder instance = ESAPI.encoder();
			assertEquals("No special characters to escape", "Helloé", instance.encodeForDN("Helloé"));
			assertEquals("leading #", "\\# Helloé", instance.encodeForDN("# Helloé"));
			assertEquals("leading space", "\\ Helloé", instance.encodeForDN(" Helloé"));
			assertEquals("trailing space", "Helloé\\ ", instance.encodeForDN("Helloé "));
			assertEquals("less than greater than", "Hello\\<\\>", instance.encodeForDN("Hello<>"));
			assertEquals("only 3 spaces", "\\  \\ ", instance.encodeForDN("   "));
			assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", instance.encodeForDN(" Hello\\ + , \"World\" ; "));
		}
		
		
		/// <summary> Test of encodeForXML method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForXML()
		{
			System.Console.Out.WriteLine("encodeForXML");
			IEncoder instance = ESAPI.encoder();
			assertEquals(" ", instance.encodeForXML(" "));
			assertEquals("&lt;script&gt;", instance.encodeForXML("<script>"));
			assertEquals(",.-_", instance.encodeForXML(",.-_"));
			assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForXML("!@$%()=+{}[]"));
		}
		
		
		
		/// <summary> Test of encodeForXMLAttribute method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForXMLAttribute()
		{
			System.Console.Out.WriteLine("encodeForXMLAttribute");
			IEncoder instance = ESAPI.encoder();
			assertEquals("&#32;", instance.encodeForXMLAttribute(" "));
			assertEquals("&lt;script&gt;", instance.encodeForXMLAttribute("<script>"));
			assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
			assertEquals("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
		}
		
		/// <summary> Test of encodeForURL method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForURL()
		{
			System.Console.Out.WriteLine("encodeForURL");
			IEncoder instance = ESAPI.encoder();
			assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
		}
		
		/// <summary> Test of decodeFromURL method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testDecodeFromURL()
		{
			System.Console.Out.WriteLine("decodeFromURL");
			IEncoder instance = ESAPI.encoder();
			try
			{
				assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
				assertEquals("     ", instance.decodeFromURL("+++++"));
			}
			catch (System.Exception e)
			{
				fail();
			}
		}
		
		/// <summary> Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testEncodeForBase64()
		{
			System.Console.Out.WriteLine("encodeForBase64");
			IEncoder instance = ESAPI.encoder();
			try
			{
				for (int i = 0; i < 100; i++)
				{
					sbyte[] r = SupportClass.ToSByteArray(SupportClass.ToByteArray(ESAPI.randomizer().getRandomString(20, Encoder.CHAR_SPECIALS)));
					System.String encoded = instance.encodeForBase64(r, ESAPI.randomizer().RandomBoolean);
					sbyte[] decoded = instance.decodeFromBase64(encoded);
					assertTrue(SupportClass.ArraySupport.Equals(SupportClass.ToByteArray(r), SupportClass.ToByteArray(decoded)));
				}
			}
			catch (System.IO.IOException e)
			{
				fail();
			}
		}
		
		/// <summary> Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.</summary>
		public virtual void  testDecodeFromBase64()
		{
			System.Console.Out.WriteLine("decodeFromBase64");
			IEncoder instance = ESAPI.encoder();
			for (int i = 0; i < 100; i++)
			{
				try
				{
					sbyte[] r = SupportClass.ToSByteArray(SupportClass.ToByteArray(ESAPI.randomizer().getRandomString(20, Encoder.CHAR_SPECIALS)));
					System.String encoded = instance.encodeForBase64(r, ESAPI.randomizer().RandomBoolean);
					sbyte[] decoded = instance.decodeFromBase64(encoded);
					assertTrue(SupportClass.ArraySupport.Equals(SupportClass.ToByteArray(r), SupportClass.ToByteArray(decoded)));
				}
				catch (System.IO.IOException e)
				{
					fail();
				}
			}
			for (int i = 0; i < 100; i++)
			{
				try
				{
					sbyte[] r = SupportClass.ToSByteArray(SupportClass.ToByteArray(ESAPI.randomizer().getRandomString(20, Encoder.CHAR_SPECIALS)));
					System.String encoded = ESAPI.randomizer().getRandomString(1, Encoder.CHAR_ALPHANUMERICS) + instance.encodeForBase64(r, ESAPI.randomizer().RandomBoolean);
					sbyte[] decoded = instance.decodeFromBase64(encoded);
					assertFalse(SupportClass.ArraySupport.Equals(SupportClass.ToByteArray(r), SupportClass.ToByteArray(decoded)));
				}
				catch (System.IO.IOException e)
				{
					// expected
				}
			}
		}
	}
}