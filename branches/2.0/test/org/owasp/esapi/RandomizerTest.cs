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
using IRandomizer = org.owasp.esapi.interfaces.IRandomizer;
namespace org.owasp.esapi
{
	
	/// <summary> The Class RandomizerTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class RandomizerTest:TestCase
	{
		
		/// <summary> Instantiates a new randomizer test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public RandomizerTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(RandomizerTest));
			return suite;
		}
		
		/// <summary> Test of getRandomString method, of class org.owasp.esapi.Randomizer.</summary>
		public virtual void  testGetRandomString()
		{
			System.Console.Out.WriteLine("getRandomString");
			int length = 20;
			IRandomizer instance = ESAPI.randomizer();
			for (int i = 0; i < 100; i++)
			{
				System.String result = instance.getRandomString(length, Encoder.CHAR_ALPHANUMERICS);
				// FIXME: only the set of characters should be here
				assertEquals(length, result.Length);
			}
		}
		
		/// <summary> Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.</summary>
		public virtual void  testGetRandomInteger()
		{
			System.Console.Out.WriteLine("getRandomInteger");
			int min = - 20;
			int max = 100;
			IRandomizer instance = ESAPI.randomizer();
			int minResult = (max - min) / 2;
			int maxResult = (max - min) / 2;
			for (int i = 0; i < 100; i++)
			{
				int result = instance.getRandomInteger(min, max);
				if (result < minResult)
					minResult = result;
				if (result > maxResult)
					maxResult = result;
			}
			assertEquals(true, (minResult >= min && maxResult < max));
		}
		
		/// <summary> Test of getRandomReal method, of class org.owasp.esapi.Randomizer.</summary>
		public virtual void  testGetRandomReal()
		{
			System.Console.Out.WriteLine("getRandomReal");
			float min = - 20.5234F;
			float max = 100.12124F;
			IRandomizer instance = ESAPI.randomizer();
			float minResult = (max - min) / 2;
			float maxResult = (max - min) / 2;
			for (int i = 0; i < 100; i++)
			{
				float result = instance.getRandomReal(min, max);
				if (result < minResult)
					minResult = result;
				if (result > maxResult)
					maxResult = result;
			}
			assertEquals(true, (minResult >= min && maxResult < max));
		}
		
		
		/// <summary> Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.</summary>
		public virtual void  testGetRandomGUID()
		{
			System.Console.Out.WriteLine("getRandomGUID");
			IRandomizer instance = ESAPI.randomizer();
			System.Collections.ArrayList list = new System.Collections.ArrayList();
			for (int i = 0; i < 100; i++)
			{
				System.String guid = instance.RandomGUID;
				if (list.Contains(guid))
					fail();
				list.Add(guid);
			}
		}
	}
}