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
using EnterpriseSecurityException = org.owasp.esapi.errors.EnterpriseSecurityException;
using IntegrityException = org.owasp.esapi.errors.IntegrityException;
using IEncryptor = org.owasp.esapi.interfaces.IEncryptor;
namespace org.owasp.esapi
{
	
	/// <summary> The Class EncryptorTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class EncryptorTest:TestCase
	{
		
		/// <summary> Instantiates a new encryptor test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public EncryptorTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(EncryptorTest));
			
			return suite;
		}
		
		/// <summary> Test of hash method, of class org.owasp.esapi.Encryptor.</summary>
		public virtual void  testHash()
		{
			System.Console.Out.WriteLine("hash");
			IEncryptor instance = ESAPI.encryptor();
			System.String hash1 = instance.hash("test1", "salt");
			System.String hash2 = instance.hash("test2", "salt");
			assertFalse(hash1.Equals(hash2));
			System.String hash3 = instance.hash("test", "salt1");
			System.String hash4 = instance.hash("test", "salt2");
			assertFalse(hash3.Equals(hash4));
		}
		
		/// <summary> Test of encrypt method, of class org.owasp.esapi.Encryptor.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testEncrypt()
		{
			System.Console.Out.WriteLine("encrypt");
			IEncryptor instance = ESAPI.encryptor();
			System.String plaintext = "test123";
			System.String ciphertext = instance.encrypt(plaintext);
			System.String result = instance.decrypt(ciphertext);
			assertEquals(plaintext, result);
		}
		
		/// <summary> Test of decrypt method, of class org.owasp.esapi.Encryptor.</summary>
		public virtual void  testDecrypt()
		{
			System.Console.Out.WriteLine("decrypt");
			IEncryptor instance = ESAPI.encryptor();
			try
			{
				System.String plaintext = "test123";
				System.String ciphertext = instance.encrypt(plaintext);
				assertFalse(plaintext.Equals(ciphertext));
				System.String result = instance.decrypt(ciphertext);
				assertEquals(plaintext, result);
			}
			catch (EncryptionException e)
			{
				fail();
			}
		}
		
		/// <summary> Test of sign method, of class org.owasp.esapi.Encryptor.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testSign()
		{
			System.Console.Out.WriteLine("sign");
			IEncryptor instance = ESAPI.encryptor();
			System.String plaintext = ESAPI.randomizer().getRandomString(32, Encoder.CHAR_ALPHANUMERICS);
			System.String signature = instance.sign(plaintext);
			assertTrue(instance.verifySignature(signature, plaintext));
			assertFalse(instance.verifySignature(signature, "ridiculous"));
			assertFalse(instance.verifySignature("ridiculous", plaintext));
		}
		
		/// <summary> Test of verifySignature method, of class org.owasp.esapi.Encryptor.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testVerifySignature()
		{
			System.Console.Out.WriteLine("verifySignature");
			IEncryptor instance = ESAPI.encryptor();
			System.String plaintext = ESAPI.randomizer().getRandomString(32, Encoder.CHAR_ALPHANUMERICS);
			System.String signature = instance.sign(plaintext);
			assertTrue(instance.verifySignature(signature, plaintext));
		}
		
		
		/// <summary> Test of seal method, of class org.owasp.esapi.Encryptor.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testSeal()
		{
			System.Console.Out.WriteLine("seal");
			IEncryptor instance = ESAPI.encryptor();
			System.String plaintext = ESAPI.randomizer().getRandomString(32, Encoder.CHAR_ALPHANUMERICS);
			System.String seal = instance.seal(plaintext, instance.TimeStamp + 1000 * 60);
			instance.verifySeal(seal, plaintext);
		}
		
		/// <summary> Test of verifySeal method, of class org.owasp.esapi.Encryptor.
		/// 
		/// </summary>
		/// <throws>  EncryptionException </throws>
		/// <summary>             the encryption exception
		/// </summary>
		public virtual void  testVerifySeal()
		{
			System.Console.Out.WriteLine("verifySeal");
			IEncryptor instance = ESAPI.encryptor();
			System.String plaintext = ESAPI.randomizer().getRandomString(32, Encoder.CHAR_ALPHANUMERICS);
			System.String seal = instance.seal(plaintext, instance.TimeStamp + 1000 * 60);
			assertTrue(instance.verifySeal(seal, plaintext));
			assertFalse(instance.verifySeal("ridiculous", plaintext));
			assertFalse(instance.verifySeal(instance.encrypt("ridiculous"), plaintext));
			assertFalse(instance.verifySeal(instance.encrypt(100 + ":" + "ridiculous"), plaintext));
			assertFalse(instance.verifySeal(instance.encrypt(System.Int64.MaxValue + ":" + "ridiculous"), plaintext));
		}
	}
}