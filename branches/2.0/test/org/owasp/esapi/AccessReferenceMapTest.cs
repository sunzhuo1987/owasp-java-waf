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
using AccessControlException = org.owasp.esapi.errors.AccessControlException;
using AuthenticationException = org.owasp.esapi.errors.AuthenticationException;
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
//UPGRADE_TODO: The type 'junit.framework.Test' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Test = junit.framework.Test;
//UPGRADE_TODO: The type 'junit.framework.TestCase' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using TestCase = junit.framework.TestCase;
//UPGRADE_TODO: The type 'junit.framework.TestSuite' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using TestSuite = junit.framework.TestSuite;
namespace org.owasp.esapi
{
	
	/// <summary> The Class AccessReferenceMapTest.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public class AccessReferenceMapTest:TestCase
	{
		
		/// <summary> Instantiates a new access reference map test.
		/// 
		/// </summary>
		/// <param name="testName">the test name
		/// </param>
		public AccessReferenceMapTest(System.String testName):base(testName)
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
			TestSuite suite = new TestSuite(typeof(AccessReferenceMapTest));
			return suite;
		}
		
		
		/// <summary> Test of update method, of class org.owasp.esapi.AccessReferenceMap.
		/// 
		/// </summary>
		/// <throws>  AuthenticationException </throws>
		/// <summary>             the authentication exception
		/// </summary>
		public virtual void  testUpdate()
		{
			System.Console.Out.WriteLine("update");
			AccessReferenceMap arm = new AccessReferenceMap();
			IAuthenticator auth = ESAPI.authenticator();
			
			System.String pass = auth.generateStrongPassword();
			User u = auth.createUser("armUpdate", pass, pass);
			
			// test to make sure update returns something
			arm.update(auth.getUserNames());
			System.String indirect = arm.getIndirectReference(u.AccountName);
			if (indirect == null)
				fail();
			
			// test to make sure update removes items that are no longer in the list
			auth.removeUser(u.AccountName);
			arm.update(auth.getUserNames());
			indirect = arm.getIndirectReference(u.AccountName);
			if (indirect != null)
				fail();
			
			// test to make sure old indirect reference is maintained after an update
			arm.update(auth.getUserNames());
			System.String newIndirect = arm.getIndirectReference(u.AccountName);
			assertEquals(indirect, newIndirect);
		}
		
		
		/// <summary> Test of iterator method, of class org.owasp.esapi.AccessReferenceMap.</summary>
		public virtual void  testIterator()
		{
			System.Console.Out.WriteLine("iterator");
			AccessReferenceMap arm = new AccessReferenceMap();
			IAuthenticator auth = ESAPI.authenticator();
			
			arm.update(auth.getUserNames());
			
			System.Collections.IEnumerator i = arm.iterator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String userName = (System.String) i.Current;
				User u = auth.getUser(userName);
				if (u == null)
					fail();
			}
		}
		
		/// <summary> Test of getIndirectReference method, of class
		/// org.owasp.esapi.AccessReferenceMap.
		/// </summary>
		public virtual void  testGetIndirectReference()
		{
			System.Console.Out.WriteLine("getIndirectReference");
			
			System.String directReference = "234";
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport list = new SupportClass.HashSetSupport();
			list.Add("123");
			list.Add(directReference);
			list.Add("345");
			AccessReferenceMap instance = new AccessReferenceMap(list);
			
			System.String expResult = directReference;
			System.String result = instance.getIndirectReference(directReference);
			assertNotSame(expResult, result);
		}
		
		/// <summary> Test of getDirectReference method, of class
		/// org.owasp.esapi.AccessReferenceMap.
		/// 
		/// </summary>
		/// <throws>  AccessControlException </throws>
		/// <summary>             the access control exception
		/// </summary>
		public virtual void  testGetDirectReference()
		{
			System.Console.Out.WriteLine("getDirectReference");
			
			System.String directReference = "234";
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport list = new SupportClass.HashSetSupport();
			list.Add("123");
			list.Add(directReference);
			list.Add("345");
			AccessReferenceMap instance = new AccessReferenceMap(list);
			
			System.String ind = instance.getIndirectReference(directReference);
			System.String dir = (System.String) instance.getDirectReference(ind);
			assertEquals(directReference, dir);
			try
			{
				instance.getDirectReference("invalid");
				fail();
			}
			catch (AccessControlException e)
			{
				// success
			}
		}
	}
}