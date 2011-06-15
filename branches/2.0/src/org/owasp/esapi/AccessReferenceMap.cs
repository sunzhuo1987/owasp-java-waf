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
using IRandomizer = org.owasp.esapi.interfaces.IRandomizer;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IAccessReferenceMap interface. This
	/// implementation generates random 6 character alphanumeric strings for indirect
	/// references. It is possible to use simple integers as indirect references, but
	/// the random string approach provides a certain level of protection from CSRF
	/// attacks, because an attacker would have difficulty guessing the indirect
	/// reference.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IAccessReferenceMap">
	/// </seealso>
	public class AccessReferenceMap : org.owasp.esapi.interfaces.IAccessReferenceMap
	{
		private void  InitBlock()
		{
			random = ESAPI.randomizer();
		}
		
		/// <summary>The itod. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		internal System.Collections.Hashtable itod = new System.Collections.Hashtable();
		
		/// <summary>The dtoi. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		internal System.Collections.Hashtable dtoi = new System.Collections.Hashtable();
		
		/// <summary>The random. </summary>
		//UPGRADE_NOTE: The initialization of  'random' was moved to method 'InitBlock'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		internal IRandomizer random;
		
		/// <summary> This AccessReferenceMap implementation uses short random strings to
		/// create a layer of indirection. Other possible implementations would use
		/// simple integers as indirect references.
		/// </summary>
		public AccessReferenceMap()
		{
			InitBlock();
			// call update to set up the references
		}
		
		/// <summary> Instantiates a new access reference map.
		/// 
		/// </summary>
		/// <param name="directReferences">the direct references
		/// </param>
		public AccessReferenceMap(SupportClass.SetSupport directReferences)
		{
			InitBlock();
			update(directReferences);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessReferenceMap#iterator()
		*/
		public virtual System.Collections.IEnumerator iterator()
		{
			//UPGRADE_TODO: Class 'java.util.TreeSet' was converted to 'SupportClass.TreeSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilTreeSet'"
			//UPGRADE_TODO: Method 'java.util.HashMap.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapkeySet'"
			SupportClass.TreeSetSupport sorted = new SupportClass.TreeSetSupport(new SupportClass.HashSetSupport(dtoi.Keys));
			return sorted.GetEnumerator();
		}
		
		/// <summary> Adds a direct reference and a new random indirect reference, overwriting any existing values.</summary>
		/// <param name="direct">
		/// </param>
		public virtual void  addDirectReference(System.String direct)
		{
			System.String indirect = random.getRandomString(6, Encoder.CHAR_ALPHANUMERICS);
			itod[indirect] = direct;
			dtoi[direct] = indirect;
		}
		
		
		// FIXME: add addDirectRef and removeDirectRef to IAccessReferenceMap
		// FIXME: add test code for add/remove direct ref
		
		/// <summary> Remove a direct reference and the corresponding indirect reference.</summary>
		/// <param name="direct">
		/// </param>
		public virtual void  removeDirectReference(System.String direct)
		{
			//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
			System.String indirect = (System.String) dtoi[direct];
			if (indirect != null)
			{
				itod.Remove(indirect);
				dtoi.Remove(direct);
			}
		}
		
		/*
		* This preserves any existing mappings for items that are still in the new
		* list. You could regenerate new indirect references every time, but that
		* might mess up anything that previously used an indirect reference, such
		* as a URL parameter.
		*/
		/// <summary> Update.
		/// 
		/// </summary>
		/// <param name="directReferences">the direct references
		/// </param>
		public void  update(SupportClass.SetSupport directReferences)
		{
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			System.Collections.Hashtable dtoi_old = (System.Collections.Hashtable) dtoi.Clone();
			dtoi.Clear();
			itod.Clear();
			
			System.Collections.IEnumerator i = directReferences.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.Object direct = i.Current;
				
				// get the old indirect reference
				//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
				System.String indirect = (System.String) dtoi_old[direct];
				
				// if the old reference is null, then create a new one that doesn't
				// collide with any existing indirect references
				if (indirect == null)
				{
					//UPGRADE_TODO: Method 'java.util.HashMap.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapkeySet'"
					do 
					{
						indirect = random.getRandomString(6, Encoder.CHAR_ALPHANUMERICS);
					}
					while (new SupportClass.HashSetSupport(itod.Keys).Contains(indirect));
				}
				itod[indirect] = direct;
				dtoi[direct] = indirect;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessReferenceMap#getIndirectReference(java.lang.String)
		*/
		public virtual System.String getIndirectReference(System.Object directReference)
		{
			//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
			return (System.String) dtoi[directReference];
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessReferenceMap#getDirectReference(java.lang.String)
		*/
		public virtual System.Object getDirectReference(System.String indirectReference)
		{
			if (itod.ContainsKey(indirectReference))
			{
				//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
				return itod[indirectReference];
			}
			throw new AccessControlException("Access denied", "Request for invalid indirect reference: " + indirectReference);
		}
	}
}