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
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IAccessReferenceMap interface is used to map from a set of internal
	/// direct object references to a set of indirect references that are safe to
	/// disclose publically. This can be used to help protect database keys,
	/// filenames, and other types of direct object references. As a rule, developers
	/// should not expose their direct object references as it enables attackers to
	/// attempt to manipulate them.
	/// <P>
	/// <img src="doc-files/AccessReferenceMap.jpg" height="600">
	/// <P>
	/// <P>
	/// Indirect references are handled as strings, to facilitate their use in HTML.
	/// Implementations can generate simple integers or more complicated random
	/// character strings as indirect references. Implementations should probably add
	/// a constructor that takes a list of direct references.
	/// <P>
	/// Note that in addition to defeating all forms of parameter tampering attacks,
	/// there is a side benefit of the AccessReferenceMap. Using random strings as indirect object
	/// references, as opposed to simple integers makes it impossible for an attacker to
	/// guess valid identifiers. So if per-user AccessReferenceMaps are used, then request
	/// forgery (CSRF) attacks will also be prevented.
	/// 
	/// <pre>
	/// Set fileSet = new HashSet();
	/// fileSet.addAll(...);
	/// AccessReferenceMap map = new AccessReferenceMap( fileSet );
	/// // store the map somewhere safe - like the session!
	/// String indRef = map.getIndirectReference( file1 );
	/// String href = &quot;http://www.aspectsecurity.com/esapi?file=&quot; + indRef );
	/// ...
	/// String indref = request.getParameter( &quot;file&quot; );
	/// File file = (File)map.getDirectReference( indref );
	/// </pre>
	/// 
	/// <P>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public interface IAccessReferenceMap
	{
		
		/// <summary> Get an iterator through the direct object references.
		/// 
		/// </summary>
		/// <returns> the iterator
		/// </returns>
		System.Collections.IEnumerator iterator();
		
		/// <summary> Get a safe indirect reference to use in place of a potentially sensitive
		/// direct object reference. Developers should use this call when building
		/// URL's, form fields, hidden fields, etc... to help protect their private
		/// implementation information.
		/// 
		/// </summary>
		/// <param name="directReference">the direct reference
		/// 
		/// </param>
		/// <returns> the indirect reference
		/// </returns>
		System.String getIndirectReference(System.Object directReference);
		
		/// <summary> Get the original direct object reference from an indirect reference.
		/// Developers should use this when they get an indirect reference from an
		/// HTTP request to translate it back into the real direct reference. If an
		/// invalid indirectReference is requested, then an AccessControlException is
		/// thrown.
		/// 
		/// </summary>
		/// <param name="indirectReference">the indirect reference
		/// 
		/// </param>
		/// <returns> the direct reference
		/// 
		/// </returns>
		/// <throws>  AccessControlException </throws>
		/// <summary>             the access control exception
		/// </summary>
		System.Object getDirectReference(System.String indirectReference);
		
		/// <summary> Adds a direct reference to the AccessReferenceMap and generates an associated indirect reference. </summary>
		/// <param name="direct">
		/// </param>
		void  addDirectReference(System.String direct);
		
		/// <summary> Removes a direct reference and its associated indirect reference from the AccessReferenceMap.</summary>
		/// <param name="direct">
		/// </param>
		/// <throws>  AccessControlException </throws>
		void  removeDirectReference(System.String direct);
	}
}