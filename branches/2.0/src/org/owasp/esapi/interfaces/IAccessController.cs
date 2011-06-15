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
namespace org.owasp.esapi.interfaces
{
	
	
	/// <summary> The IAccessController interface defines a set of methods that can be used in a wide variety of applications to
	/// enforce access control. In most applications, access control must be performed in multiple different locations across
	/// the various applicaton layers. This class provides access control for URLs, business functions, data, services, and
	/// files.
	/// <P>
	/// <img src="doc-files/AccessController.jpg" height="600">
	/// <P>
	/// The implementation of this interface will need to access some sort of user information repository to determine what
	/// roles or permissions are assigned to the accountName passed into the various methods. In addition, the implementation
	/// will also need information about the resources that are being accessed. Using the user information and the resource
	/// information, the implementation should return an access control decision. 
	/// <P>
	/// Implementers are encouraged to build on existing access control mechanisms, such as methods like isUserInRole() or
	/// hasPrivilege(). While powerful, these methods can be confusing, as users may be in multiple roles or possess multiple
	/// overlapping privileges. These methods encourage the use of complex boolean tests throughout the code. The point of
	/// this interface is to centralize access control logic so that it is easy to use and easy to verify.
	/// 
	/// <pre>
	/// if ( ESAPI.accessController().isAuthorizedForFunction( BUSINESS_FUNCTION ) ) {
	/// ... access is allowed
	/// } else {
	/// ... attack in progress
	/// }
	/// </pre>
	/// 
	/// Note that in the user interface layer, access control checks can be used to control whether particular controls are
	/// rendered or not. These checks are supposed to fail when an unauthorized user is logged in, and do not represent
	/// attacks. Remember that regardless of how the user interface appears, an attacker can attempt to invoke any business
	/// function or access any data in your application. Therefore, access control checks in the user interface should be
	/// repeated in both the business logic and data layers.
	/// 
	/// <pre>
	/// &lt;% if ( ESAPI.accessController().isAuthorizedForFunction( ADMIN_FUNCTION ) ) { %&gt;
	/// &lt;a href=&quot;/doAdminFunction&quot;&gt;ADMIN&lt;/a&gt;
	/// &lt;% } else { %&gt;
	/// &lt;a href=&quot;/doNormalFunction&quot;&gt;NORMAL&lt;/a&gt;
	/// &lt;% } %&gt;
	/// </pre>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	public interface IAccessController
	{
		
		/// <summary> Checks if an account is authorized to access the referenced URL. The implementation should allow
		/// access to be granted to any part of the URI. Generally, this method should be invoked in the
		/// application's controller or a filter as follows:
		/// <PRE>ESAPI.accessController().isAuthorizedForURL(request.getRequestURI().toString());</PRE>
		/// 
		/// </summary>
		/// <param name="uri">the uri as returned by request.getRequestURI().toString()
		/// </param>
		/// <returns> true, if is authorized for URL
		/// </returns>
		bool isAuthorizedForURL(System.String url);
		
		/// <summary> Checks if an account is authorized to access the referenced function. The implementation should define the
		/// function "namespace" to be enforced. Choosing something simple like the classname of action classes or menu item
		/// names will make this implementation easier to use.
		/// 
		/// </summary>
		/// <param name="functionName">the function name
		/// </param>
		/// <returns> true, if is authorized for function
		/// </returns>
		bool isAuthorizedForFunction(System.String functionName);
		
		/// <summary> Checks if an account is authorized to access the referenced data. The implementation should define the data
		/// "namespace" to be enforced.
		/// 
		/// </summary>
		/// <param name="key">the key
		/// </param>
		/// <returns> true, if is authorized for data
		/// </returns>
		bool isAuthorizedForData(System.String key);
		
		/// <summary> Checks if an account is authorized to access the referenced file. The implementation should be extremely careful
		/// about canonicalization.
		/// 
		/// </summary>
		/// <param name="filepath">the filepath
		/// </param>
		/// <returns> true, if is authorized for file
		/// </returns>
		bool isAuthorizedForFile(System.String filepath);
		
		/// <summary> Checks if an account is authorized to access the referenced service. This can be used in applications that
		/// provide access to a variety of backend services.
		/// 
		/// </summary>
		/// <param name="serviceName">the service name
		/// </param>
		/// <returns> true, if is authorized for service
		/// </returns>
		bool isAuthorizedForService(System.String serviceName);
	}
}