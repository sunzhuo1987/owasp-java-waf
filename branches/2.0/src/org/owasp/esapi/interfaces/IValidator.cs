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
using ValidationException = org.owasp.esapi.errors.ValidationException;
namespace org.owasp.esapi.interfaces
{
	
	/// <summary> The IValidator interface defines a set of methods for canonicalizing and
	/// validating untrusted input. Implementors should feel free to extend this
	/// interface to accomodate their own data formats. Rather than throw exceptions,
	/// this interface returns boolean results because not all validation problems
	/// are security issues. Boolean returns allow developers to handle both valid
	/// and invalid results more cleanly than exceptions.
	/// <P>
	/// <img src="doc-files/Validator.jpg" height="600">
	/// <P>
	/// Implementations must adopt a "whitelist" approach to validation where a
	/// specific pattern or character set is matched. "Blacklist" approaches that
	/// attempt to identify the invalid or disallowed characters are much more likely
	/// to allow a bypass with encoding or other tricks.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public interface IValidator
	{
		
		/// <summary> </summary>
		/// <param name="type">
		/// </param>
		/// <param name="input">
		/// </param>
		/// <returns>
		/// </returns>
		/// <throws>  ValidationException </throws>
		System.String getValidDataFromBrowser(System.String context, System.String type, System.String value_Renamed);
		
		/// <summary> Gets a valid date from the input.</summary>
		System.DateTime getValidDate(System.String context, System.String value_Renamed, System.Globalization.DateTimeFormatInfo format);
		
		/// <summary> Returns valid safe HTML from any input string.</summary>
		System.String getValidSafeHTML(System.String context, System.String value_Renamed);
		
		/// <summary> Checks if input is a valid credit card.</summary>
		bool isValidCreditCard(System.String context, System.String value_Renamed);
		
		/// <summary> Checks if input from browser is valid according to the specified type. The types are configured
		/// as regular expressions in ESAPI.config.
		/// </summary>
		bool isValidDataFromBrowser(System.String name, System.String type, System.String value_Renamed);
		
		/// <summary> Checks if input is a valid directory path.</summary>
		bool isValidDirectoryPath(System.String context, System.String value_Renamed);
		
		/// <summary> Checks if input is a valid file upload.
		/// 
		/// </summary>
		/// <param name="content">the content
		/// 
		/// </param>
		/// <returns> true, if is valid file upload
		/// </returns>
		bool isValidFileContent(System.String context, sbyte[] content);
		
		/// <summary> Checks if input is a valid file name.
		/// 
		/// </summary>
		/// <param name="input">the input
		/// 
		/// </param>
		/// <returns> true, if is valid file name
		/// </returns>
		bool isValidFileName(System.String context, System.String input);
		
		/// <summary> Checks whether a file upload has a valid name, path, and content.
		/// 
		/// </summary>
		/// <param name="filepath">the filepath
		/// </param>
		/// <param name="filename">the filename
		/// </param>
		/// <param name="content">the content
		/// 
		/// </param>
		/// <returns> true if the file is safe
		/// </returns>
		bool isValidFileUpload(System.String context, System.String filepath, System.String filename, sbyte[] content);
		
		/// <summary> Validate an HTTP requests by comparing parameters, headers, and cookies to a predefined whitelist of allowed
		/// characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.
		/// 
		/// </summary>
		/// <param name="request">
		/// </param>
		/// <returns>
		/// </returns>
		bool isValidHTTPRequest(System.Web.HttpRequest request);
		
		/// <summary> Checks if input is a valid list item.</summary>
		bool isValidListItem(System.Collections.IList list, System.String value_Renamed);
		
		/// <summary> Checks if input is a valid number.</summary>
		bool isValidNumber(System.String input);
		
		/// <summary> Checks if the supplied set of parameters matches the required parameter set, with no extra and no missing parameters.</summary>
		bool isValidParameterSet(SupportClass.SetSupport required, SupportClass.SetSupport optional);
		
		/// <summary> Checks if input is valid printable ASCII characters.</summary>
		bool isValidPrintable(sbyte[] input);
		
		/// <summary> Checks if input is valid printable ASCII characters.</summary>
		bool isValidPrintable(System.String input);
		
		/// <summary> Checks if input is a valid redirect location.</summary>
		bool isValidRedirectLocation(System.String context, System.String location);
		
		/// <summary> Checks if input is valid safe HTML. Implementors should reference the OWASP AntiSamy project for ideas
		/// on how to do HTML validation in a whitelist way.
		/// </summary>
		bool isValidSafeHTML(System.String context, System.String input);
		
		
		/// <summary> Reads from an input stream until end-of-line or a maximum number of
		/// characters. This method protects against the inherent denial of service
		/// attack in reading until the end of a line. If an attacker doesn't ever
		/// send a newline character, then a normal input stream reader will read
		/// until all memory is exhausted and the platform throws an OutOfMemoryError
		/// and probably terminates.
		/// 
		/// </summary>
		/// <param name="inputStream">the InputStream
		/// </param>
		/// <param name="maxsChar">the maxs char
		/// 
		/// </param>
		/// <returns> the line
		/// 
		/// </returns>
		/// <throws>  ValidationException </throws>
		/// <summary>             the validation exception
		/// </summary>
		// FIXME: ENHANCE timeout too!
		System.String safeReadLine(System.IO.Stream inputStream, int maxsChar);
	}
}