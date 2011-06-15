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
//UPGRADE_TODO: The type 'java.util.regex.Pattern' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Pattern = System.Text.RegularExpressions.Regex;
using EncodingException = org.owasp.esapi.errors.EncodingException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationAvailabilityException = org.owasp.esapi.errors.ValidationAvailabilityException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
namespace org.owasp.esapi
{
	//import org.owasp.validator.html.AntiSamy;
	//import org.owasp.validator.html.CleanResults;
	//import org.owasp.validator.html.PolicyException;
	//import org.owasp.validator.html.ScanException;
	
	/// <summary> Reference implementation of the IValidator interface. This implementation
	/// relies on the ESAPI Encoder, Java Pattern (regex), Date,
	/// and several other classes to provide basic validation functions. This library
	/// has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
	/// characters, even in multiple encoding schemes, such as <PRE>&amp;lt;</PRE> or
	/// <PRE>%26lt;<PRE> or even <PRE>%25%26lt;</PRE> are disallowed.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IValidator">
	/// </seealso>
	public class Validator : org.owasp.esapi.interfaces.IValidator
	{
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Validator'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		
		public Validator()
		{
		}
		
		/// <summary> Validates data received from the browser and returns a safe version. Only
		/// URL encoding is supported. Double encoding is treated as an attack.
		/// 
		/// </summary>
		/// <param name="name">
		/// </param>
		/// <param name="type">
		/// </param>
		/// <param name="input">
		/// </param>
		/// <returns>
		/// </returns>
		/// <throws>  ValidationException </throws>
		public virtual System.String getValidDataFromBrowser(System.String context, System.String type, System.String input)
		{
			try
			{
				System.String canonical = ESAPI.encoder().canonicalize(input);
				
				if (input == null)
					throw new ValidationException("Bad input", type + " (" + context + ") input to validate was null");
				
				if (type == null)
					throw new ValidationException("Bad input", type + " (" + context + ") type to validate against was null");
				
				Pattern p = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern(type);
				if (p == null)
					throw new ValidationException("Bad input", type + " (" + context + ") type to validate against not configured in ESAPI.properties");
				
				if (!p.matcher(canonical).matches())
					throw new ValidationException("Bad input", type + " (" + context + "=" + input + ") input did not match type definition " + p);
				
				// if everything passed, then return the canonical form
				return canonical;
			}
			catch (EncodingException ee)
			{
				throw new ValidationException("Internal error", "Error canonicalizing user input", ee);
			}
		}
		
		/// <summary> Returns true if data received from browser is valid. Only URL encoding is
		/// supported. Double encoding is treated as an attack.
		/// 
		/// </summary>
		/// <param name="name">
		/// </param>
		/// <param name="type">
		/// </param>
		/// <param name="value">
		/// </param>
		/// <returns>
		/// </returns>
		public virtual bool isValidDataFromBrowser(System.String context, System.String type, System.String value_Renamed)
		{
			try
			{
				getValidDataFromBrowser(context, type, value_Renamed);
				return true;
			}
			catch (System.Exception e)
			{
				return false;
			}
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#getValidDate(java.lang.String)
		*/
		public virtual System.DateTime getValidDate(System.String context, System.String input, System.Globalization.DateTimeFormatInfo format)
		{
			try
			{
				System.DateTime date = System.DateTime.Parse(input, format);
				return date;
			}
			catch (System.Exception e)
			{
				throw new ValidationException("Invalid date", "Problem parsing date (" + context + "=" + input + ") ", e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidCreditCard(java.lang.String)
		*/
		public virtual bool isValidCreditCard(System.String context, System.String value_Renamed)
		{
			try
			{
				System.String canonical = getValidDataFromBrowser(context, "CreditCard", value_Renamed);
				
				// perform Luhn algorithm checking
				System.Text.StringBuilder digitsOnly = new System.Text.StringBuilder();
				char c;
				for (int i = 0; i < canonical.Length; i++)
				{
					c = canonical[i];
					if (System.Char.IsDigit(c))
					{
						digitsOnly.Append(c);
					}
				}
				
				int sum = 0;
				int digit = 0;
				int addend = 0;
				bool timesTwo = false;
				
				for (int i = digitsOnly.Length - 1; i >= 0; i--)
				{
					digit = System.Int32.Parse(digitsOnly.ToString(i, i + 1));
					if (timesTwo)
					{
						addend = digit * 2;
						if (addend > 9)
						{
							addend -= 9;
						}
					}
					else
					{
						addend = digit;
					}
					sum += addend;
					timesTwo = !timesTwo;
				}
				
				int modulus = sum % 10;
				return modulus == 0;
			}
			catch (System.Exception e)
			{
				return false;
			}
		}
		
		/// <summary> Returns true if the directory path (not including a filename) is valid.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.isValidDirectoryPath(java.lang.String)">
		/// </seealso>
		public virtual bool isValidDirectoryPath(System.String context, System.String dirpath)
		{
			try
			{
				System.String canonical = ESAPI.encoder().canonicalize(dirpath);
				
				// do basic validation
				Pattern directoryNamePattern = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("DirectoryName");
				if (!directoryNamePattern.matcher(canonical).matches())
				{
					new ValidationException("Invalid directory name", "Attempt to use a directory name (" + canonical + ") that violates the global rule in ESAPI.properties (" + directoryNamePattern.pattern() + ")");
					return false;
				}
				
				// get the canonical path without the drive letter if present
				System.String cpath = new System.IO.FileInfo(canonical).FullName.replaceAll("\\\\", "/");
				System.String temp = cpath.ToLower();
				if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
				{
					cpath = cpath.Substring(2);
				}
				
				// prepare the input without the drive letter if present
				System.String escaped = canonical.replaceAll("\\\\", "/");
				temp = escaped.ToLower();
				if (temp.Length >= 2 && temp[0] >= 'a' && temp[0] <= 'z' && temp[1] == ':')
				{
					escaped = escaped.Substring(2);
				}
				
				// the path is valid if the input matches the canonical path
				return escaped.Equals(cpath.ToLower());
			}
			catch (System.IO.IOException e)
			{
				return false;
			}
			catch (EncodingException ee)
			{
				throw new IntrusionException("Invalid directory", "Exception during directory validation", ee);
			}
		}
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidFileUpload(java.lang.String,java.lang.String,byte[]
		*      content)
		*/
		public virtual bool isValidFileContent(System.String context, sbyte[] content)
		{
			// FIXME: AAA - temporary - what makes file content valid? Maybe need a parameter here?
			long length = ESAPI.securityConfiguration().AllowedFileUploadSize;
			return (content.Length < length);
			// FIXME: log something?
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidFileName(java.lang.String)
		*/
		
		//FIXME: AAA - getValidFileName eliminates %00 and other injections.
		//FIXME: AAA - this method should check for %00 injection too
		public virtual bool isValidFileName(System.String context, System.String input)
		{
			if (input == null || input.Length == 0)
				return false;
			
			// detect path manipulation
			try
			{
				System.String canonical = ESAPI.encoder().canonicalize(input);
				
				// do basic validation
				Pattern fileNamePattern = ((SecurityConfiguration) ESAPI.securityConfiguration()).getValidationPattern("FileName");
				if (!fileNamePattern.matcher(canonical).matches())
				{
					new ValidationException("Invalid filename", "Attempt to use a filename (" + canonical + ") that violates the global rule in ESAPI.properties (" + fileNamePattern.pattern() + ")");
					return false;
				}
				
				System.IO.FileInfo f = new System.IO.FileInfo(canonical);
				System.String c = f.FullName;
				System.String cpath = c.Substring(c.LastIndexOf(System.IO.Path.DirectorySeparatorChar.ToString()) + 1);
				if (!input.Equals(cpath))
				{
					new ValidationException("Invalid filename", "Invalid filename (" + canonical + ") doesn't match canonical path (" + cpath + ") and could be an injection attack");
					return false;
				}
			}
			catch (System.IO.IOException e)
			{
				throw new IntrusionException("Invalid filename", "Exception during filename validation", e);
			}
			catch (EncodingException ee)
			{
				throw new IntrusionException("Invalid filename", "Exception during filename validation", ee);
			}
			
			// verify extensions
			System.Collections.IList extensions = ESAPI.securityConfiguration().AllowedFileExtensions;
			System.Collections.IEnumerator i = extensions.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String ext = (System.String) i.Current;
				if (input.ToLower().EndsWith(ext.ToLower()))
				{
					return true;
				}
			}
			return false;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidFileUpload(java.lang.String,
		*      java.lang.String, byte[])
		*/
		public virtual bool isValidFileUpload(System.String context, System.String filepath, System.String filename, sbyte[] content)
		{
			return isValidDirectoryPath(context, filepath) && isValidFileName(context, filename) && isValidFileContent(context, content);
		}
		
		/// <summary> Validate the parameters, cookies, and headers in an HTTP request against
		/// specific regular expressions defined in the SecurityConfiguration. Note
		/// that isValidDataFromBrowser uses the Encoder.canonicalize() method to ensure
		/// that all encoded characters are reduced to their simplest form, and that any
		/// double-encoded characters are detected and throw an exception.
		/// </summary>
		public virtual bool isValidHTTPRequest(System.Web.HttpRequest request)
		{
			bool result = true;
			
			//UPGRADE_TODO: Method 'java.util.Map.entrySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapentrySet'"
			//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getParameterMap' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetParameterMap'"
			System.Collections.IEnumerator i1 = new SupportClass.HashSetSupport(request.getParameterMap()).GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i1.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.Collections.DictionaryEntry entry = (System.Collections.DictionaryEntry) i1.Current;
				System.String name = (System.String) entry.Key;
				if (!isValidDataFromBrowser("http", "HTTPParameterName", name))
				{
					// logger.logCritical(Logger.SECURITY, "Parameter name (" + name + ") violates global rule" );
					result = false;
				}
				
				System.String[] values = (System.String[]) entry.Value;
				//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
				System.Collections.IEnumerator i3 = new System.Collections.ArrayList(values).GetEnumerator();
				// FIXME:Enhance - consider throwing an exception if there are multiple parameters with the same name
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i3.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String value_Renamed = (System.String) i3.Current;
					if (!isValidDataFromBrowser(name, "HTTPParameterValue", value_Renamed))
					{
						// logger.logCritical(Logger.SECURITY, "Parameter value (" + name + "=" + value + ") violates global rule" );
						result = false;
					}
				}
			}
			
			if (SupportClass.GetCookies(request) != null)
			{
				//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
				System.Collections.IEnumerator i2 = new System.Collections.ArrayList(SupportClass.GetCookies(request)).GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i2.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.Web.HttpCookie cookie = (System.Web.HttpCookie) i2.Current;
					System.String name = cookie.Name;
					if (!isValidDataFromBrowser("http", "HTTPCookieName", name))
					{
						// logger.logCritical(Logger.SECURITY, "Cookie name (" + name + ") violates global rule" );
						result = false;
					}
					
					System.String value_Renamed = cookie.Value;
					if (!isValidDataFromBrowser(name, "HTTPCookieValue", value_Renamed))
					{
						// logger.logCritical(Logger.SECURITY, "Cookie value (" + name + "=" + value + ") violates global rule" );
						result = false;
					}
				}
			}
			
			System.Collections.IEnumerator e = request.Headers.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Enumeration.hasMoreElements' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationhasMoreElements'"
			while (e.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Enumeration.nextElement' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationnextElement'"
				System.String name = (System.String) e.Current;
				if (name != null && !name.ToUpper().Equals("Cookie".ToUpper()))
				{
					if (!isValidDataFromBrowser("http", "HTTPHeaderName", name))
					{
						// logger.logCritical(Logger.SECURITY, "Header name (" + name + ") violates global rule" );
						result = false;
					}
					
					System.Collections.IEnumerator e2 = SupportClass.GetHeaders(request, name);
					//UPGRADE_TODO: Method 'java.util.Enumeration.hasMoreElements' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationhasMoreElements'"
					while (e2.MoveNext())
					{
						//UPGRADE_TODO: Method 'java.util.Enumeration.nextElement' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilEnumerationnextElement'"
						System.String value_Renamed = (System.String) e2.Current;
						if (!isValidDataFromBrowser(name, "HTTPHeaderValue", value_Renamed))
						{
							// logger.logCritical(Logger.SECURITY, "Header value (" + name + "=" + value + ") violates global rule" );
							result = false;
						}
					}
				}
			}
			return result;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidListItem(java.util.List,
		*      java.lang.String)
		*/
		public virtual bool isValidListItem(System.Collections.IList list, System.String value_Renamed)
		{
			return list.Contains(value_Renamed);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidNumber(java.lang.String)
		*/
		public virtual bool isValidNumber(System.String input)
		{
			try
			{
				double d = System.Double.Parse(input);
				return (!System.Double.IsInfinity(d) && !System.Double.IsNaN(d));
			}
			catch (System.FormatException e)
			{
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidParameterSet(java.util.Set,
		*      java.util.Set, java.util.Set)
		*/
		public virtual bool isValidParameterSet(SupportClass.SetSupport requiredNames, SupportClass.SetSupport optionalNames)
		{
			System.Web.HttpRequest request = ((Authenticator) ESAPI.authenticator()).CurrentRequest;
			//UPGRADE_TODO: Method 'java.util.Map.keySet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilMapkeySet'"
			//UPGRADE_ISSUE: Method 'javax.servlet.ServletRequest.getParameterMap' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javaxservletServletRequestgetParameterMap'"
			SupportClass.SetSupport actualNames = new SupportClass.HashSetSupport(request.getParameterMap().Keys);
			
			// verify ALL required parameters are present
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport missing = new SupportClass.HashSetSupport(requiredNames);
			SupportClass.ICollectionSupport.RemoveAll(missing, actualNames);
			if (missing.Count > 0)
			{
				return false;
			}
			
			// verify ONLY optional + required parameters are present
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			SupportClass.SetSupport extra = new SupportClass.HashSetSupport(actualNames);
			SupportClass.ICollectionSupport.RemoveAll(extra, requiredNames);
			SupportClass.ICollectionSupport.RemoveAll(extra, optionalNames);
			if (extra.Count > 0)
			{
				return false;
			}
			return true;
		}
		
		/// <summary> Checks that all bytes are valid ASCII characters (between 33 and 126
		/// inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII. (non-Javadoc)
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.isValidASCIIFileContent(byte[])">
		/// </seealso>
		public virtual bool isValidPrintable(sbyte[] input)
		{
			for (int i = 0; i < input.Length; i++)
			{
				if (input[i] < 33 || input[i] > 126)
					return false;
			}
			return true;
		}
		
		/*
		* (non-Javadoc)
		* @see org.owasp.esapi.interfaces.IValidator#isValidPrintable(java.lang.String)
		*/
		public virtual bool isValidPrintable(System.String input)
		{
			try
			{
				System.String canonical = ESAPI.encoder().canonicalize(input);
				return isValidPrintable(SupportClass.ToSByteArray(SupportClass.ToByteArray(canonical)));
			}
			catch (EncodingException ee)
			{
				logger.logError(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Could not canonicalize user input", ee);
				return false;
			}
		}
		
		/// <summary> (non-Javadoc).
		/// 
		/// </summary>
		/// <param name="location">the location
		/// </param>
		/// <returns> true, if is valid redirect location
		/// </returns>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.isValidRedirectLocation(String">
		/// location)
		/// </seealso>
		public virtual bool isValidRedirectLocation(System.String context, System.String location)
		{
			// FIXME: ENHANCE - it's too hard to put valid locations in as regex
			return ESAPI.validator().isValidDataFromBrowser(context, "Redirect", location);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#isValidSafeHTML(java.lang.String)
		*/
		public virtual bool isValidSafeHTML(System.String name, System.String input)
		{
			try
			{
				System.String canonical = ESAPI.encoder().canonicalize(input);
				// FIXME: AAA this is just a simple blacklist test - will use Anti-SAMY
				return !(canonical.IndexOf("<scri") > - 1) && !(canonical.IndexOf("onload") > - 1);
			}
			catch (EncodingException ee)
			{
				throw new IntrusionException("Invalid input", "EncodingException during HTML validation", ee);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IValidator#getValidSafeHTML(java.lang.String)
		*/
		public virtual System.String getValidSafeHTML(System.String context, System.String input)
		{
			throw new System.NotSupportedException();
			/**
			AntiSamy as = new AntiSamy();
			try {
			CleanResults test = as.scan(input);
			// OutputFormat format = new OutputFormat(test.getCleanXMLDocumentFragment().getOwnerDocument());
			// format.setLineWidth(65);
			// format.setIndenting(true);
			// format.setIndent(2);
			// format.setEncoding(AntiSamyDOMScanner.ENCODING_ALGORITHM);
			return(test.getCleanHTML().trim());
			} catch (ScanException e) {
			throw new ValidationException( "Invalid HTML", "Problem parsing HTML (" + context + "=" + input + ") ",e );
			} catch (PolicyException e) {
			throw new ValidationException( "Invalid HTML", "HTML violates policy (" + context + "=" + input + ") ",e );
			}
			**/
		}
		
		
		/// <summary> This implementation reads until a newline or the specified number of
		/// characters.
		/// 
		/// </summary>
		/// <param name="in">the in
		/// </param>
		/// <param name="max">the max
		/// </param>
		/// <returns> the string
		/// </returns>
		/// <throws>  ValidationException </throws>
		/// <summary>             the validation exception
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.safeReadLine(java.io.InputStream,">
		/// int)
		/// </seealso>
		public virtual System.String safeReadLine(System.IO.Stream in_Renamed, int max)
		{
			if (max <= 0)
				throw new ValidationAvailabilityException("Invalid input", "Must read a positive number of bytes from the stream");
			
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			int count = 0;
			int c;
			
			// FIXME: AAA - verify this method's behavior exactly matches BufferedReader.readLine()
			// so it can be used as a drop in replacement.
			try
			{
				while (true)
				{
					c = in_Renamed.ReadByte();
					if (c == - 1)
					{
						if (sb.Length == 0)
							return null;
						break;
					}
					if (c == '\n' || c == '\r')
						break;
					count++;
					if (count > max)
					{
						throw new ValidationAvailabilityException("Invalid input", "Read more than maximum characters allowed (" + max + ")");
					}
					sb.Append((char) c);
				}
				return sb.ToString();
			}
			catch (System.IO.IOException e)
			{
				throw new ValidationAvailabilityException("Invalid input", "Problem reading from input stream", e);
			}
		}
		static Validator()
		{
			logger = Logger.getLogger("ESAPI", "Validator");
		}
	}
}