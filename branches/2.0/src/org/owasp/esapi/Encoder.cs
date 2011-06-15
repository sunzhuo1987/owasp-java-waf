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
using EncodingException = org.owasp.esapi.errors.EncodingException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
//UPGRADE_TODO: The type 'sun.text.Normalizer' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Normalizer = sun.text.Normalizer;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IEncoder interface. This implementation takes
	/// a whitelist approach, encoding everything not specifically identified in a
	/// list of "immune" characters. Several methods follow the approach in the <a
	/// href="http://www.microsoft.com/downloads/details.aspx?familyid=efb9c819-53ff-4f82-bfaf-e11625130c25&displaylang=en">Microsoft
	/// AntiXSS Library</a>.
	/// <p>
	/// The canonicalization algorithm is complex, as it has to be able to recognize
	/// encoded characters that might affect downstream interpreters without being
	/// told what encodings are possible. The stream is read one character at a time.
	/// If an encoded character is encountered, it is canonicalized and pushed back
	/// onto the stream. If the next character is encoded, then a intrusion exception
	/// is thrown for the double-encoding which is assumed to be an attack. This assumption is
	/// a bit aggressive as some double-encoded characters may be sent by ordinary users
	/// through cut-and-paste.
	/// <p>
	/// If an encoded character is recognized, but does not parse properly, the response is
	/// to eat the character, stripping it from the input.
	/// <p>
	/// Currently the implementation supports:
	/// <ul><li>HTML Entity Encoding (including non-terminated)</li><li>Percent Encoding</li></ul>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IEncoder">
	/// </seealso>
	public class Encoder : org.owasp.esapi.interfaces.IEncoder
	{
		
		/// <summary>Encoding types </summary>
		public const int NO_ENCODING = 0;
		public const int URL_ENCODING = 1;
		public const int PERCENT_ENCODING = 2;
		public const int ENTITY_ENCODING = 3;
		
		/// <summary>The base64 encoder. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'base64Encoder '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_TODO: Class 'sun.misc.BASE64Encoder' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
		//UPGRADE_TODO: Constructor 'sun.misc.BASE64Encoder.BASE64Encoder' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
		private static readonly BASE64Encoder base64Encoder = new BASE64Encoder();
		
		/// <summary>The base64 decoder. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'base64Decoder '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_TODO: Class 'sun.misc.BASE64Decoder' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
		//UPGRADE_TODO: Constructor 'sun.misc.BASE64Decoder.BASE64Decoder' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
		private static readonly BASE64Decoder base64Decoder = new BASE64Decoder();
		
		/// <summary>The IMMUNE HTML. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_HTML'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_HTML = new char[]{',', '.', '-', '_', ' '};
		
		/// <summary>The IMMUNE HTMLATTR. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_HTMLATTR'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_HTMLATTR = new char[]{',', '.', '-', '_'};
		
		/// <summary>The IMMUNE JAVASCRIPT. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_JAVASCRIPT'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_JAVASCRIPT = new char[]{',', '.', '-', '_', ' '};
		
		/// <summary>The IMMUNE VBSCRIPT. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_VBSCRIPT'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_VBSCRIPT = new char[]{',', '.', '-', '_', ' '};
		
		/// <summary>The IMMUNE XML. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_XML'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_XML = new char[]{',', '.', '-', '_', ' '};
		
		/// <summary>The IMMUNE XMLATTR. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_XMLATTR'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_XMLATTR = new char[]{',', '.', '-', '_'};
		
		/// <summary>The IMMUNE XPATH. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'IMMUNE_XPATH'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		private static readonly char[] IMMUNE_XPATH = new char[]{',', '.', '-', '_', ' '};
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.Encoder'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary>The Constant CHAR_LOWERS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_LOWERS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_LOWERS = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
		
		/// <summary>The Constant CHAR_UPPERS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_UPPERS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_UPPERS = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
		
		/// <summary>The Constant CHAR_DIGITS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_DIGITS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_DIGITS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
		
		/// <summary>The Constant CHAR_SPECIALS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_SPECIALS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_SPECIALS = new char[]{'.', '-', '_', '!', '@', '$', '^', '*', '=', '~', '|', '+', '?'};
		
		/// <summary>The Constant CHAR_LETTERS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_LETTERS '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'CHAR_LETTERS' was moved to static method 'org.owasp.esapi.Encoder'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		internal static readonly char[] CHAR_LETTERS;
		
		/// <summary>The Constant CHAR_ALPHANUMERICS. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_ALPHANUMERICS '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'CHAR_ALPHANUMERICS' was moved to static method 'org.owasp.esapi.Encoder'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		internal static readonly char[] CHAR_ALPHANUMERICS;
		
		// FIXME: ENHANCE make all character sets configurable
		/// <summary> Password character set, is alphanumerics (without l, i, I, o, O, and 0)
		/// selected specials like + (bad for URL encoding, | is like i and 1,
		/// etc...)
		/// </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_PASSWORD_LOWERS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_PASSWORD_LOWERS = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_PASSWORD_UPPERS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_PASSWORD_UPPERS = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_PASSWORD_DIGITS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_PASSWORD_DIGITS = new char[]{'2', '3', '4', '5', '6', '7', '8', '9'};
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_PASSWORD_SPECIALS'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		internal static readonly char[] CHAR_PASSWORD_SPECIALS = new char[]{'_', '.', '!', '@', '$', '*', '=', '-', '?'};
		//UPGRADE_NOTE: Final was removed from the declaration of 'CHAR_PASSWORD_LETTERS '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'CHAR_PASSWORD_LETTERS' was moved to static method 'org.owasp.esapi.Encoder'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		internal static readonly char[] CHAR_PASSWORD_LETTERS;
		
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private static System.Collections.Hashtable characterToEntityMap;
		
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private static System.Collections.Hashtable entityToCharacterMap;
		
		public Encoder()
		{
			System.Array.Sort(Encoder.IMMUNE_HTML);
			System.Array.Sort(Encoder.IMMUNE_HTMLATTR);
			System.Array.Sort(Encoder.IMMUNE_JAVASCRIPT);
			System.Array.Sort(Encoder.IMMUNE_VBSCRIPT);
			System.Array.Sort(Encoder.IMMUNE_XML);
			System.Array.Sort(Encoder.IMMUNE_XMLATTR);
			System.Array.Sort(Encoder.IMMUNE_XPATH);
			System.Array.Sort(Encoder.CHAR_LOWERS);
			System.Array.Sort(Encoder.CHAR_UPPERS);
			System.Array.Sort(Encoder.CHAR_DIGITS);
			System.Array.Sort(Encoder.CHAR_SPECIALS);
			System.Array.Sort(Encoder.CHAR_LETTERS);
			System.Array.Sort(Encoder.CHAR_ALPHANUMERICS);
			System.Array.Sort(Encoder.CHAR_PASSWORD_LOWERS);
			System.Array.Sort(Encoder.CHAR_PASSWORD_UPPERS);
			System.Array.Sort(Encoder.CHAR_PASSWORD_DIGITS);
			System.Array.Sort(Encoder.CHAR_PASSWORD_SPECIALS);
			System.Array.Sort(Encoder.CHAR_PASSWORD_LETTERS);
			initializeMaps();
		}
		
		/// <summary> Simplifies percent-encoded and entity-encoded characters to their
		/// simplest form so that they can be properly validated. Attackers
		/// frequently use encoding schemes to disguise their attacks and bypass
		/// validation routines.
		/// 
		/// Handling multiple encoding schemes simultaneously is difficult, and
		/// requires some special consideration. In particular, the problem of
		/// double-encoding is difficult for parsers, and combining several encoding
		/// schemes in double-encoding makes it even harder. Consider decoding
		/// 
		/// <PRE>
		/// &amp;lt;
		/// </PRE>
		/// 
		/// or
		/// 
		/// <PRE>
		/// %26lt;
		/// </PRE>
		/// 
		/// or
		/// 
		/// <PRE>
		/// &amp;lt;
		/// </PRE>.
		/// 
		/// This implementation disallows ALL double-encoded characters and throws an
		/// IntrusionException when they are detected. Also, named entities that are
		/// not known are simply removed.
		/// 
		/// Note that most data from the browser is likely to be encoded with URL
		/// encoding (FIXME: RFC). The web server will decode the URL and form data
		/// once, so most encoded data received in the application must have been
		/// double-encoded by the attacker. However, some HTTP inputs are not decoded
		/// by the browser, so this routine allows a single level of decoding.
		/// 
		/// </summary>
		/// <throws>  IntrusionException </throws>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.canonicalize(java.lang.String)">
		/// </seealso>
		public virtual System.String canonicalize(System.String input)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			EncodedStringReader reader = new EncodedStringReader(this, input);
			while (reader.hasNext())
			{
				EncodedCharacter c = reader.NextCharacter;
				if (c != null)
				{
					sb.Append(c.Unencoded);
				}
			}
			return sb.ToString();
		}
		
		/// <summary> Normalizes special characters down to ASCII using the Normalizer built
		/// into Java.
		/// 
		/// </summary>
		/// <seealso cref="org.owasp.esapi.interfaces.IValidator.normalize(java.lang.String)">
		/// </seealso>
		public virtual System.String normalize(System.String input)
		{
			// Split any special characters into two parts, the base character and
			// the modifier
			
			System.String separated = Normalizer.normalize(input, Normalizer.DECOMP, 0); // Java 1.4
			// String separated = Normalizer.normalize(input, Form.NFD);   // Java 1.6
			
			// remove any character that is not ASCII
			return separated.replaceAll("[^\\p{ASCII}]", "");
		}
		
		/// <summary> Checks if the character is contained in the provided array of characters.
		/// 
		/// </summary>
		/// <param name="array">the array
		/// </param>
		/// <param name="element">the element
		/// </param>
		/// <returns> true, if is contained
		/// </returns>
		private bool isContained(char[] array, char element)
		{
			for (int i = 0; i < array.Length; i++)
			{
				if (element == array[i])
					return true;
			}
			return false;
			
			// FIXME: ENHANCE Performance enhancement here but character arrays must
			// be sorted, which they're currently not.
			// return( Arrays.binarySearch(array, element) >= 0 );
		}
		
		/// <summary> HTML Entity encode utility method. To avoid double-encoding, this method
		/// logs a warning if HTML entity encoded characters are passed in as input.
		/// Double-encoded characters in the input cause an exception to be thrown.
		/// 
		/// </summary>
		/// <param name="input">the input
		/// </param>
		/// <param name="immune">the immune
		/// </param>
		/// <param name="base">the base
		/// </param>
		/// <returns> the string
		/// </returns>
		private System.String entityEncode(System.String input, char[] base_Renamed, char[] immune)
		{
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			EncodedStringReader reader = new EncodedStringReader(this, input);
			while (reader.hasNext())
			{
				EncodedCharacter c = reader.NextCharacter;
				if (c != null)
				{
					if (isContained(base_Renamed, c.Unencoded) || isContained(immune, c.Unencoded))
					{
						sb.Append(c.Unencoded);
					}
					else
					{
						sb.Append(c.getEncoded(ENTITY_ENCODING));
					}
				}
			}
			return sb.ToString();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForHTML(java.lang.String)
		*/
		public virtual System.String encodeForHTML(System.String input)
		{
			// FIXME: ENHANCE - should this just strip out nonprintables? Why send
			// &#07; to the browser?
			// FIXME: Enhance - Add a configuration for masking **** out SSN and credit
			// card
			
			System.String encoded = entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTML);
			encoded = encoded.replaceAll("\r", "<BR>");
			encoded = encoded.replaceAll("\n", "<BR>");
			return encoded;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForHTMLAttribute(java.lang.String)
		*/
		public virtual System.String encodeForHTMLAttribute(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_HTMLATTR);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForJavaScript(java.lang.String)
		*/
		public virtual System.String encodeForJavascript(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, Encoder.IMMUNE_JAVASCRIPT);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForVisualBasicScript(java.lang.String)
		*/
		public virtual System.String encodeForVBScript(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_VBSCRIPT);
		}
		
		/// <summary> This method is not recommended. The use PreparedStatement is the normal
		/// and preferred approach. However, if for some reason this is impossible,
		/// then this method is provided as a weaker alternative. The best approach
		/// is to make sure any single-quotes are double-quoted. Another possible
		/// approach is to use the {escape} syntax described in the JDBC
		/// specification in section 1.5.6 (see
		/// http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html).
		/// However, this syntax does not work with all drivers, and requires
		/// modification of all queries.
		/// 
		/// </summary>
		/// <param name="input">the input
		/// </param>
		/// <returns> the string
		/// </returns>
		/// <seealso cref="org.owasp.esapi.interfaces.IEncoder.encodeForSQL(java.lang.String)">
		/// </seealso>
		public virtual System.String encodeForSQL(System.String input)
		{
			System.String canonical = canonicalize(input);
			return canonical.replaceAll("'", "''");
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForLDAP(java.lang.String)
		*/
		public virtual System.String encodeForLDAP(System.String input)
		{
			System.String canonical = canonicalize(input);
			
			// FIXME: ENHANCE this is a negative list -- make positive?
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			for (int i = 0; i < canonical.Length; i++)
			{
				char c = canonical[i];
				switch (c)
				{
					
					case '\\': 
						sb.Append("\\5c");
						break;
					
					case '*': 
						sb.Append("\\2a");
						break;
					
					case '(': 
						sb.Append("\\28");
						break;
					
					case ')': 
						sb.Append("\\29");
						break;
					
					case '\u0000': 
						sb.Append("\\00");
						break;
					
					default: 
						sb.Append(c);
						break;
					
				}
			}
			return sb.ToString();
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForDN(java.lang.String)
		*/
		public virtual System.String encodeForDN(System.String input)
		{
			System.String canonical = canonicalize(input);
			
			System.Text.StringBuilder sb = new System.Text.StringBuilder();
			if ((canonical.Length > 0) && ((canonical[0] == ' ') || (canonical[0] == '#')))
			{
				sb.Append('\\'); // add the leading backslash if needed
			}
			for (int i = 0; i < canonical.Length; i++)
			{
				char c = canonical[i];
				switch (c)
				{
					
					case '\\': 
						sb.Append("\\\\");
						break;
					
					case ',': 
						sb.Append("\\,");
						break;
					
					case '+': 
						sb.Append("\\+");
						break;
					
					case '"': 
						sb.Append("\\\"");
						break;
					
					case '<': 
						sb.Append("\\<");
						break;
					
					case '>': 
						sb.Append("\\>");
						break;
					
					case ';': 
						sb.Append("\\;");
						break;
					
					default: 
						sb.Append(c);
						break;
					
				}
			}
			// add the trailing backslash if needed
			if ((canonical.Length > 1) && (canonical[input.Length - 1] == ' '))
			{
				sb.Insert(sb.Length - 1, '\\');
			}
			return sb.ToString();
		}
		
		/// <summary> This implementation encodes almost everything and may overencode. The
		/// difficulty is that XPath has no built in mechanism for escaping
		/// characters. It is possible to use XQuery in a parameterized way to
		/// prevent injection. For more information, refer to <a
		/// href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">this
		/// article</a> which specifies the following list of characters as the most
		/// dangerous: ^&"*';<>(). <a
		/// href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">This
		/// paper</a> suggests disallowing ' and " in queries.
		/// 
		/// </summary>
		/// <param name="input">the input
		/// </param>
		/// <returns> the string
		/// </returns>
		/// <seealso cref="org.owasp.esapi.interfaces.IEncoder.encodeForXPath(java.lang.String)">
		/// </seealso>
		public virtual System.String encodeForXPath(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XPATH);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForXML(java.lang.String)
		*/
		public virtual System.String encodeForXML(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XML);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForXMLAttribute(java.lang.String)
		*/
		public virtual System.String encodeForXMLAttribute(System.String input)
		{
			return entityEncode(input, Encoder.CHAR_ALPHANUMERICS, IMMUNE_XMLATTR);
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForURL(java.lang.String)
		*/
		public virtual System.String encodeForURL(System.String input)
		{
			System.String canonical = canonicalize(input);
			
			try
			{
				return URLEncoder.encode(canonical, ESAPI.securityConfiguration().CharacterEncoding);
			}
			catch (System.IO.IOException ex)
			{
				throw new EncodingException("Encoding failure", "Encoding not supported", ex);
			}
			catch (System.Exception e)
			{
				throw new EncodingException("Encoding failure", "Problem URL decoding input", e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#decodeFromURL(java.lang.String)
		*/
		public virtual System.String decodeFromURL(System.String input)
		{
			System.String canonical = canonicalize(input);
			try
			{
				return URLDecoder.decode(canonical, ESAPI.securityConfiguration().CharacterEncoding);
			}
			catch (System.IO.IOException ex)
			{
				throw new EncodingException("Decoding failed", "Encoding not supported", ex);
			}
			catch (System.Exception e)
			{
				throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#encodeForBase64(byte[])
		*/
		public virtual System.String encodeForBase64(sbyte[] input, bool wrap)
		{
			//UPGRADE_TODO: Method 'sun.misc.CharacterEncoder.encode' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
			System.String b64 = base64Encoder.encode(input);
			// remove line-feeds and carriage-returns inserted in output
			if (!wrap)
			{
				b64 = b64.replaceAll("\r", "").replaceAll("\n", "");
			}
			return b64;
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncoder#decodeFromBase64(java.lang.String)
		*/
		public virtual sbyte[] decodeFromBase64(System.String input)
		{
			//UPGRADE_TODO: Method 'sun.misc.CharacterDecoder.decodeBuffer' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1095'"
			return base64Decoder.decodeBuffer(input);
		}
		
		// FIXME: ENHANCE - change formatting here to more like -- "quot", "34", //
		// quotation mark
		private void  initializeMaps()
		{
			System.String[] entityNames = new System.String[]{"quot", "amp", "lt", "gt", "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf", "laquo", "not", "shy", "reg", "macr", "deg", "plusmn", "sup2", "sup3", "acute", "micro", "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14", "frac12", "frac34", "iquest", "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig", "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml", "ETH", "Ntilde", "Ograve", "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml", "Yacute", "THORN", "szlig", "agrave", "aacute", "acirc", "atilde", "auml", "aring", "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave", "iacute", "icirc", "iuml", "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml", "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml", "OElig", "oelig", "Scaron", "scaron", "Yuml", "fnof", "circ", "tilde", "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega", "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigmaf", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega", "thetasym", "upsih", "piv", "ensp", "emsp", "thinsp", "zwnj", "zwj", "lrm", "rlm", "ndash", "mdash", "lsquo", "rsquo", "sbquo", "ldquo", "rdquo", "bdquo", "dagger", "Dagger", "bull", "hellip", "permil", "prime", "Prime", "lsaquo", "rsaquo", "oline", "frasl", "euro", "image", "weierp", "real", "trade", "alefsym", "larr", "uarr", "rarr", "darr", "harr", "crarr", "lArr", "uArr", "rArr", "dArr", "hArr", "forall", "part", "exist", "empty", "nabla", "isin", "notin", "ni", "prod", "sum", "minus", "lowast", "radic", "prop", "infin", "ang", "and", "or", "cap", "cup", "int", "there4", "sim", "cong", "asymp", "ne", 
				"equiv", "le", "ge", "sub", "sup", "nsub", "sube", "supe", "oplus", "otimes", "perp", "sdot", "lceil", "rceil", "lfloor", "rfloor", "lang", "rang", "loz", "spades", "clubs", "hearts", "diams"};
			
			char[] entityValues = new char[]{(char) (34), (char) (38), (char) (60), (char) (62), (char) (160), (char) (161), (char) (162), (char) (163), (char) (164), (char) (165), (char) (166), (char) (167), (char) (168), (char) (169), (char) (170), (char) (171), (char) (172), (char) (173), (char) (174), (char) (175), (char) (176), (char) (177), (char) (178), (char) (179), (char) (180), (char) (181), (char) (182), (char) (183), (char) (184), (char) (185), (char) (186), (char) (187), (char) (188), (char) (189), (char) (190), (char) (191), (char) (192), (char) (193), (char) (194), (char) (195), (char) (196), (char) (197), (char) (198), (char) (199), (char) (200), (char) (201), (char) (202), (char) (203), (char) (204), (char) (205), (char) (206), (char) (207), (char) (208), (char) (209), (char) (210), (char) (211), (char) (212), (char) (213), (char) (214), (char) (215), (char) (216), (char) (217), (char) (218), (char) (219), (char) (220), (char) (221), (char) (222), (char) (223), (char) (224), (char) (225), (char) (226), (char) (227), (char) (228), (char) (229), (char) (230), (char) (231), (char) (232), (char) (233), (char) (234), (char) (235), (char) (236), (char) (237), (char) (238), (char) (239), (char) (240), (char) (241), (char) (242), (char) (243), (char) (244), (char) (245), (char) (246), (char) (247), (char) (248), (char) (249), (char) (250), (char) (251), (char) (252), (char) (253), (char) (254), (char) (255), (char) (338), (char) (339), (char) (352), (char) (353), (char) (376), (char) (402), (char) (710), (char) (732), (char) (913), (char) (914), (char) (915), (char) (916), (char) (917), (char) (918), (char) (919), (char) (920), (char) (921), (char) (922), (char) (923), (char) (924), (char) (925), (char) (926), (char) (927), (char) (928), (char) (929), (char) (931), (char) (932), (char) (933), (char) (934), (char) (935), (char) (936), (char) (937), (char) (945), (char) (946), (char) (947), (char) (948), (char) (949), (char) (950), (char) (951), (char) (952), (char) (953), (char) (954), (char) (955), 
				(char) (956), (char) (957), (char) (958), (char) (959), (char) (960), (char) (961), (char) (962), (char) (963), (char) (964), (char) (965), (char) (966), (char) (967), (char) (968), (char) (969), (char) (977), (char) (978), (char) (982), (char) (8194), (char) (8195), (char) (8201), (char) (8204), (char) (8205), (char) (8206), (char) (8207), (char) (8211), (char) (8212), (char) (8216), (char) (8217), (char) (8218), (char) (8220), (char) (8221), (char) (8222), (char) (8224), (char) (8225), (char) (8226), (char) (8230), (char) (8240), (char) (8242), (char) (8243), (char) (8249), (char) (8250), (char) (8254), (char) (8260), (char) (8364), (char) (8465), (char) (8472), (char) (8476), (char) (8482), (char) (8501), (char) (8592), (char) (8593), (char) (8594), (char) (8595), (char) (8596), (char) (8629), (char) (8656), (char) (8657), (char) (8658), (char) (8659), (char) (8660), (char) (8704), (char) (8706), (char) (8707), (char) (8709), (char) (8711), (char) (8712), (char) (8713), (char) (8715), (char) (8719), (char) (8721), (char) (8722), (char) (8727), (char) (8730), (char) (8733), (char) (8734), (char) (8736), (char) (8743), (char) (8744), (char) (8745), (char) (8746), (char) (8747), (char) (8756), (char) (8764), (char) (8773), (char) (8776), (char) (8800), (char) (8801), (char) (8804), (char) (8805), (char) (8834), (char) (8835), (char) (8836), (char) (8838), (char) (8839), (char) (8853), (char) (8855), (char) (8869), (char) (8901), (char) (8968), (char) (8969), (char) (8970), (char) (8971), (char) (9001), (char) (9002), (char) (9674), (char) (9824), (char) (9827), (char) (9829), (char) (9830)};
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			characterToEntityMap = new System.Collections.Hashtable(entityNames.Length);
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			entityToCharacterMap = new System.Collections.Hashtable(entityValues.Length);
			for (int i = 0; i < entityNames.Length; i++)
			{
				System.String e = entityNames[i];
				System.Char c = entityValues[i];
				entityToCharacterMap[e] = c;
				characterToEntityMap[c] = e;
			}
		}
		
		[STAThread]
		public static void  Main(System.String[] args)
		{
			// Encoder encoder = new Encoder();
			// try { System.out.println( ">>" + encoder.encodeForHTML("test <>
			// test") ); } catch( Exception e1 ) { System.out.println(" !" +
			// e1.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test %41 %42
			// test") ); } catch( Exception e2 ) { System.out.println(" !" +
			// e2.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test %26%42
			// test") ); } catch( Exception e2 ) { System.out.println(" !" +
			// e2.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test %26amp;
			// test") ); } catch( Exception e3 ) { System.out.println(" !" +
			// e3.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test &#38;
			// test") ); } catch( Exception e4 ) { System.out.println(" !" +
			// e4.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test
			// &#38;amp; test") ); } catch( Exception e5 ) { System.out.println(" !"
			// + e5.getMessage() ); }
			// try { System.out.println( ">>" + encoder.encodeForHTML("test &#ridi;
			// test") ); } catch( Exception e6 ) { e6.printStackTrace() ; }
			//try {
			//	System.out.println(">>" + encoder.encodeForHTML("test &#01;&#02;&#03;&#04; test"));
			//} catch (Exception e7) {
			//	System.out.println("   !" + e7.getMessage());
			//}
		}
		
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'EncodedStringReader' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		private class EncodedStringReader
		{
			private void  InitBlock(Encoder enclosingInstance)
			{
				this.enclosingInstance = enclosingInstance;
			}
			private Encoder enclosingInstance;
			virtual public EncodedCharacter NextCharacter
			{
				get
				{
					
					// get the current character and move past it
					testCharacter = nextCharacter;
					EncodedCharacter c = null;
					c = peekNextCharacter(input[nextCharacter]);
					// System.out.println( nextCharacter + ":" + (int)c.getUnencoded() +
					// " -> " + testCharacter );
					nextCharacter = testCharacter;
					if (c == null)
						return null;
					
					// if the current character is encoded, check for double-encoded
					// characters
					if (c.isEncoded())
					{
						testCharacter--;
						EncodedCharacter next = peekNextCharacter(c.Unencoded);
						if (next != null)
						{
							if (next.isEncoded())
							{
								throw new IntrusionException("Validation error", "Input contains double encoded characters.");
							}
							else
							{
								// System.out.println("Not double-encoded");
							}
						}
					}
					return c;
				}
				
			}
			public Encoder Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			
			internal System.String input = null;
			internal int nextCharacter = 0;
			internal int testCharacter = 0;
			
			public EncodedStringReader(Encoder enclosingInstance, System.String input)
			{
				InitBlock(enclosingInstance);
				// System.out.println( "***" + input );
				if (input == null)
				{
					this.input = "";
				}
				else
				{
					this.input = input;
				}
			}
			
			public virtual bool hasNext()
			{
				return nextCharacter < input.Length;
			}
			
			private EncodedCharacter peekNextCharacter(char currentCharacter)
			{
				// if we're on the last character
				if (testCharacter == input.Length - 1)
				{
					testCharacter++;
					return new EncodedCharacter(enclosingInstance, currentCharacter);
				}
				else if (currentCharacter == '&')
				{
					// if parsing an entity returns null - then we should skip it by
					// returning null here
					EncodedCharacter encoded = parseEntity(input, testCharacter);
					return encoded;
				}
				else if (currentCharacter == '%')
				{
					// if parsing a % encoded character returns null, then just
					// return the % and keep going
					EncodedCharacter encoded = parsePercent(input, testCharacter);
					if (encoded != null)
					{
						return encoded;
					}
					// FIXME: AAA add UTF-7 decoding
					// FIXME: others?
				}
				testCharacter++;
				return new EncodedCharacter(enclosingInstance, currentCharacter);
			}
			
			// return a character or null if no good character can be parsed.
			public virtual EncodedCharacter parsePercent(System.String s, int startIndex)
			{
				// FIXME: AAA check if these can be longer than 2 characters?
				// consume as many as possible?
				System.String possible = s.Substring(startIndex + 1, (startIndex + 3) - (startIndex + 1));
				try
				{
					//UPGRADE_TODO: Method 'java.lang.Integer.parseInt' was converted to 'System.Convert.ToInt32' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073'"
					int c = System.Convert.ToInt32(possible, 16);
					testCharacter += 3;
					return new EncodedCharacter(enclosingInstance, "%" + possible, (char) c, org.owasp.esapi.Encoder.PERCENT_ENCODING);
				}
				catch (System.FormatException e)
				{
					// System.out.println("Found % but there was no encoded character following it");
					return null;
				}
			}
			
			/// <summary> Return a character or null if no good character can be parsed. Badly
			/// formed characters that simply can't be parsed are dropped, such as
			/// &#ridi; for which there is no reasonable translation. Characters that
			/// aren't terminated by a semicolon are also dropped. Note that this is
			/// legal html
			/// 
			/// <PRE>
			/// &lt;body onload=&quot;&amp;#x61ler&amp;#116('xss body')&quot;&gt;
			/// </PRE>
			/// </summary>
			public virtual EncodedCharacter parseEntity(System.String s, int startIndex)
			{
				// FIXME: AAA - figure out how to handle non-semicolon terminated
				// characters
				//UPGRADE_WARNING: Method 'java.lang.String.indexOf' was converted to 'System.String.IndexOf' which may throw an exception. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1101'"
				int semiIndex = input.IndexOf(";", startIndex + 1);
				if (semiIndex != - 1)
				{
					if (semiIndex - startIndex <= 8)
					{
						System.String possible = input.Substring(startIndex + 1, (semiIndex) - (startIndex + 1)).ToLower();
						// System.out.println( " " + possible + " -> " +
						// testCharacter );
						//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
						System.Char entity = (System.Char) org.owasp.esapi.Encoder.entityToCharacterMap[possible];
						//UPGRADE_TODO: The 'System.Char' structure does not have an equivalent to NULL. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1291'"
						if (entity != null)
						{
							testCharacter += possible.Length + 2;
							return new EncodedCharacter(enclosingInstance, "&" + possible + ";", entity, org.owasp.esapi.Encoder.ENTITY_ENCODING);
						}
						else if (possible[0] == '#')
						{
							// advance past this either way
							testCharacter += possible.Length + 2;
							try
							{
								// FIXME: Enhance - consider supporting #x encoding
								int c = System.Int32.Parse(possible.Substring(1));
								return new EncodedCharacter(enclosingInstance, "&#" + (char) c + ";", (char) c, org.owasp.esapi.Encoder.ENTITY_ENCODING);
							}
							catch (System.FormatException e)
							{
								// invalid character - return null
								org.owasp.esapi.Encoder.logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Invalid numeric entity encoding &" + possible + ";");
							}
						}
					}
				}
				// System.out.println("Found & but there was no entity following it");
				testCharacter++;
				return new EncodedCharacter(enclosingInstance, "&", '&', org.owasp.esapi.Encoder.NO_ENCODING);
			}
		}
		
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'EncodedCharacter' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		//UPGRADE_NOTE: The access modifier for this class or class field has been changed in order to prevent compilation errors due to the visibility level. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1296'"
		public class EncodedCharacter
		{
			private void  InitBlock(Encoder enclosingInstance)
			{
				this.enclosingInstance = enclosingInstance;
			}
			private Encoder enclosingInstance;
			virtual public char Unencoded
			{
				get
				{
					return character;
				}
				
			}
			public Encoder Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			
			internal System.String raw = ""; // the core of the encoded representation (without
			// the prefix or suffix)
			internal char character = (char) (0);
			internal int originalEncoding;
			
			public EncodedCharacter(Encoder enclosingInstance, char character)
			{
				InitBlock(enclosingInstance);
				this.raw = "" + character;
				this.character = character;
			}
			
			public virtual bool isEncoded()
			{
				return (raw.Length != 1);
			}
			
			public EncodedCharacter(Encoder enclosingInstance, System.String raw, char character, int originalEncoding)
			{
				InitBlock(enclosingInstance);
				this.raw = raw;
				this.character = character;
				this.originalEncoding = originalEncoding;
			}
			
			public virtual System.String getEncoded(int encoding)
			{
				switch (encoding)
				{
					
					case Encoder.NO_ENCODING: 
						return "" + character;
					
					case Encoder.URL_ENCODING: 
						// FIXME: look up rules
						if (System.Char.IsWhiteSpace(character))
							return "+";
						if (System.Char.IsLetterOrDigit(character))
							return "" + character;
						return "%" + (int) character;
					
					case Encoder.PERCENT_ENCODING: 
						return "%" + (int) character;
					
					case Encoder.ENTITY_ENCODING: 
						//UPGRADE_TODO: Method 'java.util.HashMap.get' was converted to 'System.Collections.Hashtable.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMapget_javalangObject'"
						System.String entityName = (System.String) org.owasp.esapi.Encoder.characterToEntityMap[character];
						if (entityName != null)
							return "&" + entityName + ";";
						return "&#" + (int) character + ";";
					
					default: 
						return null;
					
				}
			}
		}
		static Encoder()
		{
			logger = Logger.getLogger("ESAPI", "Encoder");
			CHAR_LETTERS = Randomizer.union(CHAR_LOWERS, CHAR_UPPERS);
			CHAR_ALPHANUMERICS = Randomizer.union(CHAR_LETTERS, CHAR_DIGITS);
			CHAR_PASSWORD_LETTERS = Randomizer.union(CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS);
		}
	}
}