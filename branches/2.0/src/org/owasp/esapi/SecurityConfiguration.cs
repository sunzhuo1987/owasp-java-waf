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
//UPGRADE_TODO: The type 'java.util.logging.Level' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Level = java.util.logging.Level;
//UPGRADE_TODO: The type 'java.util.regex.Pattern' could not be found. If it was not included in the conversion, there may be compiler issues. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1262'"
using Pattern = java.util.regex.Pattern;
using ISecurityConfiguration = org.owasp.esapi.interfaces.ISecurityConfiguration;
namespace org.owasp.esapi
{
	
	/// <summary> The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the
	/// Configuration is critically important to getting the ESAPI working properly. You must set a system property before
	/// invoking any part of the ESAPI. Here is how to do it:
	/// 
	/// <PRE>
	/// 
	/// java -Dorg.owasp.esapi.resources="C:\temp\resources"
	/// 
	/// </PRE>
	/// 
	/// You may have to add this to the batch script that starts your web server. For example, in the "catalina" script that
	/// starts Tomcat, you can set the JAVA_OPTS variable to the -D string above. Once the Configuration is initialized with
	/// a resource directory, you can edit it to set things like master keys and passwords, logging locations, error
	/// thresholds, and allowed file extensions.
	/// 
	/// </summary>
	/// <author>  jwilliams
	/// </author>
	
	// FIXME: ENHANCE make a getCharacterSet( name );
	// FIXME: ENHANCE make character sets configurable
	// characterSet.password
	// characterSet.globalAllowedCharacterList=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890
	// characterSet.makeYourOwnName=
	// 
	public class SecurityConfiguration : ISecurityConfiguration
	{
		/// <summary> Gets the master password.
		/// 
		/// </summary>
		/// <returns> the master password
		/// </returns>
		virtual public char[] MasterPassword
		{
			get
			{
				return properties.Get(MASTER_PASSWORD).ToCharArray();
			}
			
		}
		/// <summary> Gets the keystore.
		/// 
		/// </summary>
		/// <returns> the keystore
		/// </returns>
		virtual public System.IO.FileInfo Keystore
		{
			get
			{
				return new System.IO.FileInfo(ResourceDirectory.FullName + "\\" + "keystore");
			}
			
		}
		//UPGRADE_NOTE: Respective javadoc comments were merged.  It should be changed in order to comply with .NET documentation conventions. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1199'"
		/// <summary> Gets the resource directory.
		/// 
		/// </summary>
		/// <returns> the resource directory
		/// </returns>
		/// <summary> Sets the resource directory.
		/// 
		/// </summary>
		/// <param name="dir">the new resource directory
		/// </param>
		virtual protected internal System.IO.FileInfo ResourceDirectory
		{
			get
			{
				return new System.IO.FileInfo(resourceDirectory);
			}
			
			set
			{
				resourceDirectory = value.FullName;
			}
			
		}
		/// <summary> Gets the master salt.
		/// 
		/// </summary>
		/// <returns> the master salt
		/// </returns>
		virtual public sbyte[] MasterSalt
		{
			get
			{
				return SupportClass.ToSByteArray(SupportClass.ToByteArray(properties.Get(MASTER_SALT)));
			}
			
		}
		/// <summary> Gets the allowed file extensions.
		/// 
		/// </summary>
		/// <returns> the allowed file extensions
		/// </returns>
		virtual public System.Collections.IList AllowedFileExtensions
		{
			get
			{
				System.String def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
				System.String[] extList = (properties[VALID_EXTENSIONS] == null?def:properties[VALID_EXTENSIONS]).split(",");
				//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
				return new System.Collections.ArrayList(extList);
			}
			
		}
		/// <summary> Gets the allowed file upload size.
		/// 
		/// </summary>
		/// <returns> the allowed file upload size
		/// </returns>
		virtual public int AllowedFileUploadSize
		{
			get
			{
				System.String bytes = properties[MAX_UPLOAD_FILE_BYTES] == null?"50000":properties[MAX_UPLOAD_FILE_BYTES];
				return System.Int32.Parse(bytes);
			}
			
		}
		/// <summary> Gets the password parameter name.
		/// 
		/// </summary>
		/// <returns> the password parameter name
		/// </returns>
		virtual public System.String PasswordParameterName
		{
			get
			{
				return properties[PASSWORD_PARAMETER_NAME] == null?"password":properties[PASSWORD_PARAMETER_NAME];
			}
			
		}
		/// <summary> Gets the username parameter name.
		/// 
		/// </summary>
		/// <returns> the username parameter name
		/// </returns>
		virtual public System.String UsernameParameterName
		{
			get
			{
				return properties[USERNAME_PARAMETER_NAME] == null?"username":properties[USERNAME_PARAMETER_NAME];
			}
			
		}
		/// <summary> Gets the encryption algorithm.
		/// 
		/// </summary>
		/// <returns> the algorithm
		/// </returns>
		virtual public System.String EncryptionAlgorithm
		{
			get
			{
				return properties[ENCRYPTION_ALGORITHM] == null?"PBEWithMD5AndDES/CBC/PKCS5Padding":properties[ENCRYPTION_ALGORITHM];
			}
			
		}
		/// <summary> Gets the hasing algorithm.
		/// 
		/// </summary>
		/// <returns> the algorithm
		/// </returns>
		virtual public System.String HashAlgorithm
		{
			get
			{
				return properties[HASH_ALGORITHM] == null?"SHA-512":properties[HASH_ALGORITHM];
			}
			
		}
		/// <summary> Gets the character encoding.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		virtual public System.String CharacterEncoding
		{
			get
			{
				return properties[CHARACTER_ENCODING] == null?"UTF-8":properties[CHARACTER_ENCODING];
			}
			
		}
		/// <summary> Gets the digital signature algorithm.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		virtual public System.String DigitalSignatureAlgorithm
		{
			get
			{
				return properties[DIGITAL_SIGNATURE_ALGORITHM] == null?"SHAwithDSA":properties[DIGITAL_SIGNATURE_ALGORITHM];
			}
			
		}
		/// <summary> Gets the random number generation algorithm.
		/// 
		/// </summary>
		/// <returns> encoding name
		/// </returns>
		virtual public System.String RandomAlgorithm
		{
			get
			{
				return properties[RANDOM_ALGORITHM] == null?"SHA1PRNG":properties[RANDOM_ALGORITHM];
			}
			
		}
		/// <summary> Gets the allowed login attempts.
		/// 
		/// </summary>
		/// <returns> the allowed login attempts
		/// </returns>
		virtual public int AllowedLoginAttempts
		{
			get
			{
				System.String attempts = properties[ALLOWED_LOGIN_ATTEMPTS] == null?"5":properties[ALLOWED_LOGIN_ATTEMPTS];
				return System.Int32.Parse(attempts);
			}
			
		}
		/// <summary> Gets the max old password hashes.
		/// 
		/// </summary>
		/// <returns> the max old password hashes
		/// </returns>
		virtual public int MaxOldPasswordHashes
		{
			get
			{
				System.String max = properties[MAX_OLD_PASSWORD_HASHES] == null?"12":properties[MAX_OLD_PASSWORD_HASHES];
				return System.Int32.Parse(max);
			}
			
		}
		virtual public Level LogLevel
		{
			// FIXME: ENHANCE integrate log level configuration
			
			get
			{
				System.String level = properties.Get(LOG_LEVEL);
				if (level.ToUpper().Equals("TRACE".ToUpper()))
					return Level.FINER;
				if (level.ToUpper().Equals("ERROR".ToUpper()))
					return Level.WARNING;
				if (level.ToUpper().Equals("SEVERE".ToUpper()))
					return Level.SEVERE;
				if (level.ToUpper().Equals("WARNING".ToUpper()))
					return Level.WARNING;
				if (level.ToUpper().Equals("SUCCESS".ToUpper()))
					return Level.INFO;
				if (level.ToUpper().Equals("DEBUG".ToUpper()))
					return Level.CONFIG;
				if (level.ToUpper().Equals("NONE".ToUpper()))
					return Level.OFF;
				return Level.ALL;
			}
			
		}
		virtual public System.String ResponseContentType
		{
			get
			{
				System.String def = "text/html; charset=UTF-8";
				return properties[RESPONSE_CONTENT_TYPE] == null?def:properties[RESPONSE_CONTENT_TYPE];
			}
			
		}
		virtual public long RememberTokenDuration
		{
			get
			{
				System.String value_Renamed = properties[REMEMBER_TOKEN_DURATION] == null?"14":properties[REMEMBER_TOKEN_DURATION];
				long days = System.Int64.Parse(value_Renamed);
				long duration = 1000 * 60 * 60 * 24 * days;
				return duration;
			}
			
		}
		virtual public System.Collections.IEnumerator ValidationPatternNames
		{
			get
			{
				//UPGRADE_TODO: Class 'java.util.TreeSet' was converted to 'SupportClass.TreeSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilTreeSet'"
				SupportClass.TreeSetSupport list = new SupportClass.TreeSetSupport();
				System.Collections.IEnumerator i = new SupportClass.HashSetSupport(properties).GetEnumerator();
				//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
				while (i.MoveNext())
				{
					//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
					System.String name = (System.String) i.Current;
					if (name.StartsWith("Validator."))
					{
						list.Add(name.Substring(name.IndexOf('.') + 1));
					}
				}
				return list.GetEnumerator();
			}
			
		}
		virtual public bool LogEncodingRequired
		{
			get
			{
				System.String value_Renamed = properties.Get("LogEncodingRequired");
				if (value_Renamed != null && value_Renamed.ToUpper().Equals("false".ToUpper()))
					return false;
				return true;
			}
			
		}
		
		/// <summary>The properties. </summary>
		//UPGRADE_ISSUE: Class hierarchy differences between 'java.util.Properties' and 'System.Collections.Specialized.NameValueCollection' may cause compilation errors. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1186'"
		//UPGRADE_TODO: Format of property file may need to be changed. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1089'"
		private System.Collections.Specialized.NameValueCollection properties = new System.Collections.Specialized.NameValueCollection();
		
		/// <summary>Regular expression cache </summary>
		private System.Collections.IDictionary regexMap = null;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.SecurityConfiguration'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		public const System.String RESOURCE_DIRECTORY = "org.owasp.esapi.resources";
		
		private const System.String ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";
		
		private const System.String MASTER_PASSWORD = "MasterPassword";
		
		private const System.String MASTER_SALT = "MasterSalt";
		
		private const System.String VALID_EXTENSIONS = "ValidExtensions";
		
		private const System.String MAX_UPLOAD_FILE_BYTES = "MaxUploadFileBytes";
		
		private const System.String USERNAME_PARAMETER_NAME = "UsernameParameterName";
		
		private const System.String PASSWORD_PARAMETER_NAME = "PasswordParameterName";
		
		private const System.String MAX_OLD_PASSWORD_HASHES = "MaxOldPasswordHashes";
		
		private const System.String ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";
		
		private const System.String HASH_ALGORITHM = "HashAlgorithm";
		
		private const System.String CHARACTER_ENCODING = "CharacterEncoding";
		
		private const System.String RANDOM_ALGORITHM = "RandomAlgorithm";
		
		private const System.String DIGITAL_SIGNATURE_ALGORITHM = "DigitalSignatureAlgorithm";
		
		private const System.String RESPONSE_CONTENT_TYPE = "ResponseContentType";
		
		private const System.String REMEMBER_TOKEN_DURATION = "RememberTokenDuration";
		
		private const System.String LOG_LEVEL = "LogLevel";
		
		/// <summary> Load properties from properties file. Important: This implementation relies on a System property defined when
		/// Java is launched. Use:
		/// <P>
		/// java -Dorg.owasp.esapi.resources="/path/resources"
		/// <P>
		/// where path references the appropriate directory in your system.
		/// </summary>
		//UPGRADE_ISSUE: Method 'java.lang.System.getProperty' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javalangSystem'"
		private static System.String resourceDirectory = System_Renamed.getProperty(RESOURCE_DIRECTORY);
		
		/// <summary>The last modified. </summary>
		private static long lastModified = 0;
		
		/// <summary> Instantiates a new configuration.</summary>
		public SecurityConfiguration()
		{
			// FIXME : this should be reloaded periodically
			loadConfiguration();
		}
		
		/// <summary> Load configuration.</summary>
		private void  loadConfiguration()
		{
			System.IO.FileInfo file = new System.IO.FileInfo(ResourceDirectory.FullName + "\\" + "ESAPI.properties");
			//UPGRADE_TODO: The equivalent in .NET for method 'java.io.File.lastModified' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
			if (((file.LastWriteTime.Ticks - 621355968000000000) / 10000) == lastModified)
				return ;
			
			System.IO.FileStream fis = null;
			try
			{
				//UPGRADE_TODO: Constructor 'java.io.FileInputStream.FileInputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileInputStreamFileInputStream_javaioFile'"
				fis = new System.IO.FileStream(file.FullName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
				//UPGRADE_TODO: Method 'java.util.Properties.load' was converted to 'System.Collections.Specialized.NameValueCollection' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilPropertiesload_javaioInputStream'"
				properties = new System.Collections.Specialized.NameValueCollection(System.Configuration.ConfigurationSettings.AppSettings);
				logger.logSpecial("Loaded ESAPI properties from " + file.FullName, null);
			}
			catch (System.Exception e)
			{
				logger.logSpecial("Can't load ESAPI properties from " + file.FullName, e);
			}
			finally
			{
				try
				{
					fis.Close();
				}
				catch (System.IO.IOException e)
				{
					// give up
				}
			}
			
			logger.logSpecial("  ========Master Configuration========", null);
			//UPGRADE_TODO: Class 'java.util.TreeSet' was converted to 'SupportClass.TreeSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilTreeSet'"
			System.Collections.IEnumerator i = new SupportClass.TreeSetSupport(new SupportClass.HashSetSupport(properties)).GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String key = (System.String) i.Current;
				//UPGRADE_TODO: The equivalent in .NET for method 'java.lang.Object.toString' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
				logger.logSpecial("  |   " + key + "=" + properties[(System.String) key], null);
			}
			logger.logSpecial("  ========Master Configuration========", null);
			//UPGRADE_TODO: The equivalent in .NET for method 'java.io.File.lastModified' may return a different value. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1043'"
			lastModified = ((file.LastWriteTime.Ticks - 621355968000000000) / 10000);
			
			// cache regular expressions
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			regexMap = new System.Collections.Hashtable();
			
			System.Collections.IEnumerator regexIterator = ValidationPatternNames;
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (regexIterator.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String name = (System.String) regexIterator.Current;
				Pattern regex = getValidationPattern(name);
				if (name != null && regex != null)
				{
					regexMap[name] = regex;
				}
			}
		}
		
		// FIXME: ENHANCE should read these quotas into a map and cache them
		public virtual Threshold getQuota(System.String eventName)
		{
			
			int count = 0;
			System.String countString = properties.Get(eventName + ".count");
			if (countString != null)
			{
				count = System.Int32.Parse(countString);
			}
			
			int interval = 0;
			System.String intervalString = properties.Get(eventName + ".interval");
			if (intervalString != null)
			{
				interval = System.Int32.Parse(intervalString);
			}
			
			System.Collections.IList actions = new System.Collections.ArrayList();
			System.String actionString = properties.Get(eventName + ".actions");
			if (actionString != null)
			{
				System.String[] actionList = actionString.split(",");
				//UPGRADE_TODO: Method 'java.util.Arrays.asList' was converted to 'System.Collections.ArrayList' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilArraysasList_javalangObject[]'"
				actions = new System.Collections.ArrayList(actionList);
			}
			
			Threshold q = new Threshold(eventName, count, interval, actions);
			return q;
		}
		
		public virtual Pattern getValidationPattern(System.String key)
		{
			System.String value_Renamed = properties.Get("Validator." + key);
			if (value_Renamed == null)
				return null;
			Pattern pattern = Pattern.compile(value_Renamed);
			return pattern;
		}
		static SecurityConfiguration()
		{
			logger = Logger.getLogger("ESAPI", "SecurityConfiguration");
		}
	}
}