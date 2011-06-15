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
using EncryptionException = org.owasp.esapi.errors.EncryptionException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IEncryptedProperties interface. This
	/// implementation wraps a normal properties file, and creates surrogates for the
	/// getProperty and setProperty methods that perform encryption and decryption based on the Encryptor.
	/// A very simple main program is provided that can be used to create an
	/// encrypted properties file. A better approach would be to allow unencrypted
	/// properties in the file and to encrypt them the first time the file is
	/// accessed.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	/// href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IEncryptedProperties">
	/// </seealso>
	public class EncryptedProperties : org.owasp.esapi.interfaces.IEncryptedProperties
	{
		
		/// <summary>The properties. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'properties '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_ISSUE: Class hierarchy differences between 'java.util.Properties' and 'System.Collections.Specialized.NameValueCollection' may cause compilation errors. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1186'"
		//UPGRADE_TODO: Format of property file may need to be changed. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1089'"
		private System.Collections.Specialized.NameValueCollection properties = new System.Collections.Specialized.NameValueCollection();
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'logger '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.EncryptedProperties'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly Logger logger;
		
		/// <summary> Instantiates a new encrypted properties.</summary>
		public EncryptedProperties()
		{
			// hidden
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptedProperties#getProperty(java.lang.String)
		*/
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'getProperty'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual System.String getProperty(System.String key)
		{
			lock (this)
			{
				try
				{
					return ESAPI.encryptor().decrypt(properties.Get(key));
				}
				catch (System.Exception e)
				{
					throw new EncryptionException("Property retrieval failure", "Couldn't decrypt property", e);
				}
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IEncryptedProperties#setProperty(java.lang.String,
		*      java.lang.String)
		*/
		//UPGRADE_NOTE: Synchronized keyword was removed from method 'setProperty'. Lock expression was added. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1027'"
		public virtual System.String setProperty(System.String key, System.String value_Renamed)
		{
			lock (this)
			{
				try
				{
					System.Object tempObject;
					//UPGRADE_TODO: Method 'java.util.Properties.setProperty' was converted to 'System.Collections.Specialized.NameValueCollection.Item' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilPropertiessetProperty_javalangString_javalangString'"
					tempObject = properties[key];
					properties[key] = ESAPI.encryptor().encrypt(value_Renamed);
					return (System.String) tempObject;
				}
				catch (System.Exception e)
				{
					throw new EncryptionException("Property setting failure", "Couldn't encrypt property", e);
				}
			}
		}
		
		/// <summary> Key set.
		/// 
		/// </summary>
		/// <returns> the set
		/// </returns>
		public virtual SupportClass.SetSupport keySet()
		{
			return new SupportClass.HashSetSupport(properties);
		}
		
		/// <summary> Load.
		/// 
		/// </summary>
		/// <param name="in">the in
		/// 
		/// </param>
		/// <throws>  IOException </throws>
		/// <summary>             Signals that an I/O exception has occurred.
		/// </summary>
		public virtual void  load(System.IO.Stream in_Renamed)
		{
			//UPGRADE_TODO: Method 'java.util.Properties.load' was converted to 'System.Collections.Specialized.NameValueCollection' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilPropertiesload_javaioInputStream'"
			properties = new System.Collections.Specialized.NameValueCollection(System.Configuration.ConfigurationSettings.AppSettings);
			logger.logTrace(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Encrypted properties loaded successfully");
		}
		
		/// <summary> Store.
		/// 
		/// </summary>
		/// <param name="out">the out
		/// </param>
		/// <param name="comments">the comments
		/// 
		/// </param>
		/// <throws>  IOException </throws>
		/// <summary>             Signals that an I/O exception has occurred.
		/// </summary>
		public virtual void  store(System.IO.Stream out_Renamed, System.String comments)
		{
			//UPGRADE_ISSUE: Method 'java.util.Properties.store' was not converted. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1000_javautilPropertiesstore_javaioOutputStream_javalangString'"
			properties.store(out_Renamed, comments);
		}
		
		/// <summary> The main method.
		/// 
		/// </summary>
		/// <param name="args">the arguments
		/// 
		/// </param>
		/// <throws>  Exception </throws>
		/// <summary>             the exception
		/// </summary>
		[STAThread]
		public static void  Main(System.String[] args)
		{
			// FIXME: AAA verify that this still works
			System.IO.FileInfo f = new System.IO.FileInfo(args[0]);
			Logger.getLogger("EncryptedProperties", "main").logDebug(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Loading encrypted properties from " + f.FullName);
			bool tmpBool;
			if (System.IO.File.Exists(f.FullName))
				tmpBool = true;
			else
				tmpBool = System.IO.Directory.Exists(f.FullName);
			if (!tmpBool)
				throw new System.IO.IOException("Properties file not found: " + f.FullName);
			Logger.getLogger("EncryptedProperties", "main").logDebug(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Encrypted properties found in " + f.FullName);
			EncryptedProperties ep = new EncryptedProperties();
			//UPGRADE_TODO: Constructor 'java.io.FileInputStream.FileInputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileInputStreamFileInputStream_javaioFile'"
			System.IO.FileStream in_Renamed = new System.IO.FileStream(f.FullName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
			ep.load(in_Renamed);
			
			//UPGRADE_TODO: The differences in the expected value  of parameters for constructor 'java.io.BufferedReader.BufferedReader'  may cause compilation errors.  "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1092'"
			//UPGRADE_WARNING: At least one expression was used more than once in the target code. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1181'"
			System.IO.StreamReader br = new System.IO.StreamReader(new System.IO.StreamReader(System.Console.OpenStandardInput(), System.Text.Encoding.Default).BaseStream, new System.IO.StreamReader(System.Console.OpenStandardInput(), System.Text.Encoding.Default).CurrentEncoding);
			System.String key = null;
			do 
			{
				System.Console.Out.Write("Enter key: ");
				key = br.ReadLine();
				System.Console.Out.Write("Enter value: ");
				System.String value_Renamed = br.ReadLine();
				if (key != null && key.Length > 0 && value_Renamed.Length > 0)
				{
					ep.setProperty(key, value_Renamed);
				}
			}
			while (key != null && key.Length > 0);
			
			//UPGRADE_TODO: Constructor 'java.io.FileOutputStream.FileOutputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileOutputStreamFileOutputStream_javaioFile'"
			System.IO.FileStream out_Renamed = new System.IO.FileStream(f.FullName, System.IO.FileMode.Create);
			ep.store(out_Renamed, "Encrypted Properties File");
			out_Renamed.Close();
			
			System.Collections.IEnumerator i = ep.keySet().GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String k = (System.String) i.Current;
				System.String value_Renamed = ep.getProperty(k);
				System.Console.Out.WriteLine("   " + k + "=" + value_Renamed);
			}
		}
		static EncryptedProperties()
		{
			logger = Logger.getLogger("ESAPI", "EncryptedProperties");
		}
	}
}