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
using EncodingException = org.owasp.esapi.errors.EncodingException;
using IntrusionException = org.owasp.esapi.errors.IntrusionException;
using ValidationException = org.owasp.esapi.errors.ValidationException;
namespace org.owasp.esapi
{
	
	/// <summary> Reference implementation of the IAccessController interface. This reference
	/// implementation uses a simple model for specifying a set of access control
	/// rules. Many organizations will want to create their own implementation of the
	/// methods provided in the IAccessController interface.
	/// <P>
	/// This reference implementation uses a simple scheme for specifying the rules.
	/// The first step is to create a namespace for the resources being accessed. For
	/// files and URL's, this is easy as they already have a namespace. Be extremely
	/// careful about canonicalizing when relying on information from the user in an
	/// access ctnrol decision.
	/// <P>
	/// For functions, data, and services, you will have to come up with your own
	/// namespace for the resources being accessed. You might simply define a flat
	/// namespace with a list of category names. For example, you might specify
	/// 'FunctionA', 'FunctionB', and 'FunctionC'. Or you can create a richer
	/// namespace with a hierarchical structure, such as:
	/// <P>
	/// /functions
	/// <ul>
	/// <li>purchasing</li>
	/// <li>shipping</li>
	/// <li>inventory</li>
	/// </ul>
	/// /admin
	/// <ul>
	/// <li>createUser</li>
	/// <li>deleteUser</li>
	/// </ul>
	/// Once you've defined your namespace, you have to work out the rules that
	/// govern access to the different parts of the namespace. This implementation
	/// allows you to attach a simple access control list (ACL) to any part of the
	/// namespace tree. The ACL lists a set of roles that are either allowed or
	/// denied access to a part of the tree. You specify these rules in a textfile
	/// with a simple format.
	/// <P>
	/// There is a single configuration file supporting each of the five methods in
	/// the IAccessController interface. These files are located in the ESAPI
	/// resources directory as specified when the JVM was started. The use of a
	/// default deny rule is STRONGLY recommended. The file format is as follows:
	/// 
	/// <pre>
	/// path          | role,role   | allow/deny | comment
	/// ------------------------------------------------------------------------------------
	/// /banking/*    | user,admin  | allow      | authenticated users can access /banking
	/// /admin        | admin       | allow      | only admin role can access /admin
	/// /             | any         | deny       | default deny rule
	/// </pre>
	/// 
	/// To find the matching rules, this implementation follows the general approach
	/// used in Java EE when matching HTTP requests to servlets in web.xml. The
	/// four mapping rules are used in the following order:
	/// <ul>
	/// <li>exact match, e.g. /access/login</li>
	/// <li>longest path prefix match, beginning / and ending /*, e.g. /access/* or /*</li>
	/// <li>extension match, beginning *., e.g. *.css</li>
	/// <li>default rule, specified by the single character pattern /</li>
	/// </ul>
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com)
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	/// <seealso cref="org.owasp.esapi.interfaces.IAccessController">
	/// </seealso>
	public class AccessController : org.owasp.esapi.interfaces.IAccessController
	{
		private void  InitBlock()
		{
			deny = new Rule(this);
		}
		
		/// <summary>The resource directory. </summary>
		//UPGRADE_NOTE: Final was removed from the declaration of 'resourceDirectory '. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1003'"
		//UPGRADE_NOTE: The initialization of  'resourceDirectory' was moved to static method 'org.owasp.esapi.AccessController'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static readonly System.IO.FileInfo resourceDirectory;
		
		/// <summary>The url map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary urlMap = new System.Collections.Hashtable();
		
		/// <summary>The function map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary functionMap = new System.Collections.Hashtable();
		
		/// <summary>The data map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary dataMap = new System.Collections.Hashtable();
		
		/// <summary>The file map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary fileMap = new System.Collections.Hashtable();
		
		/// <summary>The service map. </summary>
		//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
		private System.Collections.IDictionary serviceMap = new System.Collections.Hashtable();
		
		/// <summary>The deny. </summary>
		//UPGRADE_NOTE: The initialization of  'deny' was moved to method 'InitBlock'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private Rule deny;
		
		/// <summary>The logger. </summary>
		//UPGRADE_NOTE: The initialization of  'logger' was moved to static method 'org.owasp.esapi.AccessController'. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1005'"
		private static Logger logger;
		
		public AccessController()
		{
			InitBlock();
		}
		
		// FIXME: consider adding flag for logging
		// FIXME: perhaps an enumeration for context (i.e. the layer the call is made from)
		
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForURL(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool isAuthorizedForURL(System.String url)
		{
			if ((urlMap.Count == 0))
			{
				try
				{
					urlMap = loadRules(new System.IO.FileInfo(resourceDirectory.FullName + "\\" + "URLAccessRules.txt"));
				}
				catch (AccessControlException ex)
				{
					return false;
				}
			}
			try
			{
				return matchRule(urlMap, url);
			}
			catch (AccessControlException ex)
			{
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFunction(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool isAuthorizedForFunction(System.String functionName)
		{
			if ((functionMap.Count == 0))
			{
				try
				{
					functionMap = loadRules(new System.IO.FileInfo(resourceDirectory.FullName + "\\" + "FunctionAccessRules.txt"));
				}
				catch (AccessControlException ex)
				{
					return false;
				}
			}
			try
			{
				return matchRule(functionMap, functionName);
			}
			catch (AccessControlException ex)
			{
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForData(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool isAuthorizedForData(System.String key)
		{
			if ((dataMap.Count == 0))
			{
				try
				{
					dataMap = loadRules(new System.IO.FileInfo(resourceDirectory.FullName + "\\" + "DataAccessRules.txt"));
				}
				catch (AccessControlException ex)
				{
					return false;
				}
			}
			try
			{
				return matchRule(dataMap, key);
			}
			catch (AccessControlException ex)
			{
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFile(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool isAuthorizedForFile(System.String filepath)
		{
			if ((fileMap.Count == 0))
			{
				try
				{
					fileMap = loadRules(new System.IO.FileInfo(resourceDirectory.FullName + "\\" + "FileAccessRules.txt"));
				}
				catch (AccessControlException ex)
				{
					return false;
				}
			}
			try
			{
				// FIXME: AAA think about canonicalization here - use Java file canonicalizer
				// remember that Windows paths have \ instad of /
				return matchRule(fileMap, filepath.replaceAll("\\\\", "/"));
			}
			catch (AccessControlException ex)
			{
				return false;
			}
		}
		
		/*
		* (non-Javadoc)
		* 
		* @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForBackendService(java.lang.String,
		*      java.lang.String)
		*/
		public virtual bool isAuthorizedForService(System.String serviceName)
		{
			if ((serviceMap.Count == 0))
			{
				try
				{
					serviceMap = loadRules(new System.IO.FileInfo(resourceDirectory.FullName + "\\" + "ServiceAccessRules.txt"));
				}
				catch (AccessControlException ex)
				{
					return false;
				}
			}
			try
			{
				return matchRule(serviceMap, serviceName);
			}
			catch (AccessControlException ex)
			{
				return false;
			}
		}
		
		/// <summary> Match rule.
		/// 
		/// </summary>
		/// <param name="map">the map
		/// </param>
		/// <param name="path">the path
		/// 
		/// </param>
		/// <returns> true, if successful
		/// 
		/// </returns>
		/// <throws>  AccessControlException </throws>
		/// <summary>             the access control exception
		/// </summary>
		private bool matchRule(System.Collections.IDictionary map, System.String path)
		{
			// get users roles
			User user = ESAPI.authenticator().getCurrentUser();
			if (user == null)
			{
				return false;
			}
			SupportClass.SetSupport roles = user.Roles;
			// search for the first rule that matches the path and rules
			Rule rule = searchForRule(map, roles, path);
			return rule.allow;
		}
		
		/// <summary> Search for rule. Four mapping rules are used in order: - exact match,
		/// e.g. /access/login - longest path prefix match, beginning / and ending
		/// /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css -
		/// default servlet, specified by the single character pattern /
		/// 
		/// </summary>
		/// <param name="map">the map
		/// </param>
		/// <param name="roles">the roles
		/// </param>
		/// <param name="path">the path
		/// 
		/// </param>
		/// <returns> the rule
		/// 
		/// </returns>
		/// <throws>  AccessControlException </throws>
		/// <summary>             the access control exception
		/// </summary>
		private Rule searchForRule(System.Collections.IDictionary map, SupportClass.SetSupport roles, System.String path)
		{
			System.String canonical = null;
			try
			{
				canonical = ESAPI.encoder().canonicalize(path);
			}
			catch (EncodingException ee)
			{
				throw new AccessControlException("Internal error", "Failed to canonicaliize input ", ee);
			}
			
			System.String part = canonical;
			while (part.EndsWith("/"))
			{
				part = part.Substring(0, (part.Length - 1) - (0));
			}
			
			if (part.IndexOf("..") != - 1)
			{
				throw new IntrusionException("Attempt to manipulate access control path", "Attempt to manipulate access control path: " + path);
			}
			
			// extract extension if any
			System.String extension = "";
			int extIndex = part.LastIndexOf(".");
			if (extIndex != - 1)
			{
				extension = part.Substring(extIndex + 1);
			}
			
			// Check for exact match - ignore any ending slash
			Rule rule = (Rule) map[part];
			
			// Check for ending with /*
			if (rule == null)
				rule = (Rule) map[part + "/*"];
			
			// Check for matching extension rule *.ext
			if (rule == null)
				rule = (Rule) map["*." + extension];
			
			// if rule found and user's roles match rules' roles, return the rule
			if (rule != null && overlap(rule.roles, roles))
				return rule;
			
			// if rule has not been found, strip off the last element and recurse
			part = part.Substring(0, (part.LastIndexOf('/')) - (0));
			
			// return default deny
			if (part.Length <= 1)
			{
				return deny;
			}
			
			return searchForRule(map, roles, part);
		}
		
		/// <summary> Return true if there is overlap between the two sets.
		/// 
		/// </summary>
		/// <param name="ruleRoles">the rule roles
		/// </param>
		/// <param name="userRoles">the user roles
		/// 
		/// </param>
		/// <returns> true, if successful
		/// </returns>
		private bool overlap(SupportClass.SetSupport ruleRoles, SupportClass.SetSupport userRoles)
		{
			if (ruleRoles.Contains("any"))
			{
				return true;
			}
			System.Collections.IEnumerator i = userRoles.GetEnumerator();
			//UPGRADE_TODO: Method 'java.util.Iterator.hasNext' was converted to 'System.Collections.IEnumerator.MoveNext' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratorhasNext'"
			while (i.MoveNext())
			{
				//UPGRADE_TODO: Method 'java.util.Iterator.next' was converted to 'System.Collections.IEnumerator.Current' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilIteratornext'"
				System.String role = (System.String) i.Current;
				if (ruleRoles.Contains(role))
				{
					return true;
				}
			}
			return false;
		}
		
		/// <summary> Load rules.
		/// 
		/// </summary>
		/// <param name="f">the f
		/// 
		/// </param>
		/// <returns> the hash map
		/// 
		/// </returns>
		/// <throws>  AccessControlException </throws>
		/// <summary>             the access control exception
		/// </summary>
		private System.Collections.IDictionary loadRules(System.IO.FileInfo f)
		{
			//UPGRADE_TODO: Class 'java.util.HashMap' was converted to 'System.Collections.Hashtable' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashMap'"
			System.Collections.IDictionary map = new System.Collections.Hashtable();
			System.IO.FileStream fis = null;
			try
			{
				//UPGRADE_TODO: Constructor 'java.io.FileInputStream.FileInputStream' was converted to 'System.IO.FileStream.FileStream' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javaioFileInputStreamFileInputStream_javaioFile'"
				fis = new System.IO.FileStream(f.FullName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
				System.String line = "";
				while ((line = ESAPI.validator().safeReadLine(fis, 500)) != null)
				{
					if (line.Length > 0 && line[0] != '#')
					{
						Rule rule = new Rule(this);
						System.String[] parts = line.split("\\|");
						// fix Windows paths
						rule.path = parts[0].Trim().replaceAll("\\\\", "/");
						rule.roles.Add(parts[1].Trim().ToLower());
						System.String action = parts[2].Trim();
						rule.allow = action.ToUpper().Equals("allow".ToUpper());
						if (map.Contains(rule.path))
						{
							throw new AccessControlException("Access control failure", "Problem in access control file. Duplicate rule " + rule);
						}
						map[rule.path] = rule;
					}
				}
				return map;
			}
			catch (System.IO.IOException e)
			{
				throw new AccessControlException("Access control failure", "Failure loading access control file " + f, e);
			}
			catch (ValidationException e1)
			{
				throw new AccessControlException("Access control failure", "Failure loading access control file " + f, e1);
			}
			finally
			{
				try
				{
					if (fis != null)
					{
						fis.Close();
					}
				}
				catch (System.IO.IOException e)
				{
					logger.logWarning(org.owasp.esapi.interfaces.ILogger_Fields.SECURITY, "Failure closing access control file: " + f, e);
				}
			}
		}
		
		//UPGRADE_NOTE: Field 'EnclosingInstance' was added to class 'Rule' to access its enclosing instance. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1019'"
		/// <summary> The Class Rule.</summary>
		private class Rule
		{
			private void  InitBlock(AccessController enclosingInstance)
			{
				this.enclosingInstance = enclosingInstance;
			}
			private AccessController enclosingInstance;
			public AccessController Enclosing_Instance
			{
				get
				{
					return enclosingInstance;
				}
				
			}
			
			/// <summary>The path. </summary>
			protected internal System.String path = "";
			
			/// <summary>The roles. </summary>
			//UPGRADE_TODO: Class 'java.util.HashSet' was converted to 'SupportClass.HashSetSupport' which has a different behavior. "ms-help://MS.VSCC.v80/dv_commoner/local/redirect.htm?index='!DefaultContextWindowIndex'&keyword='jlca1073_javautilHashSet'"
			protected internal SupportClass.SetSupport roles = new SupportClass.HashSetSupport();
			
			/// <summary>The allow. </summary>
			protected internal bool allow = false;
			
			/// <summary> Creates a new Rule object.</summary>
			protected internal Rule(AccessController enclosingInstance)
			{
				InitBlock(enclosingInstance);
				// to replace synthetic accessor method
			}
			
			/*
			* (non-Javadoc)
			* 
			* @see java.lang.Object#toString()
			*/
			public override System.String ToString()
			{
				return "URL:" + path + " | " + SupportClass.CollectionToString(roles) + " | " + (allow?"allow":"deny");
			}
		}
		static AccessController()
		{
			resourceDirectory = ((SecurityConfiguration) ESAPI.securityConfiguration()).ResourceDirectory;
			logger = Logger.getLogger("ESAPI", "AccessController");
		}
	}
}