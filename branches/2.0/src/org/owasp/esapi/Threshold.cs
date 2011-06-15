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
namespace org.owasp.esapi
{
	
	/// <summary> The threshold class simply models the data for a basic threshold with a name,
	/// elapsed time, counter, and a set of actions to take.
	/// 
	/// </summary>
	/// <author>  Jeff Williams (jeff.williams@aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
	/// </author>
	/// <since> June 1, 2007
	/// </since>
	public class Threshold
	{
		public System.String name = null;
		public int count = 0;
		public long interval = 0;
		public System.Collections.IList actions = null;
		
		public Threshold(System.String name, int count, long interval, System.Collections.IList actions)
		{
			this.name = name;
			this.count = count;
			this.interval = interval;
			this.actions = actions;
		}
	}
}