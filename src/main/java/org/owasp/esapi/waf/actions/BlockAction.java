/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.actions;

import org.owasp.esapi.waf.configuration.ConfigurationParser;

/**
 * The class that indicates the request processing should be halted and that a blank response
 * should be returned.
 * 
 * @author Arshan Dabirsiaghi
 */
public class BlockAction extends Action {
	private int statusCode = ConfigurationParser.DEFAULT_RESPONSE_CODE;
	public BlockAction () {}
	public BlockAction (int statusCode) {
		this.statusCode = statusCode;
	}
	public boolean failedRule() {
		return true;
	}

	public boolean isActionNecessary() {
		return true;
	}
	
	public int getStatusCode () {
		return statusCode;	
	}

}
