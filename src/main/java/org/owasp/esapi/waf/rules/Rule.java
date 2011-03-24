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
package org.owasp.esapi.waf.rules;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the base class for the WAF rules.
 * @author Arshan Dabirsiaghi
 *
 */
public abstract class Rule {

	protected String id = "(no rule ID)";
	protected static Logger logger = Logger.getLogger(Rule.class);
	protected Action ruleDefaultAction = new DefaultAction();
	
	public abstract Action check( HttpServletRequest request, InterceptingHTTPServletResponse response, HttpServletResponse httpResponse );

	public void log( HttpServletRequest request, String message ) {
		Date timestamp = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat();
		sdf.setTimeZone(new SimpleTimeZone(0, "GMT"));
		sdf.applyPattern("dd.MM.yyyy.HH:mm:ss:S");

		logger.log(AppGuardianConfiguration.LOG_LEVEL,
				sdf.format(timestamp) +
				",[IP=" + request.getRemoteAddr() +
				",Rule=" + this.getClass().getSimpleName() + ",ID="+id+"] " + message);
		
		request.getSession().setAttribute("ErrorCode", sdf.format(timestamp)+id.toString());
	}

	protected void setId(String id) {
		if ( id == null || "".equals(id) )
			return;

		this.id = id;
	}

	public Action getDefaultAction() {
		return this.ruleDefaultAction;
	}
	
	public String toString() {
		return "Rule:" + this.getClass().getName();
	}
}
