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

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;virtual-patch&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class SimpleVirtualPatchRule extends Rule {

	private static final String REQUEST_PARAMETERS = "request.parameters.";
	private static final String REQUEST_HEADERS = "request.headers.";

	private Pattern path;
	private String variable;
	private Pattern valid;
	private String message;
	private boolean required;

	public SimpleVirtualPatchRule(String id, Pattern path, String variable, Pattern valid, String message, boolean required, Action ruleDefaultAction) {
		setId(id);
		this.path = path;
		this.variable = variable;
		this.valid = valid;
		this.message = message;
		this.ruleDefaultAction = ruleDefaultAction;
		this.required = required;
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;

		String uri = request.getRequestURI();
		if ( ! path.matcher(uri).matches() ) {

			return new DoNothingAction();

		} else {

			/*
			 * Decide which parameters/headers to act on.
			 */
			String target = null;
			Enumeration en = null;
			boolean parameter = true;

			if ( variable.startsWith(REQUEST_PARAMETERS)) {

				target = variable.substring(REQUEST_PARAMETERS.length());
				en = request.getParameterNames();

			} else if ( variable.startsWith(REQUEST_HEADERS) ) {

				parameter = false;
				target = variable.substring(REQUEST_HEADERS.length());
				en = request.getHeaderNames();

			} else {
				log(request, "Patch failed (improperly configured variable '" + variable + "')");
				return this.ruleDefaultAction;
			}

			/*
			 * If it contains a regex character, it's a regex. Loop through elements and grab any matches.
			 */
			if ( target.contains("*") || target.contains("?") ) {

				target = target.replaceAll("\\*", ".*");
				Pattern p = Pattern.compile(target);
				String[] values = null;
				while (en.hasMoreElements() ) {
					String s = (String)en.nextElement();
					if ( p.matcher(s).matches() ) {
						if ( parameter ) {
							values = request.ARGS.get(s);
						} else {
							values = request.REQUEST_HEADERS.get(s);
						}
						for (int i=0; i<values.length; i++) {
							if ( values[i] != null && ! valid.matcher(values[i]).matches() ) {
								log(request, "Virtual patch tripped on variable '" + variable + "' (specifically '" + s + "'). User input was '" + values[i] + "' and legal pattern was '" + valid.pattern() + "': " + message);
								return this.ruleDefaultAction;
							}	
						}
					}
				}
				return new DoNothingAction();

			} else {
				String[] values;
				if ( parameter ) {
					values = request.ARGS.get(target);
				} else {
					values = request.REQUEST_HEADERS.get(target);
				}
				if (values == null || values.length == 0){
					if (this.required) {
						log(request, "Virtual patch tripped on " + (parameter? "parameter" : "header") + " '" + target + "'. Parameter is required and not present: " + message);
						return this.ruleDefaultAction;
					} else {
						return new DoNothingAction();
					}
				} else { //it is not null
					for (int i = 0; i < values.length; i++) {
						if (valid.matcher(values[i]).matches() ) {
							return new DoNothingAction();
						} else {
							log(request, "Virtual patch tripped on " + (parameter? "parameter" : "header") + " '" + target + "'. User input was '" + values[i] + "' and legal pattern was '" + valid.pattern() + "': " + message);
							return this.ruleDefaultAction;
						}	
					}
				}
			}
		}
		return new DoNothingAction();
	}

	public String getMessage() {
		return message;
	}


}
