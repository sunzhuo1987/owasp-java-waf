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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

import bsh.EvalError;
import bsh.Interpreter;
import bsh.ParseException;
import bsh.Parser;

/**
 * This is the Rule subclass executed for &lt;bean-shell-script&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class BeanShellRule extends Rule {

	private Interpreter i;
	private String script;
	private Pattern path;
	private String Message;
	
	public BeanShellRule(String fileLocation, String id, Pattern path, String Message) throws IOException, EvalError { 
		i = new Interpreter();
		i.set("logger", logger);
		this.script = getFileContents(new File(fileLocation));
		this.id = id;
		this.path = path;
		this.Message = Message;
		//Validate the script is correct, bubble beanshell exception if not
		Parser p = new Parser(new FileReader(fileLocation));
		while (! (p.Line())) {}
	}
	
	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * Early fail: if the URL doesn't match one we're interested in.
		 */
		
		if ( path != null && ! path.matcher(request.getRequestURI()).matches() ) {
			return new DoNothingAction();
		}
		
		/*
		 * Run the beanshell that we've already parsed
		 * and pre-compiled. Populate the "request"
		 * and "response" objects so the script has
		 * access to the same variables we do here.
		 */
		
		try {
		
			Action a = null;
			
			i.set("action", a);
			i.set("request", request);
			
			if ( response != null ) {
				i.set("response", response);	
			} else {
				i.set("response", httpResponse);
			}

			i.set("session", request.getSession());
			i.eval(script);

			a = (Action)i.get("action");
	
			if ( a != null ) {
				return a;
			}
			
		} catch (EvalError e) {
			log(request,"Error running custom beanshell rule (" + id + ") - " + e.getMessage());
		}
	
		return new DoNothingAction();
	}
	
	private String getFileContents(File f) throws IOException {
		
		FileReader fr = new FileReader(f);
		StringBuffer sb = new StringBuffer();
		String line;
		BufferedReader br = new BufferedReader(fr);
		
		while( (line=br.readLine()) != null ) {
			sb.append(line + System.getProperty("line.separator"));
		}
		
		return sb.toString();
	}

	public String getMessage() {
		return Message;
	}

}
