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
package org.owasp.esapi.waf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.FactoryConfigurationError;

import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.BlockAction;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.configuration.ConfigurationParser;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.Rule;

/**
 * This is the main class for the ESAPI Web Application Firewall (WAF). It is a standard J2EE servlet filter
 * that, in different methods, invokes the reading of the configuration file and handles the runtime processing
 * and enforcing of the developer-specified rules.
 * 
 * Ideally the filter should be configured to catch all requests (/*) in web.xml. If there are URL segments that
 * need to be extremely fast and don't require any protection, the pattern may be modified with extreme caution.
 *  
 * @author Arshan Dabirsiaghi
 *
 */
public class ESAPIWebApplicationFirewallFilter implements Filter {

	private AppGuardianConfiguration appGuardConfig;

	private static final String CONFIGURATION_FILE_PARAM = "configuration";
	private static final String LOGGING_FILE_PARAM = "log_settings";
	private static final String POLLING_TIME_PARAM = "polling_time";
	
	private static final int DEFAULT_POLLING_TIME = 30000;
	
	private String configurationFilename = null;

	private Timer pollTimer;
    
	private long pollingTime;
		
	private FilterConfig fc;
	
	private Logger logger = Logger.getLogger(ESAPIWebApplicationFirewallFilter.class);
	
	/**
	 * This function is used in testing to dynamically alter the configuration.
	 * @param policyFilePath The path to the policy file
	 * @param webRootDir The root directory of the web application.
     * @throws FileNotFoundException if the policy file cannot be located
	 * @throws ConfigurationException 
	 */
	public void setConfiguration( String policyFilePath, String webRootDir ) throws FileNotFoundException, ConfigurationException {
		try {
			appGuardConfig = ConfigurationParser.readConfigurationFile(new FileInputStream(new File(policyFilePath)), webRootDir);
			configurationFilename = policyFilePath;
		} catch (ConfigurationException e ) {
			throw e;
		}
	}
	
	public AppGuardianConfiguration getConfiguration() {
		return appGuardConfig;
	}
	
	
	/**
	 * 
	 * This function is invoked at application startup and when the configuration file
	 * polling period has elapsed and a change in the configuration file has been detected.
	 * 
	 * It's main purpose is to read the configuration file and establish the configuration
	 * object model for use at runtime during the <code>doFilter()</code> method. 
	 */
	public void init(FilterConfig fc) throws ServletException {

		/*
		 * This variable is saved so that we can retrieve it later to re-invoke this function.
		 */
		this.fc = fc;
		
		logger.debug("Success >> Initializing WAF" );
		/*
		 * Pull logging file.
		 */

        // Demoted scope to a local since this is the only place it is referenced
        String logSettingsFilename = fc.getInitParameter(LOGGING_FILE_PARAM);

		String realLogSettingsFilename = fc.getServletContext().getRealPath(logSettingsFilename);
		
		if ( realLogSettingsFilename == null || (! new File(realLogSettingsFilename).exists()) ) {
			//allow default configuration //throw new ServletException("[ESAPI WAF] Could not find log file at resolved path: " + realLogSettingsFilename);
			logger.debug("Success >> Using Default log4j configuration" );
		} else {
			try {
				DOMConfigurator.configure(realLogSettingsFilename);
				logger.debug("Success >> Using log4j xml configuration file" );
			} catch (FactoryConfigurationError e) {
				throw new ServletException(e);
			}
		}

		/*
		 * Pull main configuration file.
		 */

		configurationFilename = fc.getInitParameter(CONFIGURATION_FILE_PARAM);

		configurationFilename = fc.getServletContext().getRealPath(configurationFilename);
		
		if ( configurationFilename == null || ! new File(configurationFilename).exists() ) {
			throw new ServletException("[ESAPI WAF] Could not find configuration file at resolved path: " + configurationFilename);
		}

		/*
		 * Find out polling time from a parameter. If none is provided, use
		 * the default (10 seconds).
		 */
		
		String sPollingTime = fc.getInitParameter(POLLING_TIME_PARAM);
		
		if ( sPollingTime != null ) {
			pollingTime = Long.parseLong(sPollingTime);
		} else {
			pollingTime = DEFAULT_POLLING_TIME;
		}

		//Initial configuration loading
		LoadConfig();

		//Start the Poll Schedule 
		pollTimer = new Timer();
		File f = new File(configurationFilename);
		pollTimer.schedule(new PolicyRefreshPoll(this, f.lastModified()), this.pollingTime, this.pollingTime);
}

	/*
	 * Open up configuration file and populate the AppGuardian configuration object.
	 */
	private synchronized void LoadConfig() throws ServletException {
		try {
			String webRootDir = fc.getServletContext().getRealPath("/");
			appGuardConfig = ConfigurationParser.readConfigurationFile(new FileInputStream(configurationFilename),webRootDir);			
		} catch (FileNotFoundException e) {
			throw new ServletException(e);
		} catch (ConfigurationException e) {
			throw new ServletException(e);
		}
	}
		
	/**
	 * This is the where the main interception and rule-checking logic of the WAF resides.
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain chain) throws IOException, ServletException {
		
		logger.debug("Success >>In WAF doFilter");

		HttpServletRequest httpRequest = (HttpServletRequest)servletRequest;
		HttpServletResponse httpResponse = (HttpServletResponse)servletResponse;

		InterceptingHTTPServletRequest request = null;
		InterceptingHTTPServletResponse response = null;

		/*
		 * First thing to do is create the InterceptingHTTPServletResponse, since
		 * we'll need that possibly before the InterceptingHTTPServletRequest.
		 *
		 * The normal HttpRequest-type objects will suffice us until we get to
		 * stage 2.
		 *
		 * 1st argument = the response to base the instance on
		 * 2nd argument = should we bother intercepting the egress response?
		 * 3rd argument = cookie rules because thats where they mostly get acted on
		 */
		int responseRulesCount = appGuardConfig.getCookieRules().size() + appGuardConfig.getBeforeResponseRules().size();
		if (appGuardConfig.getResponseBodyAccess()) {
			if (responseRulesCount > 0) { //if there are rules to process then intercept response
				response = new InterceptingHTTPServletResponse(httpResponse, true, appGuardConfig.getCookieRules());
			}
		} else {
			if (responseRulesCount > 0) { //want on ignored rules
				logger.warn("ResponseBodyAccess disabled " + responseRulesCount + " cookie/response-specific rules will be ignored");
			}
		}
		/*
		 * Stage 1: Rules that do not need the request body.
		 */
		logger.debug("Success >> Starting stage 1" );

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);
			logger.debug("Success >> Applying BEFORE rule:  " + rule.getClass().getName() );
			
			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(httpRequest, response, httpResponse);

			if ( action.isActionNecessary() ) {
				if ( action instanceof BlockAction ) {
					if ( response != null ) {
						response.setStatus(((BlockAction)action).getStatusCode());
					} else {
						httpResponse.setStatus(((BlockAction)action).getStatusCode());
					}
					return;

				} else if ( action instanceof RedirectAction ) {
					//HttpSession httpSession = httpRequest.getSession();
					httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
					sendRedirect(httpRequest, response, httpResponse, ((RedirectAction)action).getRedirectURL()); 
					return;

				} else if ( action instanceof DefaultAction ) {				
					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							if ( response != null ) {
								response.setStatus(appGuardConfig.getDefaultResponseCode());
							} else {
								httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
							}
							return;
							
						case AppGuardianConfiguration.REDIRECT:
							//HttpSession httpSession = httpRequest.getSession();
							httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
							sendRedirect(httpRequest, response, httpResponse, appGuardConfig.getDefaultErrorPage());
							return;
					}
				}
			}
		}

		/*
		 * Create the InterceptingHTTPServletRequest.
		 */
		
		
		/*
		 * Stage 2: After the body has been read, but before the the application has gotten it.
		 */
		logger.debug("Success >> Starting Stage 2" );

		if (this.appGuardConfig.getResponseBodyAccess()) {
			try {
				request = new InterceptingHTTPServletRequest((HttpServletRequest)servletRequest);
			} catch (FileUploadException fue) {
				logger.error("Success >> Error Wrapping Request", fue );
			}
			rules = this.appGuardConfig.getAfterBodyRules();

			for(int i=0;i<rules.size();i++) {
	
				Rule rule = rules.get(i);
				logger.debug("Success >>  Applying BEFORE CHAIN rule:  " + rule.getClass().getName() );
	
				/*
				 * The rules execute in check(). The check() method will take care of logging. 
				 * All we have to do is decide what other actions to take.
				 */
				Action action = rule.check(request, response, httpResponse);
	
				if ( action.isActionNecessary() ) {
	
					if ( action instanceof BlockAction ) {
						if ( response != null ) {
							response.setStatus(((BlockAction)action).getStatusCode());
						} else {
							httpResponse.setStatus(((BlockAction)action).getStatusCode());
						}
						return;
	
					} else if ( action instanceof RedirectAction ) {
						//HttpSession httpSession = httpRequest.getSession();
						httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
						sendRedirect(httpRequest, response, httpResponse, ((RedirectAction)action).getRedirectURL()); 
						return;
	
					} else if ( action instanceof DefaultAction ) {				
						switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
							case AppGuardianConfiguration.BLOCK:
								if ( response != null ) {
									response.setStatus(appGuardConfig.getDefaultResponseCode());
								} else {
									httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
								}
								return;
								
							case AppGuardianConfiguration.REDIRECT:
								//HttpSession httpSession = httpRequest.getSession();
								httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
								sendRedirect(httpRequest, response, httpResponse, appGuardConfig.getDefaultErrorPage());
								return;
						}
					}
				}
			}
		}

		/*
		 * In between stages 2 and 3 is the application's processing of the input.
		 */
		logger.debug("Success >> Calling the FilterChain: " + chain );
		chain.doFilter(request != null ? request : httpRequest, response != null ? response : httpResponse);

		/*
		 * Stage 3: Before the response has been sent back to the user.
		 */
		logger.debug("Success >> Starting Stage 3" );
		
		if (appGuardConfig.getResponseBodyAccess()) { //Process response rules
			rules = this.appGuardConfig.getBeforeResponseRules();
	
			for(int i=0;i<rules.size();i++) {
	
				Rule rule = rules.get(i);
				logger.debug("Success >> Applying AFTER CHAIN rule:  " + rule.getClass().getName() );
	
				/*
				 * The rules execute in check(). The check() method will also log. All we have
				 * to do is decide what other actions to take.
				 */
				Action action = rule.check(request, response, httpResponse);
	
				if ( action.isActionNecessary() ) {
	
					if ( action instanceof BlockAction ) {
						if ( response != null ) {
							response.setStatus(((BlockAction)action).getStatusCode());
						} else {
							httpResponse.setStatus(((BlockAction)action).getStatusCode());
						}
						return;
	
					} else if ( action instanceof RedirectAction ) {
						//HttpSession httpSession = httpRequest.getSession();
						httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
						sendRedirect(httpRequest, response, httpResponse, ((RedirectAction)action).getRedirectURL()); 
						return;
	
					} else if ( action instanceof DefaultAction ) {				
						switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
							case AppGuardianConfiguration.BLOCK:
								if ( response != null ) {
									response.setStatus(appGuardConfig.getDefaultResponseCode());
								} else {
									httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
								}
								return;
								
							case AppGuardianConfiguration.REDIRECT:
								//HttpSession httpSession = httpRequest.getSession();
								httpRequest.setAttribute("ESAPIWAF_LastBrokenRule", rule);
								sendRedirect(httpRequest, response, httpResponse, appGuardConfig.getDefaultErrorPage());
								return;
						}
					}
				}
			}
		}

		/*
		 * Now that we've run our last set of rules we can allow the response to go through if
		 * we were intercepting.
		 */
		if ( response != null ) {
			response.LoadVariables(httpResponse);
			logger.debug("Success >>> committing reponse" );
			response.commit();
		}
	}

	/*
	 * Utility method to send HTTP redirects that automatically determines which response class to use.
	 */
	private void sendRedirect(HttpServletRequest request, InterceptingHTTPServletResponse response,
			HttpServletResponse httpResponse, String redirectURL) throws IOException, ServletException {
		
		ServletContext sc = request.getSession().getServletContext();
		String FWPath = redirectURL;
		if (FWPath.startsWith(sc.getContextPath())) {
			FWPath = FWPath.substring(sc.getContextPath().length());
		}
		if ( response != null ) { // if we've been buffering everything we clean it all out before sending back.
			response.reset();
			response.resetBuffer();
			sc.getRequestDispatcher(FWPath).forward(request, response);
			//response.sendRedirect(redirectURL);
			response.commit();
		} else {
			//httpResponse.sendRedirect(redirectURL);
			sc.getRequestDispatcher(FWPath).forward(request, httpResponse);
		}
		
	}

	public void destroy() {
		//Cancel poll
		pollTimer.cancel();
	}

	
	/*[JC Calderon] To avoid duplication, I commented this function out, as function above provides the same functionality */
	/*private void sendRedirect(InterceptingHTTPServletResponse response, HttpServletResponse httpResponse) throws IOException {
        /* [chrisisbeef] - commented out as this is not currently used. Minor performance tweak.
		String finalJavaScript = AppGuardianConfiguration.JAVASCRIPT_REDIRECT;
		finalJavaScript = finalJavaScript.replaceAll(AppGuardianConfiguration.JAVASCRIPT_TARGET_TOKEN, appGuardConfig.getDefaultErrorPage());
        */
		/*
		if ( response != null ) {
			response.reset();
			response.resetBuffer();
			/*
			response.setStatus(appGuardConfig.getDefaultResponseCode());
			response.getOutputStream().write(finalJavaScript.getBytes());
			*//*
			response.sendRedirect(appGuardConfig.getDefaultErrorPage());
			
		} else {
			if ( ! httpResponse.isCommitted() ) {
				httpResponse.sendRedirect(appGuardConfig.getDefaultErrorPage());
			} else {
				/*
				 * Can't send redirect because response is already committed. I'm not sure 
				 * how this could happen, but I didn't want to cause IOExceptions in case
				 * if it ever does. 
				 *//*
			}
			
		}
	}	*/

	private class PolicyRefreshPoll extends TimerTask {
		private ESAPIWebApplicationFirewallFilter filterReferer;
		private long lastConfigModifiedTime;
		public PolicyRefreshPoll(ESAPIWebApplicationFirewallFilter filterReferer, long lastConfigModifiedTime) {
			//Save reference to filter class for future call back
			this.filterReferer = filterReferer;
			this.lastConfigModifiedTime = lastConfigModifiedTime;
		}
		
		public void run() {
			try {
				File f = new File(this.filterReferer.configurationFilename);
				if (f.lastModified() != lastConfigModifiedTime) { 
					logger.debug("Success >> Re-reading WAF policy");
					this.filterReferer.LoadConfig();
					lastConfigModifiedTime = f.lastModified();
				}
			} catch (ServletException e) {
				logger.warn(e);
			}
		}
	}
}