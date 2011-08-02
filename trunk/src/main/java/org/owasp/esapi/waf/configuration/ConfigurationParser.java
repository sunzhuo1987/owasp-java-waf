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
package org.owasp.esapi.waf.configuration;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.jws.WebParam.Mode;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Elements;
import nu.xom.ParsingException;
import nu.xom.ValidityException;

import org.apache.log4j.*;
import org.omg.CORBA.portable.ApplicationException;
import org.owasp.esapi.waf.ConfigurationException;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.BlockAction;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.configuration.ModSecRuleParser.BodyAccessEnum;
import org.owasp.esapi.waf.rules.AddHTTPOnlyFlagRule;
import org.owasp.esapi.waf.rules.AddHeaderRule;
import org.owasp.esapi.waf.rules.AddSecureFlagRule;
import org.owasp.esapi.waf.rules.AuthenticatedRule;
import org.owasp.esapi.waf.rules.BeanShellRule;
import org.owasp.esapi.waf.rules.DetectOutboundContentRule;
import org.owasp.esapi.waf.rules.EnforceHTTPSRule;
import org.owasp.esapi.waf.rules.HTTPMethodRule;
import org.owasp.esapi.waf.rules.IPRule;
import org.owasp.esapi.waf.rules.ModSecurityRule;
import org.owasp.esapi.waf.rules.MustMatchRule;
import org.owasp.esapi.waf.rules.PathExtensionRule;
import org.owasp.esapi.waf.rules.ReplaceContentRule;
import org.owasp.esapi.waf.rules.RestrictContentTypeRule;
import org.owasp.esapi.waf.rules.RestrictUserAgentRule;
import org.owasp.esapi.waf.rules.SimpleVirtualPatchRule;

import bsh.EvalError;
import bsh.ParseException;

/**
 * 
 * The class used to turn a policy file's contents into an object model. 
 * 
 * @author Arshan Dabirsiaghi
 * @author Juan Carlos Calderon
 * @see org.owasp.esapi.waf.AppGuardianConfiguration
 */
public class ConfigurationParser {

	public static final int DEFAULT_RESPONSE_CODE = 403;
	public static String defaultRedirectPage = "";
	public static final String DEFAULT_SESSION_COOKIE = "JSESSIONID";
	private static final String REGEX = "regex";
	private static final String DEFAULT_PATH_APPLY_ALL = ".*";
	private static org.apache.log4j.Logger logger;
	private static final String[] STAGES = {
		"before-request-body",
		"after-request-body",
		"before-response"
	};
	
	public static AppGuardianConfiguration readConfigurationFile(InputStream stream, String webRootDir) throws ConfigurationException {

		AppGuardianConfiguration config = new AppGuardianConfiguration();
		logger = Logger.getLogger(ConfigurationParser.class);
		Builder parser = new Builder();
		Document doc;
		Element root;

		try {

			doc = parser.build(stream);
			root = doc.getRootElement();

			Element aliasesRoot = root.getFirstChildElement("aliases");
			Element settingsRoot = root.getFirstChildElement("settings");
			Element authNRoot = root.getFirstChildElement("authentication-rules");
			Element authZRoot = root.getFirstChildElement("authorization-rules");
			Element urlRoot = root.getFirstChildElement("url-rules");
			Element headerRoot = root.getFirstChildElement("header-rules");
			Element customRulesRoot = root.getFirstChildElement("custom-rules");;
			Element virtualPatchesRoot = root.getFirstChildElement("virtual-patches");
			Element outboundRoot = root.getFirstChildElement("outbound-rules");
			Element beanShellRoot = root.getFirstChildElement("bean-shell-rules");
			Element modSecurityRoot = root.getFirstChildElement("mod_security-rules");
			
			/**
			 * Parse the 'aliases' section.
			 */
			if ( aliasesRoot != null ) {
				Elements aliases = aliasesRoot.getChildElements("alias");
	
				for(int i=0;i<aliases.size();i++) {
					Element e = aliases.get(i);
					String name = e.getAttributeValue("name");
					String type = e.getAttributeValue("type");
					String value = e.getValue();
					if ( REGEX.equals(type) ) {
						config.addAlias(name, Pattern.compile(value));
					} else {
						config.addAlias(name, value);
					}
				}
			}
			
			/**
			 * Parse the 'settings' section.
			 */
			if ( settingsRoot == null ) {
				throw new ConfigurationException("The <settings> section is required");
			} else if ( settingsRoot != null ) {
				
				
				try {
					String sessionCookieName = settingsRoot.getFirstChildElement("session-cookie-name").getValue();
					if ( ! "".equals(sessionCookieName) ) {
						config.setSessionCookieName(sessionCookieName);
					}
				} catch (NullPointerException npe) {
					config.setSessionCookieName(DEFAULT_SESSION_COOKIE);
				}

				String mode = settingsRoot.getFirstChildElement("mode").getValue();
				
				if ( "block".equals(mode.toLowerCase() ) ) {
					AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.BLOCK;
				} else if ( "redirect".equals(mode.toLowerCase() ) ){
					AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.REDIRECT;
				} else if ( "log".equals(mode.toLowerCase() ) ){
					AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.LOG;
				} else {
					logger.log(Level.WARN, "ESAPI WAF is working in log mode due to missing or non understandable mode setting");
					AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.LOG;
				}
				
				String processRequest = settingsRoot.getFirstChildElement("process-request-body").getValue();
				config.setRequestBodyAccess(processRequest.toLowerCase().equals("true"));

				String processResponse = settingsRoot.getFirstChildElement("process-response-body").getValue();
				config.setResponseBodyAccess(processResponse.toLowerCase().equals("true"));
	
				Element errorHandlingRoot = settingsRoot.getFirstChildElement("error-handling");
				
				synchronized (defaultRedirectPage) {
					defaultRedirectPage = errorHandlingRoot.getFirstChildElement("default-redirect-page").getValue() ;	
					config.setDefaultErrorPage(defaultRedirectPage);
				}
				try {
					//[JC]check code is into minimum and maximum HTTP response range, notice a value like 460 
					//or higher will not be valid but still this validation is better than nothing
					int blockCode = Integer.parseInt(errorHandlingRoot.getFirstChildElement("block-status").getValue());
					if (blockCode <100 && blockCode > 510) {  
						throw new ApplicationException("Block code is not in the range of valid numbers for HTTP response codes", null);
					}
					config.setDefaultResponseCode(blockCode);
				} catch (Exception e) {
					config.setDefaultResponseCode( DEFAULT_RESPONSE_CODE );
					logger.log(Level.WARN, "block-status is not set to an appropriate HTTP response code number, ESAPI WAF is using '" + DEFAULT_RESPONSE_CODE + "' response code instead");
				}
			}
			
			/**
			 * Parse the 'authentication-rules' section if they have one.
			 */
			if ( authNRoot != null ) {
				String key = authNRoot.getAttributeValue("key");
				String path = authNRoot.getAttributeValue("path");
				String id = authNRoot.getAttributeValue("id");
				String action = authNRoot.getAttributeValue("action");
				String target = authNRoot.getAttributeValue("target");
				String blockStatus = authNRoot.getAttributeValue("block-status");
				
				List<Object> AuthExepts = getExceptionsFromElement(authNRoot);
				//[JC]Add global default error page as exception for authentication rule
				AuthExepts.add(defaultRedirectPage);
				if ( path != null && key != null ) {	
					config.addBeforeBodyRule(new AuthenticatedRule(id,key,Pattern.compile(path), AuthExepts, getActionFromElement(action, target, blockStatus)));
				} else if ( key != null ) {
					config.addBeforeBodyRule(new AuthenticatedRule(id,key,null,AuthExepts, getActionFromElement(action, target, blockStatus)));
				} else {
					throw new ConfigurationException("The <authentication-rules> rule requires a 'key' attribute");
				}
			}

			/**
			 * Parse 'authorization-rules' section if they have one.
			 */

			if ( authZRoot != null ) {

				Elements restrictNodes = authZRoot.getChildElements("restrict-source-ip");

				for(int i=0;i<restrictNodes.size();i++) {

					Element restrictNodeRoot = restrictNodes.get(i);
					String id = restrictNodeRoot.getAttributeValue("id");
					Pattern ips = Pattern.compile(restrictNodeRoot.getAttributeValue("ip-regex"));
					String ipHeader = restrictNodeRoot.getAttributeValue("ip-header");
					String action = restrictNodeRoot.getAttributeValue("action");
					String target = restrictNodeRoot.getAttributeValue("target");
					String blockStatus = restrictNodeRoot.getAttributeValue("block-status");

					if ( REGEX.equalsIgnoreCase(restrictNodeRoot.getAttributeValue("type")) ) {
						config.addBeforeBodyRule( new IPRule(id, ips, Pattern.compile(restrictNodeRoot.getValue()),ipHeader, getActionFromElement(action,  target, blockStatus)));
					} else {
						config.addBeforeBodyRule( new IPRule(id, ips, restrictNodeRoot.getValue(), getActionFromElement(action,  target, blockStatus)) );
					}

				}

				Elements mustMatchNodes = authZRoot.getChildElements("must-match");

				for(int i=0;i<mustMatchNodes.size();i++) {

					Element e = mustMatchNodes.get(i);
					Pattern path = Pattern.compile(e.getAttributeValue("path"));
					String variable = e.getAttributeValue("variable");
					String value = e.getAttributeValue("value");
					String operator = e.getAttributeValue("operator");
					String id = e.getAttributeValue("id");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");

					int op = AppGuardianConfiguration.OPERATOR_EQ;

					if ( "exists".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_EXISTS;
					} else if ( "inList".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_IN_LIST;
					} else if ( "contains".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_CONTAINS;
					}

					config.addAfterBodyRule( new MustMatchRule(id, path,variable,op,value, getActionFromElement(action,  target, blockStatus)) );
				}

			}

			/**
			 * Parse the 'url-rules' section if they have one.
			 */
			if ( urlRoot != null ) {

				Elements restrictExtensionNodes = urlRoot.getChildElements("restrict-extension");
				Elements restrictMethodNodes = urlRoot.getChildElements("restrict-method");
				Elements enforceHttpsNodes = urlRoot.getChildElements("enforce-https");

				/*
				 * Read in rules that allow an app to restrict by extension.
				 * E.g., you may want to explicitly only allow:
				 *  .jsp, .jpg, .gif, .css, .js, etc.
				 *
				 * You may also want to instead explicitly deny:
				 * .bak, .log, .txt, etc.
				 */

				for (int i=0;i<restrictExtensionNodes.size();i++) {

					Element e = restrictExtensionNodes.get(i);
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					String id = e.getAttributeValue("id");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");

					if ( allow != null && deny != null ) {
						throw new ConfigurationException( "restrict-extension rules can't have both 'allow' and 'deny'" );
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new PathExtensionRule(id,Pattern.compile( ".*\\" + allow + "$"),null, getActionFromElement(action,  target, blockStatus)) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new PathExtensionRule(id, null,Pattern.compile( ".*\\" + deny + "$"), getActionFromElement(action,  target, blockStatus)) );

					} else {
						throw new ConfigurationException("restrict extension rule should have either a 'deny' or 'allow' attribute");
					}
				}

				/*
				 * Read in rules that allow the site to control
				 * which HTTP methods are allowed to reach the
				 * app.
				 *
				 * 99% of the time, you'll only need POST and
				 * GET.
				 */
				for (int i=0;i<restrictMethodNodes.size();i++) {

					Element e = restrictMethodNodes.get(i);

					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					String path = e.getAttributeValue("path");
					String id = e.getAttributeValue("id");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");

					if ( path == null ) {
						path = DEFAULT_PATH_APPLY_ALL;
					}

					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-method rule should not have both 'allow' and 'deny' values");
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new HTTPMethodRule(id, Pattern.compile(allow), null, Pattern.compile(path), getActionFromElement(action,  target, blockStatus)) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new HTTPMethodRule(id, null, Pattern.compile(deny), Pattern.compile(path), getActionFromElement(action,  target, blockStatus)) );

					} else {
						throw new ConfigurationException("restrict-method rule should have either an 'allow' or 'deny' value");
					}
				}

				for (int i=0;i<enforceHttpsNodes.size();i++) {

					Element e = (Element)enforceHttpsNodes.get(i);
					String path = e.getAttributeValue("path");
					String id = e.getAttributeValue("id");
					List<Object> exceptions = getExceptionsFromElement(e);

					config.addBeforeBodyRule( new EnforceHTTPSRule(id, Pattern.compile(path), exceptions) );
				}

			}

			if ( headerRoot != null ) {

				Elements restrictContentTypes = headerRoot.getChildElements("restrict-content-type");
				Elements restrictUserAgents = headerRoot.getChildElements("restrict-user-agent");

				for(int i=0;i<restrictContentTypes.size();i++) {

					Element e = restrictContentTypes.get(i);
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					String id = e.getAttributeValue("id");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");

					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-content-type rule should not have both 'allow' and 'deny' values");
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new RestrictContentTypeRule(id, Pattern.compile(allow), null, getActionFromElement(action,  target, blockStatus)) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new RestrictContentTypeRule(id, null, Pattern.compile(deny), getActionFromElement(action,  target, blockStatus)) );

					} else {
						throw new ConfigurationException("restrict-content-type rule should have either an 'allow' or 'deny' value");
					}
				}

				for(int i=0;i<restrictUserAgents.size();i++) {
					Element e = restrictUserAgents.get(i);
					String id = e.getAttributeValue("id");
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");
					int iblockStatus = config.getDefaultResponseCode();
					
					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-user-agent rule should not have both 'allow' and 'deny' values");
					}
					
					if (blockStatus != null) {
						iblockStatus = config.getDefaultResponseCode();
					}

					if ( allow != null ) {						
						config.addBeforeBodyRule( new RestrictUserAgentRule(id, Pattern.compile(allow), null, new BlockAction(iblockStatus)) );
					} else if ( deny != null ) {

						config.addBeforeBodyRule( new RestrictUserAgentRule(id, null, Pattern.compile(deny), new BlockAction(iblockStatus)) );

					} else {
						throw new ConfigurationException("restrict-user-agent rule should have either an 'allow' or 'deny' value");
					}
				}

			}

			if ( virtualPatchesRoot != null ) {
				Elements virtualPatchNodes = virtualPatchesRoot.getChildElements("virtual-patch");
				for(int i=0;i<virtualPatchNodes.size();i++) {
					Element e = virtualPatchNodes.get(i);
					String id = e.getAttributeValue("id");
					String path = e.getAttributeValue("path");
					String variable = e.getAttributeValue("variable");
					String pattern = e.getAttributeValue("pattern");
					String message = e.getAttributeValue("message");
					String required = e.getAttributeValue("required");
					boolean bRequired = (required!=null && "true".equals(required.toLowerCase()));
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");
					

					config.addAfterBodyRule( new SimpleVirtualPatchRule(id, Pattern.compile(path), variable, Pattern.compile(pattern), message, bRequired,getActionFromElement(action,  target, blockStatus)) );
				}
			}

			// Haven't implemented this yet. Not sure what we want those rules to look like.
			/*
			if ( customRulesRoot != null ) {
				Elements rules = customRulesRoot.getChildElements("rule");
				
				 // Parse the complex rules.
				 
			}
			*/
			
			if ( outboundRoot != null ) {

				/*
				 * Parse the <add-header> rules. This could be used to add:
				 * - X-I-DONT-WANT-TO-BE-FRAMED
				 * - Caching prevention headers
				 * - Custom application headers
				 */

				Elements addHeaderNodes = outboundRoot.getChildElements("add-header");

				for(int i=0;i<addHeaderNodes.size();i++) {
					Element e = addHeaderNodes.get(i);
					String name = e.getAttributeValue("name");
					String value = e.getAttributeValue("value");
					String path = e.getAttributeValue("path");
					String id = e.getAttributeValue("id");

					if ( path == null ) {
						path = DEFAULT_PATH_APPLY_ALL;
					}

					AddHeaderRule ahr = new AddHeaderRule(id, name, value, Pattern.compile(path), getExceptionsFromElement(e));
					config.addBeforeResponseRule(ahr);

				}

				/*
				 * Parse the <add-http-only-flag> rules that allow
				 * us to add the HTTPOnly flag to cookies, both
				 * custom and app server.
				 */
				Elements addHTTPOnlyFlagNodes = outboundRoot.getChildElements("add-http-only-flag");

				for(int i=0;i<addHTTPOnlyFlagNodes.size();i++) {
					Element e = addHTTPOnlyFlagNodes.get(i);

					Elements cookiePatterns = e.getChildElements("cookie");
					String id = e.getAttributeValue("id");
					ArrayList<Pattern> patterns = new ArrayList<Pattern>();

					for(int j=0;j<cookiePatterns.size();j++) {
						Element cookie = cookiePatterns.get(j);
						patterns.add(Pattern.compile(cookie.getAttributeValue("name")));
					}

					AddHTTPOnlyFlagRule ahfr = new AddHTTPOnlyFlagRule(id, patterns);
					config.addCookieRule(ahfr);

					if ( ahfr.doesCookieMatch(config.getSessionCookieName()) ) {
						config.setApplyHTTPOnlyFlagToSessionCookie(true);
					}
				}

				/*
				 * Parse the <add-secure-flag> rules that allow
				 * us to add the secure flag to cookies, both
				 * custom and app server.
				 */
				Elements addSecureFlagNodes = outboundRoot.getChildElements("add-secure-flag");

				for(int i=0;i<addSecureFlagNodes.size();i++) {
					Element e = addSecureFlagNodes.get(i);
					String id = e.getAttributeValue("id");
					Elements cookiePatterns = e.getChildElements("cookie");
					ArrayList<Pattern> patterns = new ArrayList<Pattern>();

					for(int j=0;j<cookiePatterns.size();j++) {
						Element cookie = cookiePatterns.get(j);
						patterns.add(Pattern.compile(cookie.getAttributeValue("name")));
					}

					AddSecureFlagRule asfr = new AddSecureFlagRule(id, patterns);
					config.addCookieRule(asfr);

					if ( asfr.doesCookieMatch(config.getSessionCookieName()) ) {
						config.setApplySecureFlagToSessionCookie(true);
					}

				}

				/*
				 * Parse dynamic-insertion nodes that allow us to dynamically
				 * insert stuff into responses.
				 */
				Elements dynamicInsertionNodes = outboundRoot.getChildElements("dynamic-insertion");

				for(int i=0;i<dynamicInsertionNodes.size();i++) {

					Element e = dynamicInsertionNodes.get(i);
					String pattern = e.getAttributeValue("pattern");
					String id = e.getAttributeValue("id");
					String contentType = e.getAttributeValue("content-type");
					String urlPaths = e.getAttributeValue("path");
					Element replacement = e.getFirstChildElement("replacement");

					ReplaceContentRule rcr = new ReplaceContentRule(
							id, 
							Pattern.compile(pattern,Pattern.DOTALL), 
							replacement.getValue(),
							contentType != null ? Pattern.compile(contentType) : null,
							urlPaths != null ? Pattern.compile(urlPaths) : null);
					
					config.addBeforeResponseRule(rcr);

				}

				/*
				 * Parse detect-content nodes that allow us to simply detect data
				 * leaving in responses.
				 */
				Elements detectContentNodes = outboundRoot.getChildElements("detect-content");

				for(int i=0;i<detectContentNodes.size();i++) {

					Element e = detectContentNodes.get(i);
					String token = e.getAttributeValue("pattern");
					String contentType = e.getAttributeValue("content-type");
					String id = e.getAttributeValue("id");
					String path = e.getAttributeValue("path");
					String action = e.getAttributeValue("action");
					String target = e.getAttributeValue("target");
					String blockStatus = e.getAttributeValue("block-status");

					if ( token == null ) {
						throw new ConfigurationException("<detect-content> rules must contain a 'pattern' attribute");
					} else if ( contentType == null ) {
						throw new ConfigurationException("<detect-content> rules must contain a 'content-type' attribute");
					}

					DetectOutboundContentRule docr = new DetectOutboundContentRule(
							id, 
							Pattern.compile(contentType),
							Pattern.compile(token,Pattern.DOTALL),
							path != null ? Pattern.compile(path) : null,
									getActionFromElement(action,  target, blockStatus));
					
					config.addBeforeResponseRule(docr);

				}

			}
			
			/**
			 * Parse the 'bean-shell-rules' section.
			 */
			
			if ( beanShellRoot != null ) {
			
				Elements beanShellRules = beanShellRoot.getChildElements("bean-shell-script");
				
				for (int i=0;i<beanShellRules.size(); i++) {

					Element e = beanShellRules.get(i);
					
					String id = e.getAttributeValue("id");
					String fileName = e.getAttributeValue("file");
					String stage = e.getAttributeValue("stage"); //
					String path = e.getAttributeValue("path");
					String message = e.getAttributeValue("message");
					
					if ( id == null ) {
						throw new ConfigurationException("bean shell rules all require a unique 'id' attribute");
					}
					
					if ( fileName == null ) {
						throw new ConfigurationException("bean shell rules all require a unique 'file' attribute that has the location of the .bsh script" );
					}
					
					try {
						
						BeanShellRule bsr = new BeanShellRule(
								webRootDir + fileName, 
								id,
								(path != null) ? Pattern.compile(path) : null, 
								message);
						
						if ( STAGES[0].equals(stage) ) {
							config.addBeforeBodyRule(bsr);
						} else if ( STAGES[1].equals(stage)) {
							config.addAfterBodyRule(bsr);
						} else if ( STAGES[2].equals(stage)) {
							config.addBeforeResponseRule(bsr);
						} else {
							throw new ConfigurationException("bean shell rules all require a 'stage' attribute when the rule should be fired (valid values are " + STAGES[0] + ", " + STAGES[1] + ", or " + STAGES[2] + ")" );
						}
												
					} catch (FileNotFoundException fnfe) {
						throw new ConfigurationException ("bean shell rule '" + id + "' had a source file that could not be found (" + fileName + "), web directory = " + webRootDir );
					} catch (EvalError ee) {
						String errorText ="Unknown";
						try {
							errorText = ee.getErrorText();
						} catch (NullPointerException npe) {
							//do nothing
						}
						logger.log(Level.ERROR, "bean shell rule '" + id + "' contains an error(" + errorText + "). Fix it and reload configuration : " + ee.getScriptStackTrace());
					}
					
				}
			}
			
			/**
			 * Parse the 'mod-security-rules' section.
			 */
			
			if ( modSecurityRoot != null ) {
				Elements ruleNodes = authZRoot.getChildElements("mod-security-rule");
				for(int i=0;i<ruleNodes.size();i++) {
					Element e = ruleNodes.get(i);
					String id = e.getAttributeValue("id");
					ModSecurityRule msr = new ModSecurityRule(id, e.getValue());
					int phase = msr.getPhase();
					if ( phase == 1) {
						config.addBeforeBodyRule(msr);
					} else if (phase == 2) {
						config.addAfterBodyRule(msr);
					} else if (phase == 3 || phase == 4) {  //Phase 3, 4 Before headers and body is sent to user
						config.addBeforeResponseRule(msr);
					} else {
						throw new ConfigurationException ("Mod Security Rule '" + id + "' does not specifies a phase to apply it");
					}
				}
				
				ruleNodes = authZRoot.getChildElements("rules-file");
				for(int i=0;i<ruleNodes.size();i++) {
					Element e = ruleNodes.get(i);
					ModSecRuleParser msrp = new ModSecRuleParser();
					//Add parse file and add rules to configuration object
					msrp.addRulesToConfig(e.getAttributeValue("filepath"), config);
					if (e.getAttributeValue("mod-security-overide-globals").toLowerCase() == "true") {
						//Change WAF mode are per Mod Security settings
						if ( msrp.getSecRuleEngine() == ModSecRuleParser.RuleEngineEnum.Off ) {
							//TODO: This mode is not supported
						} else if ( msrp.getSecRuleEngine() == ModSecRuleParser.RuleEngineEnum.On ){
							//TODO: This mode is not supported, WAF is always on
						} else if ( msrp.getSecRuleEngine() == ModSecRuleParser.RuleEngineEnum.DetectionOnly ){
							AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.LOG;
							logger.log(Level.WARN, "ESAPI WAF is working in log mode due to Mod Security SecRuleEngine directive override, disable mod-security-overide-globals to prevent this");
						} else {
							AppGuardianConfiguration.DEFAULT_FAIL_ACTION = AppGuardianConfiguration.LOG;
							logger.log(Level.WARN, "ESAPI WAF is working in log mode due to missing or non understandable mode setting");
						}
						//Change process request body as per Mod Security settings
						config.setRequestBodyAccess(msrp.getSecRequestBodyAccess() == BodyAccessEnum.On);
						//Change process response body as per Mod Security settings
						config.setResponseBodyAccess(msrp.getSecResponseBodyAccess() == BodyAccessEnum.On);
					}
				}
			}

		} catch (ValidityException e) {
			throw new ConfigurationException(e);
		} catch (ParsingException e) {
			throw new ConfigurationException(e);
		} catch (IOException e) {
			throw new ConfigurationException(e);
		}

		return config;

	}

	private static List<Object> getExceptionsFromElement(Element root) {
		Elements exceptions = root.getChildElements("path-exception");
		ArrayList<Object> exceptionList = new ArrayList<Object>();

		for(int i=0;i<exceptions.size();i++) {
			Element e = exceptions.get(i);
			if ( REGEX.equalsIgnoreCase(e.getAttributeValue("type"))) {
				exceptionList.add( Pattern.compile(e.getValue()) );
			} else {
				exceptionList.add( e.getValue() );
			}
		}
		return exceptionList;
	}

	private static Action getActionFromElement (String action, String target, String blockStatus) {
		if (action == null) {
			return new DefaultAction();
		} else if ( "block".equals(action.toLowerCase() ) ) {
			int iblockStatus = DEFAULT_RESPONSE_CODE; 
			if (blockStatus != null) {
				try {
					//[JC] validate block code to be at least into the range of valid HTTP response codes
					int tempblockStatus = Integer.parseInt(blockStatus);
					if (tempblockStatus >= 100 && tempblockStatus <= 510){
						iblockStatus = tempblockStatus;
					}
				} finally {}
			}
			return new BlockAction(iblockStatus);
		} else if ( "redirect".equals(action.toLowerCase() ) ){
			if (target != null){
				return new RedirectAction(target);
			} else {
				return new RedirectAction(defaultRedirectPage);
			}
		} 
		//Then just log the issue
		logger.warn("Rule Action not recognized, check spelling");
		return new DoNothingAction();
	}
	
}
