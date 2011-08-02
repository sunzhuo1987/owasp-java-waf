/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Juan Carlos Calderon
 * @created 2011
 */
package org.owasp.esapi.waf.configuration;

import java.io.*;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.sound.sampled.LineListener;

import org.apache.log4j.Logger;
import org.owasp.esapi.waf.ConfigurationException;
import org.owasp.esapi.waf.rules.ModSecurityRule;

import sun.rmi.runtime.Log;

public class ModSecRuleParser {
	
	public static enum RuleEngineEnum {On, Off, DetectionOnly};
	private RuleEngineEnum SecRuleEngine;
			
	public static enum BodyAccessEnum {On, Off};
	private BodyAccessEnum SecRequestBodyAccess;
	private BodyAccessEnum SecResponseBodyAccess;
	
	public ModSecRuleParser() {	}
	
	public void addRulesToConfig(String RulesFilePath, AppGuardianConfiguration config) throws IOException, ConfigurationException {
		Logger logger = Logger.getLogger(ModSecRuleParser.class);
		FileReader fis = new FileReader(RulesFilePath);
		BufferedReader bis = new BufferedReader(fis);
		int lineNum=0;
		while (bis.ready()) {
			String line = bis.readLine().trim();
			lineNum++;
			if (!line.startsWith("#") && !line.equals("")) {
				//Include multiple lines in single logical line
				while (line.endsWith("\\") && bis.ready()){
					line = line.substring(0, line.length()-2) +  bis.readLine();
				}
				//Process Line
				String lowerCaseLine = line.toLowerCase();
				if (lowerCaseLine.startsWith("SecRuleEngine")) {
					if (lowerCaseLine.endsWith("on")) {
						setSecRuleEngine(RuleEngineEnum.On);
					} else if (lowerCaseLine.endsWith("off")) {
						setSecRuleEngine(RuleEngineEnum.Off);
					}else if (lowerCaseLine.endsWith("detectiononly")) {
						setSecRuleEngine(RuleEngineEnum.DetectionOnly);
					} else {
						logger.warn("SecRuleEngine directive value not recognized, setting ignored");
					}
					continue;
				}
				if (lowerCaseLine.startsWith("SecRequestBodyAccess")) {
					if (lowerCaseLine.endsWith("on")) {
						setSecRequestBodyAccess(BodyAccessEnum.On);
					} else if (lowerCaseLine.endsWith("off")) {
						setSecRequestBodyAccess(BodyAccessEnum.Off);
					} else {
						logger.warn("SecRequestBodyAccess directive value not recognized, setting ignored"); 
					}
					continue;
				}
				if (lowerCaseLine.startsWith("SecResponseBodyAccess")) {
					if (lowerCaseLine.endsWith("on")) {
						setSecResponseBodyAccess(BodyAccessEnum.On);
					} else if (lowerCaseLine.endsWith("off")) {
						setSecResponseBodyAccess(BodyAccessEnum.Off);
					} else {
						logger.warn("SecResponseBodyAccess directive value not recognized, setting ignored"); 
					}
					continue;
				}
				if (line.toLowerCase().startsWith("SecRule")) {
					Pattern pattern = Pattern.compile("([^\\s]+)\\s+([^\\s]+)\\s+\"(.+)\"\\s+\"(.+)\"");
					Matcher ss = pattern.matcher(line);
					if (ss.find()) {
						ModSecurityRule r = new ModSecurityRule();
						r.setRuleName(ss.group(1));
						r.setTargets (ss.group(2));
						r.setExpression (ss.group(3));
						r.setCommands (ss.group(4).split(","));
						int phase = r.getPhase();
						if ( phase == 1) {
							config.addBeforeBodyRule(r);
						} else if (phase == 2) {
							config.addAfterBodyRule(r);
						} else if (phase == 3 || phase == 4) {  //Phase 3, 4 Before headers and body is sent to user
							config.addBeforeResponseRule(r);
						} else {
							logger.error("Mod Security Rule '" + r.getId() + "' does not specifies a phase to apply it, rule was ignored");
						}
					}
					continue;
				}
				logger.error(RulesFilePath + " (Line " + lineNum + "): Not recognized as Level 1 Mod_Security rule or directive");
			}
		}
		bis.close();
		fis.close();
	}

	private ArrayList<String> SelectItems(String targets) {
		ArrayList<String> result = new ArrayList<String>(); 
		String[] targetsList = targets.split("|");
		ArrayList<String> targetNames = new ArrayList<String>(); 
		ArrayList<String> exceptionNames = new ArrayList<String>();
		for (String target : targetsList) {
			if (target.startsWith("!")) {
				exceptionNames.add(target.substring(1));
			} else {
				targetNames.add(target);
			}
			for (String targetName : targetNames) {
				if (targetName.equals("ARGS")) {
					/*for (String[] values : InterceptingHTTPServletRequest.ARGS) {
						
					}*/
				}		
			}
			//TODO: select variables and add them to the result 
			//as long as they are not part of the exceptions 
		}
		return result;
	}

	public void setSecRuleEngine(RuleEngineEnum secRuleEngine) {
		SecRuleEngine = secRuleEngine;
	}

	public RuleEngineEnum getSecRuleEngine() {
		return SecRuleEngine;
	}

	public void setSecRequestBodyAccess(BodyAccessEnum secRequestBodyAccess) {
		SecRequestBodyAccess = secRequestBodyAccess;
	}

	public BodyAccessEnum getSecRequestBodyAccess() {
		return SecRequestBodyAccess;
	}

	public void setSecResponseBodyAccess(BodyAccessEnum secResponseBodyAccess) {
		SecResponseBodyAccess = secResponseBodyAccess;
	}

	public BodyAccessEnum getSecResponseBodyAccess() {
		return SecResponseBodyAccess;
	}

	
}