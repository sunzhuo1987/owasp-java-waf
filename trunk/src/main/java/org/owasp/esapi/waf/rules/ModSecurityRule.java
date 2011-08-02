package org.owasp.esapi.waf.rules;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class ModSecurityRule extends Rule {
	private String RuleName;
	private int Phase;
	private String Targets;
	private String Expression;
	private String[] Commands;
	
	public ModSecurityRule () {}
	public ModSecurityRule (String Id, String RuleText) {
		this.id = Id;
		//TODO: parse rule text
	}
	
	public String getId() {
		return this.id;
	}

	public void setRuleName(String ruleName) {
		RuleName = ruleName;
	}

	public String getRuleName() {
		return RuleName;
	}

	public void setTargets(String targets) {
		Targets = targets;
	}

	public String getTargets() {
		return Targets;
	}

	public void setExpression(String expression) {
		Expression = expression;
	}

	public String getExpression() {
		return Expression;
	}

	public void setCommands(String[] commands) {
		Commands = commands;
	}

	public String[] getCommands() {
		return Commands;
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Rulename: " + RuleName + ", Targets: " + Targets + ", Expresssion: " + Expression + ", Commands: [");
		for (int i = 0; i < Commands.length; i++) {
			sb.append("Command " + i + ":" + Commands[i]);
		}
		sb.append("]");
		return  sb.toString();
	}
	
	@Override
	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response,
			HttpServletResponse httpResponse) {
		// TODO Auto-generated method stub
		return new DoNothingAction();
	}
	public void setPhase(int phase) {
		Phase = phase;
	}
	public int getPhase() {
		return Phase;
	}
	
	

}
