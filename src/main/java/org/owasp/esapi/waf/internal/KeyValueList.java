package org.owasp.esapi.waf.internal;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.regex.*;

public class KeyValueList extends java.util.ArrayList<KeyValueList.KeyValuePair> {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5859410239525681996L;

	/**
	 * Gets all the keys in the list
	 * @return List Iterator with references to all the keys in the list
	 */
	public ListIterator<String> getAllKeys() {
		ArrayList<String> keys = new ArrayList<String>();
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext();) {
			keys.add(it.next().Key);
		}
		return keys.listIterator();
	}
	
	/**
	 * Gets all the KeyValuePairs in the list that contain an specific value string
	 * @return List Iterator with references to matched KeyValuePairs 
	 */
	public ListIterator<KeyValuePair> getPairs(String Value) {
		ArrayList<KeyValuePair> result = new ArrayList<KeyValuePair>();
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext();) {
			KeyValuePair kvp = it.next();
			if (kvp.Value.equals(Value)) {
				result.add (kvp);
			}
		}
		return result.listIterator();
	}
	
	/**
	 * Gets all the KeyValuePairs that matches an specific key name and Value 
	 * @return List Iterator with references to all the keys in the list
	 */
	public ListIterator<KeyValuePair> getFilteredPairs(String KeyName, String Value) {
		ArrayList<KeyValuePair> results = new ArrayList<KeyValuePair>();
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext();) {
			KeyValuePair kvp = it.next();
			if (kvp.Key.equals(KeyName) && kvp.Value.equals(Value)) {
				results.add (kvp);
			}
		}
		return results.listIterator();
	}
			
	/**
	 * Get all the values that matches specific regular expression and contains an specific value
	 * @return List iterator with all the references to the values related to the desired key
	 */
	public ListIterator<KeyValuePair> getFilteredPairs(Pattern KeyRegEx, String Value) {
		ArrayList<KeyValuePair> result = new ArrayList<KeyValuePair>(5); //Assuming a small amount of items will be returned that is the most common case
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext(); ) {
			KeyValuePair kvp = it.next();
			if (KeyRegEx.matcher(kvp.Key).matches() && kvp.Value.equals(Value)){
				result.add(kvp);
			}
		}
		return result.listIterator();
	}
	
	/**
	 * Gets all the KeyValuePairs in the list that contain an specific value string
	 * @return List Iterator with references to matched KeyValuePairs 
	 */
	public ListIterator<KeyValuePair> getPairs(Pattern ValueRegEx) {
		ArrayList<KeyValuePair> result = new ArrayList<KeyValuePair>();
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext();) {
			KeyValuePair kvp = it.next();
			if (ValueRegEx.matcher(kvp.Value).matches()) {
				result.add (kvp);
			}
		}
		return result.listIterator();
	}
	
	/**
	 * Gets all the KeyValuePairs that matches an specific key name and Value 
	 * @return List Iterator with references to all the keys in the list
	 */
	public ListIterator<KeyValuePair> getFilteredPairs(String KeyName, Pattern RegExValue) {
		ArrayList<KeyValuePair> results = new ArrayList<KeyValuePair>();
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext();) {
			KeyValuePair kvp = it.next();
			if (kvp.Key.equals(KeyName) && RegExValue.matcher(kvp.Value).matches()) {
				results.add (kvp);
			}
		}
		return results.listIterator();
	}
			
	/**
	 * Get all the values that matches specific regular expression and contains an specific value
	 * @return List iterator with all the references to the values related to the desired key
	 */
	public ListIterator<KeyValuePair> getFilteredPairs(Pattern KeyRegEx, Pattern ValueRegEx) {
		ArrayList<KeyValuePair> result = new ArrayList<KeyValuePair>(5); //Assuming a small amount of items will be returned that is the most common case
		for (Iterator<KeyValuePair> it = this.iterator(); it.hasNext(); ) {
			KeyValuePair kvp = it.next();
			if (KeyRegEx.matcher(kvp.Key).matches() && ValueRegEx.matcher(kvp.Value).matches()){
				result.add(kvp);
			}
		}
		return result.listIterator();
	}
	
	public class KeyValuePair {
		public String Key;
		public String Value;
		
		public KeyValuePair() {}
		
		public KeyValuePair(String Key, String Value) {
			this.Key = Key;
			this.Value = Value;
		}
	}
}


