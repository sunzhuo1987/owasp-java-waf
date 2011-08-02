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
 * @author Juan Carlos Calderon
 * @created 2009
 */
package org.owasp.esapi.waf.internal;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;

/**
 * The wrapper for the HttpServletRequest object which will be passed to the application
 * being protected by the WAF. It contains logic for parsing multipart parameters out of
 * the request and provided downstream application logic a way of accessing it like it 
 * hasn't been touched.
 * 
 * @author Arshan Dabirsiaghi
 *
 */
public class InterceptingHTTPServletRequest extends HttpServletRequestWrapper {

	//private ArrayList<Parameter> allParameters;
	//private ArrayList<String> allParameterNames;
	private static int CHUNKED_BUFFER_SIZE = 1024;
	
	private boolean isMultipart = false;
	private RandomAccessFile requestBody;
	private RAFInputStream is;
	
	public Map<String, String[]> ARGS;
	public ArrayList<String> ARGS_NAMES;
	public String QUERY_STRING;
	public String REMOTE_ADDR;
	public String REQUEST_BASENAME;
	public String REQUEST_BODY;
	public ArrayList<String> REQUEST_COOKIES = new ArrayList<String>();
	public ArrayList<String> REQUEST_COOKIES_NAMES = new ArrayList<String>();
	public String REQUEST_FILENAME;
	public Hashtable<String, String[]> REQUEST_HEADERS;
	public ArrayList<String> REQUEST_HEADERS_NAMES;
	public String REQUEST_LINE;
	public String REQUEST_METHOD;
	public String REQUEST_PROTOCOL;
	public String REQUEST_URI;
	public String REQUEST_URI_RAW;
	
	public ServletInputStream getInputStream() throws IOException {
		if ( isMultipart ) {
			return is;	
		} else {
			return super.getInputStream();
		}
        
    }
	
	public BufferedReader getReader() throws IOException {
        String enc = getCharacterEncoding();
        if(enc == null) enc = "UTF-8";
        return new BufferedReader(new InputStreamReader(getInputStream(), enc));
    }
	
	public InterceptingHTTPServletRequest(HttpServletRequest request) throws FileUploadException, IOException {

		super(request);

		this.ARGS = request.getParameterMap();
		this.ARGS_NAMES = (ArrayList<String>)Collections.list(request.getAttributeNames());
		this.QUERY_STRING = request.getQueryString();
		this.REMOTE_ADDR= request.getRemoteAddr() ;
		this.REQUEST_BASENAME= request.getServletPath() ;
		this.REQUEST_LINE = request.getMethod() + " " + request.getRequestURL() + (QUERY_STRING!=null?QUERY_STRING:"") + " " + request.getProtocol();		
		
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for(int i=0; i< cookies.length; i++) {
				Cookie c = cookies[i];
				this.REQUEST_COOKIES.add(c.getValue());
				this.REQUEST_COOKIES_NAMES.add(c.getName());
			}
		}
		this.REQUEST_FILENAME = request.getRequestURI();
		this.REQUEST_HEADERS_NAMES = (ArrayList<String>)Collections.list(this.getHeaderNames());
		this.REQUEST_HEADERS = new Hashtable<String, String[]>(Math.round(REQUEST_HEADERS_NAMES.size()*1.2f), 0.9f); //try to get the initial capacity as needed avoiding reassignment
		for (int i=0; i<this.REQUEST_HEADERS_NAMES.size(); i++){
			String ThisHeaderName = this.REQUEST_HEADERS_NAMES.get(i);
			ArrayList<String> al = (ArrayList<String>)Collections.list(request.getHeaders(ThisHeaderName));
			this.REQUEST_HEADERS.put(ThisHeaderName, al.toArray(new String[]{}));
		}
		this.REQUEST_METHOD = request.getMethod();
		this.REQUEST_PROTOCOL = request.getProtocol();  //TODO:Difference of URI and URI_RAW
		this.REQUEST_URI = this.getRequestURI() + (QUERY_STRING!=null?"?" + QUERY_STRING:"");
		this.REQUEST_URI_RAW = this.getRequestURL() + (QUERY_STRING!=null?"?" + QUERY_STRING:"");

		
		//allParameters = new ArrayList<Parameter>();
		//allParameterNames = new ArrayList<String>();


		/*
		 * Get all the regular parameters.
		 */

		/* [JC] why create this one if we already have it
		 * 
		 * Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			allParameters.add(new Parameter(param,request.getParameter(param),false));
			allParameterNames.add(param);
		}*/


		/*
		 * Get all the multipart fields.
		 */

		isMultipart = ServletFileUpload.isMultipartContent(request);

		if ( isMultipart ) {

			requestBody = new RandomAccessFile( File.createTempFile("oew","mpc"), "rw");
			
	    	byte buffer[] = new byte[CHUNKED_BUFFER_SIZE];

	    	long size = 0;
	    	int len = 0;

	    	while ( len != -1 && size <= Integer.MAX_VALUE) {
	    		len = request.getInputStream().read(buffer, 0, CHUNKED_BUFFER_SIZE);
	    		if ( len != -1 ) {
	    			size += len;
	    			requestBody.write(buffer,0,len);	
	    		}
	    	}
			
	    	is = new RAFInputStream(requestBody);
	    	
			ServletFileUpload sfu = new ServletFileUpload();
			FileItemIterator iter = sfu.getItemIterator(this);

			while(iter.hasNext()) {
				FileItemStream item = iter.next();
				String name = item.getFieldName();
				InputStream stream = item.openStream();

				/*
				 * If this is a regular form field, add it to our
				 * parameter collection.
				 */

				if (item.isFormField()) {

					String value = Streams.asString(stream);

					/* [JC] *removed* storing the values on the new parameters
					 * allParameters.add(new Parameter(name,value,true));
			    	allParameterNames.add(name);*/
					if (this.ARGS.containsKey(name)) {
						//Move values to a new (larger) array
						String[] values =  this.ARGS.get(name);
						String[] newvalues = new String[values.length+1];
						for (int i =0; i<newvalues.length; i++) {
							newvalues[i] = values [i];
						}
						//add value to array
						newvalues[newvalues.length-1] = value;
						this.ARGS.put(name, newvalues);
					} else {
						//add a new item to the map
						String[] values = {value};
						this.ARGS.put(name, values);
						this.ARGS_NAMES.add(name);
					}
			    } else {
			    	/*
			    	 * This is a multipart content that is not a
			    	 * regular form field. Nothing to do here.
			    	 */
			    	
			    }

			}
			
			requestBody.seek(0);
			// Read the request Body and save it to its corresponding string variable.
            byte[] arr = new byte[255];
            int read=0;
            StringBuffer sb = new StringBuffer();
            while ((read = requestBody.read(arr)) != -1) {
            	sb.append(arr);
            }
            // Close the file.
            requestBody.close();
            this.REQUEST_BODY = sb.toString();
			
			
		}

	}

	/*public String getDictionaryParameter(String s) {
		/*for(int i=0;i<allParameters.size();i++) {
			Parameter p = allParameters.get(i);
			if ( p.getName().equals(s) ) {
				return p.getValue();
			}
		}*
		//[JC] a Faster way to find an item? 
		//FIXME: if there is more than one parameter with that name? an array should be returned
		int index = ARGS....indexOf(s);
		return (index == -1)? null: allParameters.get(index).getValue();
	}*/

	/*public Iterator<String> getDictionaryParameterNames() {
		return allParameterNames.iterator();
	}*/
	
	
	private class RAFInputStream extends ServletInputStream {
		
		RandomAccessFile raf;
		
		public RAFInputStream(RandomAccessFile raf) throws IOException {
			this.raf = raf;
			this.raf.seek(0);
		}

		public int read() throws IOException {
			return raf.read();
		}
		
		public synchronized void reset() throws IOException {
			raf.seek(0);
		}
	}
	
}
