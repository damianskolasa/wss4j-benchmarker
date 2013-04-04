package net.fatfredyy.wss4j.benchmarker;

import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.ws.security.WSConstants;

public class String2WSConstantsMapper {
	
	public static HashMap<String, String> string2WSconstantMap = new LinkedHashMap<String, String>();
	
	static {
		string2WSconstantMap.put("SHA1", WSConstants.SHA1);
		string2WSconstantMap.put("SHA256", WSConstants.SHA256);
		string2WSconstantMap.put("SHA384", WSConstants.SHA384);
		string2WSconstantMap.put("SHA512", WSConstants.SHA512);
		string2WSconstantMap.put("ECDSA_SHA1", WSConstants.ECDSA_SHA1);
		string2WSconstantMap.put("ECDSA_SHA256", WSConstants.ECDSA_SHA256);
		string2WSconstantMap.put("ECDSA_SHA384", WSConstants.ECDSA_SHA384);
		string2WSconstantMap.put("ECDSA_SHA512", WSConstants.ECDSA_SHA512);
		string2WSconstantMap.put("DSA_SHA1", WSConstants.DSA_SHA1);
		string2WSconstantMap.put("DSA_SHA256", WSConstants.DSA_SHA256);
		string2WSconstantMap.put("DSA_SHA384", WSConstants.DSA_SHA384);
		string2WSconstantMap.put("DSA_SHA512", WSConstants.DSA_SHA512);
		string2WSconstantMap.put("RSA_SHA1", WSConstants.RSA_SHA1);
		string2WSconstantMap.put("RSA_SHA256", WSConstants.RSA_SHA256);
		string2WSconstantMap.put("RSA_SHA384", WSConstants.RSA_SHA384);
		string2WSconstantMap.put("RSA_SHA512", WSConstants.RSA_SHA512);
	}

}
