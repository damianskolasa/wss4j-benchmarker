package net.fatfredyy.wss4j.benchmarker.main;

import java.security.Security;
import java.util.List;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.dbstore.HibernateUtil;
import net.fatfredyy.wss4j.benchmarker.dbstore.SignaturePerformanceSample;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hibernate.Session;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Main {

	private Crypto crypto = null;

	public Main() throws Exception {
		WSSConfig.init();
		crypto = CryptoFactory.getInstance();
	}

	public String checkECDSAwithSHA1Speed() throws Exception {

		return null;

	}

	public static AlgorithmSuite createECDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA256);
		algorithmSuite.setMinimumAsymmetricKeyLength(128);
		algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA256);

		return algorithmSuite;
	}

	public static AlgorithmSuite createAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA1);
		algorithmSuite.setMinimumAsymmetricKeyLength(512);
		algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA1);

		return algorithmSuite;
	}

	public void checkECDSAwithSHA1Loop() throws Exception {
		for (int i = 0; i < 1000; i++) {
			System.out.println(checkECDSAwithSHA1Speed());
			System.gc();
		}
	}

	public void checkRSAWithSHA1Speed() throws Exception {
		long start = System.currentTimeMillis();
		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm(WSConstants.RSA_SHA1);

		Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);
		Document signedDoc = builder.build(doc, crypto, secHeader);

		Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
		AlgorithmSuite algorithmSuite = createAlgorithmSuite();
		verify(securityHeader, algorithmSuite, crypto);
		long end = System.currentTimeMillis();
		System.out.println((end - start) + "ms");
	}

	public void checkRSAwithSHA1Loop() throws Exception {
		for (int i = 0; i < 1000; i++) {
			checkRSAWithSHA1Speed();
		}
	}

	private List<WSSecurityEngineResult> verify(Element securityHeader, AlgorithmSuite algorithmSuite, Crypto sigVerCrypto)
			throws Exception {
		WSSecurityEngine secEngine = new WSSecurityEngine();
		RequestData data = new RequestData();
		data.setSigCrypto(sigVerCrypto);

		data.setAlgorithmSuite(algorithmSuite);

		WSSConfig wssConfig = WSSConfig.getNewInstance();
		wssConfig.setWsiBSPCompliant(false);
		data.setWssConfig(wssConfig);

		return secEngine.processSecurityHeader(securityHeader, data);
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new XMLDSigRI());
		// if ("ecdsa".equalsIgnoreCase(args[1])) {
		// new ECDSABenchmarker().benchmark();
		// new DSABenchmarker().benchmark();
		// new RSABenchmarker().benchmark();
		// }

		

	}

}
