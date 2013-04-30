package net.fatfredyy.wss4j.benchmarker.rsa;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.String2WSConstantsMapper;
import net.fatfredyy.wss4j.benchmarker.dbstore.HibernateUtil;
import net.fatfredyy.wss4j.benchmarker.dbstore.SignaturePerformanceSample;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;
import org.hibernate.Session;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class RSABenchmarker {

	private boolean first = true;

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");

	static List<String> keySizes = Arrays.asList("1024", "3072", "7680", "15360");
	
	private SummaryStatistics signStat = new SummaryStatistics();
	private SummaryStatistics vrfStat = new SummaryStatistics();

	public RSABenchmarker() throws Exception {
	}

	public void benchmark() throws Exception {
		
		for (String keySize : keySizes) {
			for (String certDigestAlg : digestAlgorithms) {
				for (String digestAlg : digestAlgorithms) {
					benchmarkLoop(keySize, certDigestAlg, digestAlg);
				}
			}
		}
	}

	private void benchmarkLoop(String size, String certDigest, String digest) throws Exception {
		System.out.println("Trying: " + size + ", " + certDigest + ", " + digest);
		if (first) {
			banchmarkSignle(size, certDigest, digest);
			first = false;
		}

		for (int i = 0; i < 10; i++) {
			banchmarkSignle(size, certDigest, digest);
		}
		SignaturePerformanceSample sign = new SignaturePerformanceSample();
		SignaturePerformanceSample vrf = new SignaturePerformanceSample();
		
		sign.setKeySize(Integer.valueOf(size));
		sign.setDigestName(digest);
		sign.setCertDigestName(certDigest);
		sign.setMin(signStat.getMin());
		sign.setMax(signStat.getMax());
		sign.setMean(signStat.getMean());
		sign.setVariance(signStat.getVariance());
		sign.setStdDeviation(signStat.getStandardDeviation());
		sign.setScheme("RSA");
		sign.setSign(true);
		sign.setType("A");
		
		vrf.setKeySize(Integer.valueOf(size));
		vrf.setDigestName(digest);
		vrf.setCertDigestName(certDigest);
		vrf.setMin(vrfStat.getMin());
		vrf.setMax(vrfStat.getMax());
		vrf.setMean(vrfStat.getMean());
		vrf.setVariance(vrfStat.getVariance());
		vrf.setStdDeviation(vrfStat.getStandardDeviation());
		vrf.setScheme("RSA");
		vrf.setSign(false);
		vrf.setType("A");
		
		Session session = HibernateUtil.getSessionFactory().openSession();

		session.beginTransaction();

		session.save(sign);
		session.save(vrf);

		session.getTransaction().commit();
		session.flush();
		
		signStat = new SummaryStatistics();
		vrfStat = new SummaryStatistics();
		System.gc();
	}

	public void banchmarkSignle(String size, String certDigest, String digest) throws Exception {
		Properties dsaMerlinProperties = createDSAMerlinProperties(size, certDigest);
		Crypto dsaCrypto = CryptoFactory.getInstance(dsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(dsaCrypto, String2WSConstantsMapper.string2WSconstantMap.get("RSA_" + digest),
				String2WSConstantsMapper.string2WSconstantMap.get(digest));
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(dsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		if (!first) {
			signStat.addValue(new Double(mid - start));
			vrfStat.addValue(new Double(end - mid));
			
			SignaturePerformanceSample sign = new SignaturePerformanceSample();
			SignaturePerformanceSample vrf = new SignaturePerformanceSample();
			
			sign.setKeySize(Integer.valueOf(size));
			sign.setDigestName(digest);
			sign.setCertDigestName(certDigest);
			sign.setMin(new Double(mid - start));
			sign.setVariance(signStat.getVariance());
			sign.setStdDeviation(signStat.getStandardDeviation());
			sign.setScheme("RSA");
			sign.setSign(true);
			sign.setType("S");
			
			vrf.setKeySize(Integer.valueOf(size));
			vrf.setDigestName(digest);
			vrf.setCertDigestName(certDigest);
			vrf.setMin(new Double(end - mid));
			vrf.setVariance(vrfStat.getVariance());
			vrf.setStdDeviation(vrfStat.getStandardDeviation());
			vrf.setScheme("RSA");
			vrf.setSign(false);
			vrf.setType("S");
			
			Session session = HibernateUtil.getSessionFactory().openSession();

			session.beginTransaction();

			session.save(sign);
			session.save(vrf);

			session.getTransaction().commit();
			session.flush();
		}

		System.gc();
	}

	private void verifySOAPMessageSignature(Crypto dsaCrypto, Document signedDoc) throws WSSecurityException, Exception {
		Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);

		AlgorithmSuite algorithmSuite = createDSAAlgorithmSuite();
		verify(securityHeader, algorithmSuite, dsaCrypto);
	}

	private Document signSOAPMessage(Crypto dsaCrypto, String signatureAlg, String digestAlg) throws Exception, WSSecurityException {
		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo("privateKey", "123456");
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm(signatureAlg);
		builder.setDigestAlgo(digestAlg);

		Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);
		Document signedDoc = builder.build(doc, dsaCrypto, secHeader);
		return signedDoc;
	}

	private static AlgorithmSuite createDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA512);
		algorithmSuite.setMinimumAsymmetricKeyLength(128);
		algorithmSuite.setMaximumAsymmetricKeyLength(8192);
		algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA1);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA256);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA384);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA512);
		return algorithmSuite;
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

	private static Properties createDSAMerlinProperties(String size, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file",
				"/home/none/mgr_workspace/certgenerator/src/test/resources/ks_rsa_" + size + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}

}
