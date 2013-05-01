package net.fatfredyy.wss4j.benchmarker.ecdsa;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.String2WSConstantsMapper;
import net.fatfredyy.wss4j.benchmarker.dbstore.HibernateUtil;
import net.fatfredyy.wss4j.benchmarker.dbstore.SignaturePerformanceSample;
import net.fatfredyy.wss4j.benchmarker.main.SortJavaCurves;

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

public class ECDSABenchmarker {

	private boolean first = true;

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");

	private SummaryStatistics signStat = new SummaryStatistics();
	private SummaryStatistics vrfStat = new SummaryStatistics();

	public ECDSABenchmarker() throws Exception {
	}

	public void benchmark() throws Exception {

		SortJavaCurves.initialize();


		for (Integer size : SortJavaCurves.keySizes) {
			List<String> curveNames = SortJavaCurves.size2NameListMap.get(size);
			for (String curveName : curveNames) {
				for (String certDigestAlg : digestAlgorithms) {
					for (String digestAlg : digestAlgorithms) {
						if (first) {
							benchmarkLoop(curveName, certDigestAlg,
									String2WSConstantsMapper.string2WSconstantMap.get("ECDSA_" + digestAlg),
									String2WSConstantsMapper.string2WSconstantMap.get(digestAlg), digestAlg, size);
							first = false;
						}
						benchmarkLoop(curveName, certDigestAlg, String2WSConstantsMapper.string2WSconstantMap.get("ECDSA_" + digestAlg),
								String2WSConstantsMapper.string2WSconstantMap.get(digestAlg), digestAlg, size);
					}

				}

			}
		}
	}

	private void benchmarkLoop(String curveName, String certDigest, String algSuit, String digest, String digestName, Integer size)
			throws Exception {
		System.out.println("Trying: " + curveName + ", " + certDigest + ", " + algSuit + ", " + digestName);
		for (int i = 0; i < 10; i++) {
			banchmarkSignle(curveName, certDigest, algSuit, digest, size, digestName);
		}
		if (first) {
			return;
		}
		
		SignaturePerformanceSample sign = new SignaturePerformanceSample();
		SignaturePerformanceSample vrf = new SignaturePerformanceSample();
		
		sign.setCurveName(curveName);
		sign.setKeySize(size);
		sign.setDigestName(digestName);
		sign.setCertDigestName(certDigest);
		sign.setMin(signStat.getMin());
		sign.setMax(signStat.getMax());
		sign.setMean(signStat.getMean());
		sign.setVariance(signStat.getVariance());
		sign.setStdDeviation(signStat.getStandardDeviation());
		sign.setScheme("ECC");
		sign.setSign(true);
		sign.setType("A");
		
		vrf.setCurveName(curveName);
		vrf.setKeySize(size);
		vrf.setDigestName(digestName);
		vrf.setCertDigestName(certDigest);
		vrf.setMin(vrfStat.getMin());
		vrf.setMax(vrfStat.getMax());
		vrf.setMean(vrfStat.getMean());
		vrf.setVariance(vrfStat.getVariance());
		vrf.setStdDeviation(vrfStat.getStandardDeviation());
		vrf.setScheme("ECC");
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

	private void banchmarkSignle(String curveName, String certDigest, String algSuit, String digest, Integer size, String digestName) throws Exception {
		Properties ecdsaMerlinProperties = createECDSAMerlinProperties(curveName, certDigest);
		Crypto ecdsaCrypto = CryptoFactory.getInstance(ecdsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(ecdsaCrypto, algSuit, digest);
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(ecdsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		if (!first) {
			signStat.addValue(new Double(mid - start));
			vrfStat.addValue(new Double(end - mid));
			
			
			SignaturePerformanceSample sign = new SignaturePerformanceSample();
			SignaturePerformanceSample vrf = new SignaturePerformanceSample();
			
			sign.setCurveName(curveName);
			sign.setKeySize(size);
			sign.setDigestName(digestName);
			sign.setCertDigestName(certDigest);
			sign.setMin(new Double(mid - start));
			sign.setVariance(signStat.getVariance());
			sign.setStdDeviation(signStat.getStandardDeviation());
			sign.setScheme("ECC");
			sign.setSign(true);
			sign.setType("S");
			
			vrf.setCurveName(curveName);
			vrf.setKeySize(size);
			vrf.setDigestName(digestName);
			vrf.setCertDigestName(certDigest);
			vrf.setMin(new Double(end - mid));
			vrf.setVariance(vrfStat.getVariance());
			vrf.setStdDeviation(vrfStat.getStandardDeviation());
			vrf.setScheme("ECC");
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

	private void verifySOAPMessageSignature(Crypto ecdsaCrypto, Document signedDoc) throws WSSecurityException, Exception {
		Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);

		AlgorithmSuite algorithmSuite = createECDSAAlgorithmSuite();
		verify(securityHeader, algorithmSuite, ecdsaCrypto);
	}

	private Document signSOAPMessage(Crypto ecdsaCrypto, String signatureAlg, String digestAlg) throws Exception, WSSecurityException {
		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo("privateKey", "123456");
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm(signatureAlg);
		builder.setDigestAlgo(digestAlg);

		Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);
		Document signedDoc = builder.build(doc, ecdsaCrypto, secHeader);
		return signedDoc;
	}

	private static AlgorithmSuite createECDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA512);
		algorithmSuite.setMinimumAsymmetricKeyLength(100);
		algorithmSuite.setMaximumAsymmetricKeyLength(600);
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

	private static Properties createECDSAMerlinProperties(String curveName, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file",
				"keys/ks_ec_" + curveName + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}

}
