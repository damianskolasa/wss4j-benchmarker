package net.fatfredyy.wss4j.benchmarker.main;

import java.security.Security;

import net.fatfredyy.wss4j.benchmarker.ecdsa.ECDSABenchmarker;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.ws.security.WSSConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {


	public Main() throws Exception {
		WSSConfig.init();
	}


	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new XMLDSigRI());
		// if ("ecdsa".equalsIgnoreCase(args[1])) {
		new ECDSABenchmarker().benchmark();
		 //new RSABenchmarker().benchmark();
		// }

		

	}

}
