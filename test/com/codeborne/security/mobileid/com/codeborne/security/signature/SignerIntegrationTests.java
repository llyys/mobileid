package com.codeborne.security.mobileid.com.codeborne.security.signature;

import com.codeborne.security.digidoc.mapping.DataFile;
import com.codeborne.security.signature.MobileIDSigner;
import com.codeborne.security.signature.SignatureSession;
import com.codeborne.security.signature.Signer;
import com.codeborne.security.signature.SmartcardSigner;
import org.apache.commons.io.FileUtils;
import org.jdom2.JDOMException;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * These integration tests are meant to execute manually, before executing tests you must add missing files in test folder
 */
public class SignerIntegrationTests {
    String path = SignerIntegrationTests.class.getProtectionDomain().getCodeSource().getLocation().getPath();
//    @Before
    public void setUp(){

        File keystore = new File(path, "keystore.jks");
        if (!keystore.exists())
            throw new RuntimeException("File not found: " + keystore.getAbsolutePath());

        System.setProperty("javax.net.ssl.trustStore", keystore.getAbsolutePath());
    }

    //@Test
    public void canExecuteMobileIdSigningIntegration() throws Exception {
        File testFile = new File(path, "test.txt");
        MobileIDSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new MobileIDSigner("https://www.openxades.org:9443/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files);
            signer.mobileSign(session, "37903236510", "+3725227475", "Testimine", 0, true, true );
            if(signer.waitForSigning(session)){
                signer.getSignedDoc(session);
            }
        }finally {
            signer.closeSession(session);
        }
    }

    //@Test
    public void canExecuteSmartCardSigningIntegration() throws Exception {
        File testFile = new File(path, "test.txt");
        SmartcardSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new SmartcardSigner("https://digidocservice.sk.ee/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files);
            File certFile=new File(path, "cert.txt");

            String cert=FileUtils.readFileToString(certFile);


            String hash=signer.PrepareSignature(session, cert, "S0", "", "", "", "", "", "Testimine");

            String doc2 = signer.FinalizeSignature(session, "signature");
            //SignedDoc doc2 = signer.getSignedDoc(session);

        }finally {
            signer.closeSession(session);
        }
    }


    @Test
    public void IsMessageDigestCalculationAccordingToSpeck() {
        String res = Signer.calculateMessageDigest("SHA-1", "VGhpcyBpcyBhIHRlc3QgZmlsZQ0Kc2Vjb25kbGluZQ0KdGhpcmRsaW5l");
        assertEquals("DkgfEv8kuG5ZlsZaECSD6pHypzg=", res);
    }

   // @Test
    public void canGenerateSignedDocWidthCompactDataNodes() throws JAXBException, IOException, JDOMException {
        com.codeborne.security.digidoc.mapping.SignedDoc doc = new com.codeborne.security.digidoc.mapping.SignedDoc();
        File testFile = new File(path, "test.txt");

        DataFile dataFile = doc.addEmbeddedFile(testFile);

        assertNotSame("", dataFile.getContentValue());
        assertNull(dataFile.getDigestType());
        assertNull(dataFile.getDigestValue());
        String hash=dataFile.calculateHash();

        assertEquals("SHA1", dataFile.getDigestType());
        assertEquals(dataFile.getDigestValue(), hash);
        assertEquals("", dataFile.getContentValue());
        String result=doc.toXml();
        assertNotNull(result);
        List<File> files = new ArrayList<File>();
        files.add(testFile);
        //this will be needed after downloading document from digidoc service and adding Base64 content to it.
        String result2=Signer.appendDatafileDigestContent(result, files);
        assertNotSame(result, result2);
    }

    @Test
    public void canGenerateStringToHex(){
        String test="Test text to be converted as HEX";
        assertEquals("54657374207465787420746f20626520636f6e76657274656420617320484558", SmartcardSigner.bin2hex(test.getBytes()));
    }

    @Test
    public void canConvertDerToPem() throws IOException {
        //PEM certificate is base64 encoded string and it need to be converted to binary DER
        File testFile = new File(path, "cert.pem");
        File assertFile = new File(path, "cert.der");
        String cert=FileUtils.readFileToString(testFile);
        byte[] derResult= SmartcardSigner.convertPemToDer(cert);
        byte[] der=FileUtils.readFileToByteArray(assertFile);
        assertEquals(derResult.length, der.length);
        assertArrayEquals(derResult, der);
        String hex = SmartcardSigner.bin2hex(derResult);
        assertNotNull(hex);

    }

}
