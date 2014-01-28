package com.codeborne.security.mobileid.com.codeborne.security.signature;

import com.codeborne.security.digidoc.mapping.DataFile;
import com.codeborne.security.signature.MobileIDSigner;
import com.codeborne.security.signature.SignatureSession;
import com.codeborne.security.signature.Signer;
import com.codeborne.security.signature.SmartcardSigner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.jdom2.JDOMException;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * These integration tests are meant to execute manually, before executing tests you must add missing files in test folder
 */
public class SignerIntegrationTests {
    String path = SignerIntegrationTests.class.getProtectionDomain().getCodeSource().getLocation().getPath();
    boolean hasRequiredFiles=true;
    @Before
    public void setUp(){

        File keystore = new File(path, "keystore.jks");
        if(keystore==null)
        {
            hasRequiredFiles=false;
            return;
        }
        if (!keystore.exists())
            throw new RuntimeException("File not found: " + keystore.getAbsolutePath());

        System.setProperty("javax.net.ssl.trustStore", keystore.getAbsolutePath());
    }

    @Test
    public void canExecuteMobileIdSigningIntegration() throws Exception {
        if (!hasRequiredFiles)
            return;
        File testFile = new File(path, "test.txt");

        Properties properties=getProperties();

        MobileIDSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new MobileIDSigner("https://www.openxades.org:9443/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files);

            signer.mobileSign(session, properties.getProperty("personalcode"), properties.getProperty("mobileno"), "Testimine", 0, true, true );
            if(signer.waitForSigning(session)){
                signer.getSignedDoc(session);
            }
        }finally {
            signer.closeSession(session);
        }
    }

    private Properties getProperties() throws IOException {
        File properties = new File(path, "test.properties");
        Properties props=new Properties();
        FileInputStream fis=new FileInputStream(properties);
        props.load(fis);
        IOUtils.closeQuietly(fis);
        return props;
    }

    @Test
    public void canExecuteSmartCardSigningIntegration() throws Exception {
        if (!hasRequiredFiles)
            return;
        File testFile = new File(path, "test.txt");
        SmartcardSigner signer =null;
        SignatureSession session=null;
        try{

            signer = new SmartcardSigner("https://www.openxades.org:9443/", "Testimine");

            List<File> files=new ArrayList<File>();
            files.add(testFile);
            session = signer.startSession(files, true);
            File certFile=new File(path, "cert.pem");

            String cert=FileUtils.readFileToString(certFile);


            String hash=signer.PrepareSignature(session, cert, "S0", "", "", "", "", "", "Testimine");

            String doc2 = signer.FinalizeSignature(session, "804EAB68865ED2DAF6BA11CE7D59D6E2244B16EF361C29A4E04421857D5B3148615A50D11C29100DBC3381826D9C888C83C4A9C6D35FF7A13B8F764C48349A9A3222BCAC6DC7FA4D836121457C4F0B9CAEFA7568C398AEE24839A7F192842F0E9A6DBFA1534E02E4A43C4F84E8BD58BD4324B1F46828F0DC3DAFFBEAD3B249D0");
            File file = new File(path, "testresult.ddoc");
            if(file.exists())
                file.delete();
            FileUtils.writeStringToFile(file, doc2);
            //SignedDoc doc2 = signer.getSignedDoc(session);

        }finally {
            signer.closeSession(session);
        }
    }




    @Test
    public void canGenerateSignedDocWidthCompactDataNodes() throws JAXBException, IOException, JDOMException {
        if (!hasRequiredFiles)
            return;
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
    public void canConvertDerToPem() throws IOException {
        if (!hasRequiredFiles)
            return;
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
