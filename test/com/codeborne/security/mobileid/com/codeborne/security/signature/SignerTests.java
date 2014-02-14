package com.codeborne.security.mobileid.com.codeborne.security.signature;

import com.codeborne.security.digidoc.mapping.DataFile;
import com.codeborne.security.digidoc.mapping.SignedDoc;
import com.codeborne.security.signature.Signer;
import com.codeborne.security.signature.SmartcardSigner;
import org.junit.Test;

import javax.xml.bind.JAXBException;

import static org.junit.Assert.assertEquals;

public class SignerTests {
    /**
     * test will make sure that in documetation described 8.1 StartSession hash generator will generate proper hash on datafile
     * @throws javax.xml.bind.JAXBException
     */
    @Test
    public void isDataFileDigestValueAsSpec() throws JAXBException {
        DataFile df=new DataFile();
        df.setContentType(DataFile.CONTENT_EMBEDDED_BASE64);
        df.setContentValue("VGhpcyBpcyBhIHRlc3QgZmlsZQ0Kc2Vjb25kbGluZQ0KdGhpcmRsaW5l\n");
        df.setFilename("test.txt");
        df.setId("D0");
        df.setMimeType("text/plain");
        df.setSize(42);
        String result=df.toXml();

        df.calculateHash();
        assertEquals("t8eRSrKTgR4PAAKTLYWGCjuTSJA=", df.getDigestValue());

        String compactXml=df.toXml();

        assertEquals("<DataFile xmlns=\"http://www.sk.ee/DigiDoc/v1.3.0#\" ContentType=\"HASHCODE\" Filename=\"test.txt\" Id=\"D0\" MimeType=\"text/plain\" Size=\"42\" DigestType=\"sha1\" DigestValue=\"t8eRSrKTgR4PAAKTLYWGCjuTSJA=\"></DataFile>"
                , compactXml);
    }


    @Test
    public void IsMessageDigestCalculationAccordingToSpeck() {
        String res = Signer.calculateMessageDigest("SHA-1", "VGhpcyBpcyBhIHRlc3QgZmlsZQ0Kc2Vjb25kbGluZQ0KdGhpcmRsaW5l");
        assertEquals("DkgfEv8kuG5ZlsZaECSD6pHypzg=", res);
    }

    @Test
    public void canGenerateStringToHex(){
        String test="Test text to be converted as HEX";
        assertEquals("54657374207465787420746f20626520636f6e76657274656420617320484558", SmartcardSigner.bin2hex(test.getBytes()));
    }

    @Test
    public void isBase64SplittingCorrect(){
        String test="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjx4bWk6WE1JIHhtaTp2ZXJzaW9uPSIyLjAiIHhtbG5zOnhtaT0iaHR0cDovL3d3dy5vbWcub3JnL1hNSSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy=";
        String result=
                "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjx4bWk6WE1J\r\n" +
                "IHhtaTp2ZXJzaW9uPSIyLjAiIHhtbG5zOnhtaT0iaHR0cDovL3d3dy5vbWcub3Jn\r\n" +
                "L1hNSSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy=\r\n";
        assertEquals(result, SignedDoc.encodeToChunckedBase64(test));
    }


}
