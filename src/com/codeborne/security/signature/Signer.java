package com.codeborne.security.signature;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.*;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;
import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.digidoc.factory.SAXDigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.apache.axis.Message;
import org.apache.axis.description.TypeDesc;
import org.apache.axis.encoding.SerializationContext;
import org.apache.axis.encoding.ser.BeanSerializer;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.xml.XMLConstants;
import javax.xml.rpc.ServiceException;
import javax.xml.rpc.holders.IntHolder;
import javax.xml.rpc.holders.StringHolder;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.codeborne.security.AuthenticationException.Code.valueOf;

public abstract class Signer {

    public static final String CONTENT_EMBEDDED = "EMBEDDED";
    public static final String CONTENT_EMBEDDED_BASE64 = "EMBEDDED_BASE64";
    public static final String CONTENT_BINARY = "BINARY";
    public static final String CONTENT_HASHCODE = "HASHCODE";
    public final String serviceName;


    public DigiDocServicePortType service;

    public static final String FORMAT_DIGIDOC_XML = "DIGIDOC-XML";
    public static final String VERSION_1_3 = "1.3";


    public Signer(String digidocServiceURL, String serviceName) throws MalformedURLException {
        setDigidocServiceURL(new URL(digidocServiceURL));
        this.serviceName = serviceName;
    }

    public final Signer setDigidocServiceURL(URL digidocServiceURL) {
        DigiDocService_Service digiDocService = new DigiDocService_ServiceLocator();
        try {
            service = digiDocService.getDigiDocService(digidocServiceURL);
        }
        catch (ServiceException e) {
            throw new RuntimeException("Failed to initialize Mobile-ID support", e);
        }
        return this;
    }

    /**
     * Application provider sends the files for signing (DigiDoc files or original
     * files) to DigiDoc Service within the StartSession request.
     *
     * As a result of the StartSession request also a created session identifier
     * is returned, what should be used in the headers of following requests.
     */
    public SignatureSession startSession(List<File> files) throws IOException, DigiDocException {

        ConfigManager.init("jar://JDigiDoc.cfg");
        SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        sdoc.setProfile(SignedDoc.BDOC_PROFILE_TM);
        DataFileInfo[] dataFiles= new DataFileInfo[files.size()];

        for (int i = 0; i < files.size(); i++) {
            File f = files.get(i);
            String mimeType=URLConnection.guessContentTypeFromName(f.getName());
            DataFile dataFile = sdoc.addDataFile(f, mimeType, DataFile.CONTENT_EMBEDDED_BASE64);
            FileInputStream fis = new FileInputStream(f);
            byte fileContent[] = new byte[(int) f.length()];
            fis.read(fileContent);
            dataFile.setBase64Body(fileContent);
            /*
            //TODO: calculate to use hash, so you don't send whole base64 document over the wire
            String dataRaw=dataFile.toString();
            ByteArrayInputStream bais=new ByteArrayInputStream(dataFile.toXML());
            dataFile.calcHashes(bais);
            */
        }

        StringHolder status = new StringHolder();
        IntHolder sessionCode = new IntHolder();
        SignedDocInfoHolder signedDocInfo=new SignedDocInfoHolder();

        //It’s not allowed to send to the service a data of the SigDocXML and the Datafile at the same time, as they exclude each other.
        try {
            String input = sdoc.toXML();
            input=input.replace("</DataFile>", "\n</DataFile>");
//            String docXML = StringEscapeUtils.escapeXml(input);
            String docXML = input;//StringEscapeUtils.escapeXml(input);
            service.startSession("", docXML, true, null, status, sessionCode, signedDocInfo);
            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
        return new SignatureSession(sessionCode.value, signedDocInfo.value, sdoc);

    }

    /**
     * function will calculate same value as php function base64_encode(pack("H*", sha1(str_replace("\r\n","\n",$src))))
     * @param sha
     * @param src
     * @return
     */
    public static String calculateMessageDigest(String sha, String src){
        try {
            MessageDigest md = MessageDigest.getInstance(sha);
            src=src.replace("\r\n","\n");
            byte[] rawSHA = md.digest(src.getBytes("UTF-8"));
            return new String(Base64.encodeBase64(rawSHA));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * The application provider inquires the content of the signed DigiDoc with request
     * A signed document is returned from the webservice within the GetSignedDoc
     * request. If there’s a will
     * to recieve the document information in structured format in addition to signed
     * document, the GetSignedDocInfo request should be used.
     * @return XML Digidoc String that can be saved as ready signature
     */
    public SignedDoc getSignedDoc(SignatureSession session) throws DigiDocException {
        try {
            StringHolder status = new StringHolder();
            StringHolder signedDocData = new StringHolder();
            service.getSignedDoc(session.sessCode, status, signedDocData);
            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            //The content of the document is in HTMLencoded format.
            String result = StringEscapeUtils.unescapeHtml4(signedDocData.value);
            DigiDocFactory factory = new SAXDigiDocFactory();
            return factory.readSignedDoc(result);


        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

    public static boolean sleep(int sleepTimeMilliseconds) {
        try {
            Thread.sleep(sleepTimeMilliseconds);
            return true;
        }
        catch (InterruptedException e) {
            return false;
        }
    }

    /**
     * The application closes the session with sending a CloseSession request
     * to the service.
     */
    public void closeSession(SignatureSession session){
        try {
            service.closeSession(session.sessCode);
        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        }
    }

/*
    public static String serialize(SignedDocInfo doc) throws IOException {
        BeanSerializer serializer = (BeanSerializer) SignedDocInfo.getSerializer("", SignedDocInfo.class, null);

        Writer writer = new StringWriter();
        TypeDesc typeDesc = SignedDocInfo.getTypeDesc();

        SerializationContext context= new SerializationContext(writer);
        context.setWriteXMLType(new javax.xml.namespace.QName(XMLConstants.W3C_XML_SCHEMA_NS_URI, "", ""));
//        context.setPretty(true);
        serializer.serialize(typeDesc.getXmlType(), null, doc, context);
        return writer.toString();
    }

    public static SignedDocInfo deSerialize(String xml){

        Object result = null;
       // String SOAP_START = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header /><soapenv:Body>";
        String SOAP_START_XSI = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Header /><soapenv:Body>";
        String SOAP_END = "</soapenv:Body></soapenv:Envelope>";
        xml=xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
        Message message = new Message(SOAP_START_XSI + xml + SOAP_END);
        try {
            result = message.getSOAPEnvelope().getFirstBody().getObjectValue(SignedDocInfo.class);
            return (SignedDocInfo) result;
        } catch (Exception e) {
            e.printStackTrace();
        }



        return null;


    }

    public static SignedDocInfo createDigidocContainer() {
        SignedDocInfo doc= new SignedDocInfo();
        doc.setFormat(FORMAT_DIGIDOC_XML);
        doc.setVersion(VERSION_1_3);
        return doc;
    }

    public static String CalculateBase64(File testFile){
        FileInputStream fileInputStream= null;
        try {
            fileInputStream = new FileInputStream(testFile);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            org.apache.commons.io.IOUtils.copy(fileInputStream, baos);
            return new String(Base64.encodeBase64(baos.toByteArray()));
        } catch (IOException e) {
            return null;
        }
    }
*/
}
