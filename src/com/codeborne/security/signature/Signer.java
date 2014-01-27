package com.codeborne.security.signature;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.DigiDocServicePortType;
import com.codeborne.security.digidoc.DigiDocService_Service;
import com.codeborne.security.digidoc.DigiDocService_ServiceLocator;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;
import com.codeborne.security.digidoc.mapping.DataFile;
import com.codeborne.security.digidoc.mapping.SignedDoc;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import javax.xml.bind.JAXBException;
import javax.xml.rpc.ServiceException;
import javax.xml.rpc.holders.IntHolder;
import javax.xml.rpc.holders.StringHolder;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static com.codeborne.security.AuthenticationException.Code.valueOf;

public abstract class Signer {

    public final String serviceName;
    public DigiDocServicePortType service;

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
    public SignatureSession startSession(List<File> files) throws Exception {
        return startSession(files, false);
    }

    /**
     *
     * @param files
     * @param compact if true, then actual file content is not sent to the service. So after successful signing user must add file again to appendDatafileDigestContent method
     * @return
     * @throws Exception
     */
    public SignatureSession startSession(List<File> files, boolean compact) throws Exception {

        SignedDoc sDoc=new SignedDoc();

        for (int i = 0; i < files.size(); i++) {
            File f = files.get(i);
            com.codeborne.security.digidoc.mapping.DataFile dataFile = sDoc.addEmbeddedFile(f);

            if(compact)
                dataFile.calculateHash();
        }

        StringHolder status = new StringHolder();
        IntHolder sessionCode = new IntHolder();
        SignedDocInfoHolder signedDocInfo=new SignedDocInfoHolder();

        try {
            String docXML = sDoc.toXml();
            service.startSession("", docXML, true, null, status, sessionCode, signedDocInfo);
            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

        } catch (RemoteException e) {
            throw new AuthenticationException(e);
        } catch (JAXBException e) {
            throw new Exception(e);
        }
        SignatureSession session = new SignatureSession(sessionCode.value, signedDocInfo.value);
        session.isCompact=compact;
        session.files=files;
        return session;

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
     * @return SignedDoc
     */
    public String getSignedDoc(SignatureSession session) throws Exception {
        try {
            StringHolder status = new StringHolder();
            StringHolder signedDocData = new StringHolder();
            service.getSignedDoc(session.sessCode, status, signedDocData);
            if (!"OK".equals(status.value))
                throw new AuthenticationException(valueOf(status.value));

            //The content of the document may be in HTMLencoded format.
            String result = StringEscapeUtils.unescapeHtml4(signedDocData.value);
            return result;

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

    /**
     * This mehtod is required if used StartSession widht compact version.
     * It means that after signing there acutally are no file content in it. So to add this you must reappend all files
     * in data container. To iterate how many DataFiles are in container, it's good to iterate over SignatureSession.
     * @param xml
     * @param files - all signing process files now will add content to it
     * @return
     * @throws JDOMException
     * @throws IOException
     */
    public static String appendDatafileDigestContent(String xml, List<File> files) throws JDOMException, IOException {
        SAXBuilder builder = new SAXBuilder();
        Document doc = builder.build(IOUtils.toInputStream(xml));
        Element rootNode = doc.getRootElement();

        List<Element> dataFiles = rootNode.getChildren();
        for (Element dataFile : dataFiles){
            for(File file:files)
            {
                if(dataFile.getName().equalsIgnoreCase("DataFile") && dataFile.getAttributeValue("Filename").equalsIgnoreCase(file.getName())) {
                    if(dataFile.getContentSize()==0) {
                        FileInputStream fis = null;
                        try {
                            fis = new FileInputStream(file);
                            byte fileContent[] = new byte[(int) file.length()];
                            fis.read(fileContent);
                            dataFile.addContent(new String(Base64.encodeBase64(fileContent))+"\n");
                            Attribute contentType = dataFile.getAttribute("ContentType");
                            contentType.setValue(DataFile.CONTENT_EMBEDDED_BASE64);//add also back attribute to embedded base.
                        }
                        finally {
                            fis.close();
                        }
                    }
                }
            }
        }

        XMLOutputter xmlOutput = new XMLOutputter();

        xmlOutput.setFormat(Format.getPrettyFormat());
        StringWriter sw = new StringWriter();
        xmlOutput.output(doc, sw);
        return sw.toString();
    }

}
