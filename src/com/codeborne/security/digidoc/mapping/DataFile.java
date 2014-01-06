package com.codeborne.security.digidoc.mapping;

import com.codeborne.security.signature.Signer;
import org.apache.commons.codec.binary.Base64;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.namespace.QName;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;


public class DataFile implements Serializable {

    /** allowed values for content type */
    public static final String CONTENT_EMBEDDED = "EMBEDDED";
    public static final String CONTENT_EMBEDDED_BASE64 = "EMBEDDED_BASE64";
    public static final String CONTENT_BINARY = "BINARY";
    public static final String CONTENT_HASHCODE = "HASHCODE";

    @XmlAttribute(name = "ContentType")
    private String contentType;

    @XmlAttribute(name = "Filename")
    private String filename;

    @XmlAttribute(name = "Id")
    private String id;

    @XmlAttribute(name = "MimeType")
    private String mimeType;

    @XmlAttribute(name = "Size")
    private long size;

    @XmlValue
    private String contentValue;

    @XmlAttribute(name = "DigestType")
    private String digestType;

    @XmlAttribute(name = "DigestValue")
    private String digestValue;


    @XmlTransient
    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }
    @XmlTransient
    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }
    @XmlTransient
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
    @XmlTransient
    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }
    @XmlTransient
    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }
    @XmlTransient
    public String getContentValue() {
        return contentValue;
    }

    public void setContentValue(String contentValue) {
        this.contentValue = contentValue;
    }

    //sending hash code instead of full data file to the service for signing
    public String calculateHash(){
        try {
            String xml=this.toXml();
            String hash=Signer.calculateMessageDigest("SHA-1", xml);
            digestType="SHA1";
            digestValue=hash;
            setContentType(CONTENT_HASHCODE);
            contentValue="";//content will be cleared when digestValue exists. After finalizing we must put content value back to document via dom manipulation
            return hash;
        } catch (JAXBException e) {
            e.printStackTrace();
        }
        return null;

    }


    public String toXml() throws JAXBException {
        StringWriter writer = new StringWriter();
        JAXBContext context = null;

        context = JAXBContext.newInstance(SignedDoc.class);

        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        m.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
        m.marshal(new JAXBElement(new QName("", "DataFile"), DataFile.class,  this), writer);
        return writer.toString();
    }


    public String getDigestType() {
        return digestType;
    }

    public String getDigestValue() {
        return digestValue;
    }
}
