package com.codeborne.security.digidoc.mapping;

import org.apache.commons.codec.binary.Base64;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.*;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "SignedDoc")
public class SignedDoc implements Serializable {
    public SignedDoc() {
        format="DIGIDOC-XML";
        version="1.3";
        dataFiles=new ArrayList<DataFile>();
    }

    @XmlAttribute
    String format;

    @XmlAttribute(name = "xmlns")
    String namespace= "http://www.sk.ee/DigiDoc/v1.3.0#";

    @XmlAttribute
    String version;

    @XmlElement(name = "DataFile")
    public List<DataFile> dataFiles;

    public void addDataFile(DataFile e) {
        e.setId("D"+dataFiles.size());
        dataFiles.add(e);
    }

    public String toXml() throws JAXBException{
        StringWriter writer = new StringWriter();
        JAXBContext context = null;

        context = JAXBContext.newInstance(SignedDoc.class);

        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");

        m.marshal(this, writer);

        return writer.toString();
    }

    public DataFile addEmbeddedFile(File file) throws IOException {
        DataFile e = new DataFile();
        e.setContentType(DataFile.CONTENT_EMBEDDED_BASE64);
        e.setFilename(file.getName());


        String mimeType= URLConnection.guessContentTypeFromName(file.getName());
        e.setMimeType(mimeType == null ? "application/octet-stream" : mimeType);

        e.setSize(file.length());

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            byte fileContent[] = new byte[(int) file.length()];
            fis.read(fileContent);
            e.setContentValue(new String(Base64.encodeBase64(fileContent))+"\n"); //documentation insist linebreak at the end of encoded content
        }
        finally {
            if(fis!=null)
                fis.close();

        }
        addDataFile(e);
        return e;
    }


}

