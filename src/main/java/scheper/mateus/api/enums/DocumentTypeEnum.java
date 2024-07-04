package scheper.mateus.api.enums;

import dev.langchain4j.data.document.DocumentParser;
import dev.langchain4j.data.document.parser.TextDocumentParser;
import dev.langchain4j.data.document.parser.apache.pdfbox.ApachePdfBoxDocumentParser;
import dev.langchain4j.data.document.parser.apache.poi.ApachePoiDocumentParser;
import lombok.Getter;

@Getter
public enum DocumentTypeEnum {

    DOCX("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", new ApachePoiDocumentParser()),
    DOC("application/msword", "doc", new ApachePoiDocumentParser()),
    PDF("application/pdf", "pdf", new ApachePdfBoxDocumentParser()),
    TEXT("text/plain", "txt", new TextDocumentParser());

    private final String mimeType;

    private final String extension;

    private final DocumentParser documentParser;

    DocumentTypeEnum(String mimeType, String extension, DocumentParser documentParser) {
        this.mimeType = mimeType;
        this.extension = extension;
        this.documentParser = documentParser;
    }

    public static DocumentParser asParser(String type) {
        for (DocumentTypeEnum documentTypeEnum : DocumentTypeEnum.values()) {
            if (documentTypeEnum.getMimeType().equals(type)) {
                return documentTypeEnum.getDocumentParser();
            }
        }
        return null;
    }

    public static String getExtensions() {
        return String.join(", ", "." + DOCX.getExtension(), "." + DOC.getExtension(), "." + PDF.getExtension());
    }
}
