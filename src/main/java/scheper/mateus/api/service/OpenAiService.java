package scheper.mateus.api.service;

import dev.langchain4j.chain.ConversationalRetrievalChain;
import dev.langchain4j.data.document.Document;
import dev.langchain4j.data.document.DocumentParser;
import dev.langchain4j.data.document.loader.FileSystemDocumentLoader;
import dev.langchain4j.data.document.splitter.DocumentSplitters;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.input.PromptTemplate;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.openai.OpenAiEmbeddingModel;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.content.retriever.EmbeddingStoreContentRetriever;
import dev.langchain4j.store.embedding.EmbeddingStoreIngestor;
import dev.langchain4j.store.embedding.inmemory.InMemoryEmbeddingStore;
import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import scheper.mateus.api.enums.DocumentTypeEnum;
import scheper.mateus.api.exception.BusinessException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

@Service
public class OpenAiService {

    @Value("${openai.token}")
    private String openaiToken;

    @Value("${openai.model}")
    private String openaiModel;

    @Value("${openai.embeddings.model}")
    private String openaiEmbeddingsModel;

    ConversationalRetrievalChain chain;

    private void init(boolean force) {
        if (chain != null && !force) {
            return;
        }

        chain = ConversationalRetrievalChain.builder()
                .chatLanguageModel(getModel())
                .contentRetriever(getRetriever())
                .chatMemory(MessageWindowChatMemory.withMaxMessages(10))
                .promptTemplate(PromptTemplate
                        .from("""
                                You are a Factual Research AI Assistant dedicated to providing accurate information.
                                Your primary task is to assist me by providing me reliable and clear responses to my questions, based on the information available in the knowledge base as your only source.
                                Refrain from mentioning ‘unstructured knowledge base’ or file names during the conversation.
                                You are reluctant of making any claims unless they are stated or supported by the knowledge base.
                                In instances where a definitive answer is unavailable, acknowledge your inability to answer and inform to me that you cannot respond.
                                Your response must be in brazilian portuguese.
                                DO NOT answer anything that is not related to the knowledge base.
                                Question: {{question}}
                                =========
                                Knowledge base: {{information}}
                                =========
                                Answer:"""))
                .build();
    }

    private ContentRetriever getRetriever() {
        InMemoryEmbeddingStore<TextSegment> embeddingStore;
        try {
            File file = getEmbeddingFile();
            embeddingStore = InMemoryEmbeddingStore.fromFile(file.getAbsolutePath());
        } catch (Exception e) {
            throw new BusinessException("Embeddings file not found. Upload a file to /openai/upload and try again.");
        }

        return EmbeddingStoreContentRetriever.builder()
                .embeddingStore(embeddingStore)
                .embeddingModel(getEmbeddingModel())
                .maxResults(5)
                .build();
    }

    private ChatLanguageModel getModel() {
        return OpenAiChatModel.builder()
                .apiKey(openaiToken)
                .modelName(openaiModel)
                .temperature(0.7)
                .logRequests(true)
                .logResponses(true)
                .build();
    }

    public String query(String query) {
        init(false);
        return chain.execute(query);
    }

    public void ingest(MultipartFile multipartFile) {
        String contentType = multipartFile.getContentType();
        String fileName = multipartFile.getOriginalFilename();
        InputStream inputStream = getInputStream(multipartFile);
        String filePath = saveTempFile(inputStream, fileName);
        File tempDir = getTempDir();
        String embeddingsFilePath = new File(tempDir, "embeddings.json").getAbsolutePath();

        InMemoryEmbeddingStore<TextSegment> embeddingStore = new InMemoryEmbeddingStore<>();
        EmbeddingStoreIngestor ingestor = EmbeddingStoreIngestor.builder()
                .documentSplitter(DocumentSplitters.recursive(300, 0))
                .embeddingModel(getEmbeddingModel())
                .embeddingStore(embeddingStore)
                .build();

        DocumentParser documentParser = getDocumentParserByContentType(contentType);
        Document document = FileSystemDocumentLoader.loadDocument(filePath, documentParser);
        ingestor.ingest(document);

        embeddingStore.serializeToFile(embeddingsFilePath);

        init(true);
    }

    private OpenAiEmbeddingModel getEmbeddingModel() {
        return OpenAiEmbeddingModel.builder()
                .modelName(openaiEmbeddingsModel)
                .apiKey(openaiToken)
                .build();
    }

    private InputStream getInputStream(MultipartFile multipartFile) {
        try {
            return multipartFile.getInputStream();
        } catch (IOException e) {
            throw new BusinessException("Error reading file.");
        }
    }

    private DocumentParser getDocumentParserByContentType(String contentType) {
        DocumentParser parser = DocumentTypeEnum.asParser(contentType);
        if (parser == null) {
            throw new BusinessException("Unsupported file type. Supported types: " + DocumentTypeEnum.getExtensions());
        }
        return parser;
    }

    private String saveTempFile(InputStream inputStream, String name) {
        File tempDir = getTempDir();
        File file = new File(tempDir, name);
        try {
            Files.copy(inputStream, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new BusinessException("Error saving file.");
        }

        IOUtils.closeQuietly(inputStream);
        return file.getAbsolutePath();
    }

    private File getEmbeddingFile() {
        File tempDir = getTempDir();

        return new File(tempDir, "embeddings.json");
    }

    private @NotNull File getTempDir() {
        File tempDir = new File("temp");
        if (!tempDir.exists()) {
            tempDir.mkdir();
        }
        return tempDir;
    }
}
