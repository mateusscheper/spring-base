package scheper.mateus.api.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import scheper.mateus.api.service.OpenAiService;

@RestController
@RequestMapping("/openai")
public class OpenAiController {

    private final OpenAiService openAiService;

    public OpenAiController(OpenAiService openAiService) {
        this.openAiService = openAiService;
    }

    @PostMapping(value = "/query", consumes = "text/plain", produces = "text/plain")
    @ResponseStatus(HttpStatus.OK)
    public String query(@RequestBody @Valid @NotBlank(message = "The query text cannot be empty.") String query) {
        return openAiService.query(query);
    }

    @PostMapping(value = "/ingest", consumes = "multipart/form-data")
    @ResponseStatus(HttpStatus.CREATED)
    public void ingest(@RequestParam(value = "file", required = false) MultipartFile file) {
        openAiService.ingest(file);
    }

}
