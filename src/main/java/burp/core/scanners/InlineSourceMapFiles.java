package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.SourceMapper;
import burp.utils.Utilities;
import burp.core.TaskRepository;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import com.google.re2j.Matcher;
import java.net.MalformedURLException;
import java.net.URL;

import static burp.utils.Constants.b64SourceMapRegex;

public class InlineSourceMapFiles implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private Path outputDirectory;
    private final UUID taskUUID;

    public InlineSourceMapFiles(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID, long timeStamp) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        try {
            String url = requestResponse.request().url();
            this.outputDirectory = Paths.get(System.getProperty("user.home"))
                    .resolve(".BurpSuite")
                    .resolve("JS-Miner")
                    .resolve(new URL(url).getHost() + "-" + timeStamp);
        } catch (MalformedURLException e) {
            api.logging().logToError("MalformedURLException: " + e.getMessage());
        }
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        taskRepository.startTask(taskUUID);

        String responseBodyString = requestResponse.response().bodyToString();
        Matcher b64SourceMapperMatcher = b64SourceMapRegex.matcher(responseBodyString);

        while (b64SourceMapperMatcher.find()) {
            new SourceMapper(
                    requestResponse,
                    Utilities.b64Decode(b64SourceMapperMatcher.group(3)),
                    outputDirectory
            );
        }
        taskRepository.completeTask(taskUUID);
    }
}
