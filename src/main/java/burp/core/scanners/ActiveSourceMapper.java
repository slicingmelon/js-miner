package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.utils.SourceMapper;
import burp.core.TaskRepository;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

public class ActiveSourceMapper implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private URL jsMapURL;
    private Path outputDirectory;
    private final UUID taskUUID;

    public ActiveSourceMapper(MontoyaApi api, HttpRequestResponse requestResponse, long currentTimestamp, UUID taskUUID) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.taskUUID = taskUUID;
        
        try {
            String jsURL = requestResponse.request().url();
            this.jsMapURL = new URL(jsURL + ".map");
            this.outputDirectory = Paths.get(System.getProperty("user.home"))
                    .resolve(".BurpSuite")
                    .resolve("JS-Miner")
                    .resolve(jsMapURL.getHost() + "-" + currentTimestamp);
        } catch (MalformedURLException e) {
            api.logging().logToError("MalformedURLException: " + e.getMessage());
        }
    }

    @Override
    public void run() {
        try {
            taskRepository.startTask(taskUUID);
            
            HttpRequest mapRequest = HttpRequest.httpRequestFromUrl(jsMapURL.toString());
            HttpRequestResponse mapResponse = api.http().sendRequest(mapRequest);
            
            if (mapResponse.response().statusCode() == 200) {
                api.siteMap().add(mapResponse);
                String responseBody = mapResponse.response().bodyToString();
                
                if (responseBody.contains("sources") && responseBody.contains("sourcesContent")) {
                    new SourceMapper(mapResponse, responseBody, outputDirectory);
                }
            }
            taskRepository.completeTask(taskUUID);
        } catch (Exception e) {
            taskRepository.failTask(taskUUID);
            api.logging().logToError("Error in ActiveSourceMapper: " + e.getMessage());
        }
    }
}