package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.Utilities;
import burp.core.TaskRepository;
import burp.utils.CustomScanIssue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;

import static burp.utils.Constants.*;

public class CloudURLs implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;

    public CloudURLs(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        taskRepository.startTask(taskUUID);

        // For reporting unique matches with markers
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseBody = requestResponse.response().bodyToString();

        Matcher cloudURLsMatcher = CLOUD_URLS_REGEX.matcher(responseBody);

        while (cloudURLsMatcher.find()) {
            uniqueMatches.add(cloudURLsMatcher.group().getBytes(StandardCharsets.UTF_8));
            appendFoundMatches(cloudURLsMatcher.group(), uniqueMatchesSB);
        }

        reportFinding(uniqueMatchesSB, uniqueMatches);
        taskRepository.completeTask(taskUUID);
    }

    private void reportFinding(StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<int[]> allMatchesMarkers = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatches);

            // report the issue
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    "[JS Miner-NG] Cloud Resources",
                    "The following cloud URLs were found in a static file.",
                    allMatchesSB.toString(),
                    "Information",
                    "Certain"
            ));
        }
    }

    private void appendFoundMatches(String match, StringBuilder sb) {
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(match);
    }
}
