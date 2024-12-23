package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.Utilities;
import burp.utils.CustomScanIssue;
import burp.core.TaskRepository;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.utils.Constants.*;

public class Endpoints implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;

    public Endpoints(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        taskRepository.startTask(taskUUID);
        // For readability, reporting each method separately
        endpointsFinder(ENDPOINTS_GET_REGEX, "get");
        endpointsFinder(ENDPOINTS_POST_REGEX, "post");
        endpointsFinder(ENDPOINTS_PUT_REGEX, "put");
        endpointsFinder(ENDPOINTS_DELETE_REGEX, "delete");
        endpointsFinder(ENDPOINTS_PATCH_REGEX, "patch");
        taskRepository.completeTask(taskUUID);
    }

    private void endpointsFinder(Pattern endpointsPattern, String method) {
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseBodyString = requestResponse.response().bodyToString();
        Matcher endpointsMatcher = endpointsPattern.matcher(responseBodyString);

        while (endpointsMatcher.find() && endpointsMatcher.group(1).contains("/")
                && !endpointsMatcher.group(1).contains("<") && !endpointsMatcher.group(1).contains(">")) {
            uniqueMatches.add(endpointsMatcher.group(1).getBytes(StandardCharsets.UTF_8));
            appendFoundMatches(endpointsMatcher.group(1), uniqueMatchesSB);
        }

        reportFinding(uniqueMatchesSB, uniqueMatches, method.toUpperCase(Locale.ENGLISH));
    }

    private void reportFinding(StringBuilder allMatchesSB, List<byte[]> uniqueMatches, String method) {
        if (allMatchesSB.length() > 0) {
            List<int[]> allMatchesMarkers = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatches);

            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    "[JS Miner-NG] API Endpoints (" + method + ")",
                    "The following API endpoints were found in a static file.",
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
