package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.utils.Utilities;
import burp.core.TaskRepository;
import burp.utils.CustomScanIssue;
import burp.api.montoya.core.Marker;
import java.util.ArrayList;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;
import java.util.LinkedList;

import static burp.utils.Constants.*;

public class Secrets implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;

    public Secrets(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        try {
            taskRepository.startTask(taskUUID);
            String responseBodyString = requestResponse.response().bodyToString();

            List<byte[]> uniqueMatchesLow = new ArrayList<>();
            StringBuilder uniqueMatchesSBLow = new StringBuilder();
            List<byte[]> uniqueMatchesHigh = new ArrayList<>();
            StringBuilder uniqueMatchesSBHigh = new StringBuilder();

            processSecretMatches(responseBodyString, uniqueMatchesLow, uniqueMatchesSBLow, 
                               uniqueMatchesHigh, uniqueMatchesSBHigh);
            processBasicAuthSecrets(responseBodyString, uniqueMatchesLow, uniqueMatchesSBLow, 
                                  uniqueMatchesHigh, uniqueMatchesSBHigh);

            reportFindings(uniqueMatchesSBLow, uniqueMatchesLow, uniqueMatchesSBHigh, uniqueMatchesHigh);
            taskRepository.completeTask(taskUUID);
        } catch (Exception e) {
            api.logging().logToError("Error in Secrets scanner: " + e.getMessage());
            taskRepository.failTask(taskUUID);
        }
    }

    private void processSecretMatches(String responseBodyString, 
                                    List<byte[]> uniqueMatchesLow, StringBuilder uniqueMatchesSBLow,
                                    List<byte[]> uniqueMatchesHigh, StringBuilder uniqueMatchesSBHigh) {
        api.logging().logToOutput("[Debug] Starting secrets scan for: " + requestResponse.request().url());
        api.logging().logToOutput("[Debug] Response body length: " + responseBodyString.length());
        
        Matcher matcherSecrets = SECRETS_REGEX.matcher(responseBodyString);
        int matchCount = 0;
        
        while (matcherSecrets.find()) {
            matchCount++;
            String match = matcherSecrets.group();
            String potentialSecret = matcherSecrets.group(20);
            
            api.logging().logToOutput("[Debug] Found potential match #" + matchCount + ": " + match);
            api.logging().logToOutput("[Debug] Extracted secret value: " + potentialSecret);
            
            if (Utilities.isHighEntropy(potentialSecret)) {
                api.logging().logToOutput("[Debug] Classified as high entropy secret");
                uniqueMatchesHigh.add(match.getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(match, uniqueMatchesSBHigh);
            } else if (isNotFalsePositive(potentialSecret)) {
                api.logging().logToOutput("[Debug] Classified as low entropy secret");
                uniqueMatchesLow.add(match.getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(match, uniqueMatchesSBLow);
            } else {
                api.logging().logToOutput("[Debug] Discarded as false positive");
            }
        }
        
        api.logging().logToOutput("[Debug] Completed secrets scan. Found " + matchCount + " potential matches");
        api.logging().logToOutput("[Debug] High entropy matches: " + uniqueMatchesHigh.size());
        api.logging().logToOutput("[Debug] Low entropy matches: " + uniqueMatchesLow.size());
    }

    private void processBasicAuthSecrets(String responseBodyString,
                                       List<byte[]> uniqueMatchesLow, StringBuilder uniqueMatchesSBLow,
                                       List<byte[]> uniqueMatchesHigh, StringBuilder uniqueMatchesSBHigh) {
        api.logging().logToOutput("[Debug] Starting basic auth scan");
        Matcher httpBasicAuthMatcher = HTTP_BASIC_AUTH_SECRETS.matcher(responseBodyString);
        int matchCount = 0;
        
        while (httpBasicAuthMatcher.find()) {
            matchCount++;
            try {
                String base64String = httpBasicAuthMatcher.group(2);
                String decoded = api.utilities().base64Utils().decode(base64String).toString();
                String fullMatch = httpBasicAuthMatcher.group();
                
                api.logging().logToOutput("[Debug] Found basic auth match #" + matchCount);
                api.logging().logToOutput("[Debug] Base64 value: " + base64String);
                api.logging().logToOutput("[Debug] Decoded value: " + decoded);

                if (Utilities.isHighEntropy(decoded)) {
                    api.logging().logToOutput("[Debug] Classified as high entropy basic auth");
                    uniqueMatchesHigh.add(fullMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(fullMatch, uniqueMatchesSBHigh);
                } else {
                    api.logging().logToOutput("[Debug] Classified as low entropy basic auth");
                    uniqueMatchesLow.add(fullMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(fullMatch, uniqueMatchesSBLow);
                }
            } catch (IllegalArgumentException e) {
                api.logging().logToError("[Debug] Invalid base64 in Basic Auth: " + e.getMessage());
            }
        }
        
        api.logging().logToOutput("[Debug] Completed basic auth scan. Found " + matchCount + " matches");
    }

    private void reportFindings(StringBuilder uniqueMatchesSBLow, List<byte[]> uniqueMatchesLow,
                              StringBuilder uniqueMatchesSBHigh, List<byte[]> uniqueMatchesHigh) {
        if (uniqueMatchesSBHigh.length() > 0) {
            List<int[]> responseHighlights = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatchesHigh);
            List<Marker> markers = new ArrayList<>();
            
            // Convert int[] positions to Markers
            for (int[] highlight : responseHighlights) {
                markers.add(Marker.marker(highlight[0], highlight[1]));
            }
            
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse.withResponseMarkers(markers),
                    "[JS Miner-NG] High Entropy Secrets",
                    "High entropy secrets found in static file",
                    uniqueMatchesSBHigh.toString(),
                    "High",
                    "Firm"
            ));
        }

        if (uniqueMatchesSBLow.length() > 0) {
            List<int[]> responseHighlights = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatchesLow);
            List<Marker> markers = new ArrayList<>();
            
            // Convert int[] positions to Markers
            for (int[] highlight : responseHighlights) {
                markers.add(Marker.marker(highlight[0], highlight[1]));
            }
            
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse.withResponseMarkers(markers),
                    "[JS Miner-NG] Potential Secrets",
                    "Potential secrets found in static file",
                    uniqueMatchesSBLow.toString(),
                    "Medium",
                    "Firm"
            ));
        }
    }

    private static boolean isNotFalsePositive(String secret) {
        String[] falsePositives = {"basic", "bearer", "token"};
        final String cleanSecret = secret.replaceAll("[\\s\\t\\r\\n*]", "");
        
        if (cleanSecret.length() <= 4) return false;
        
        return !List.of(falsePositives).stream()
                .anyMatch(fp -> cleanSecret.equalsIgnoreCase(fp));
    }

    private void appendFoundMatches(String match, StringBuilder sb) {
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(match);
    }
}
