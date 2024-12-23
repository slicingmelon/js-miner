package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.utils.Utilities;
import burp.core.TaskRepository;
import burp.utils.CustomScanIssue;

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
        Matcher matcherSecrets = SECRETS_REGEX.matcher(responseBodyString);
        while (matcherSecrets.find()) {
            String match = matcherSecrets.group();
            String potentialSecret = matcherSecrets.group(20);
            
            if (Utilities.isHighEntropy(potentialSecret)) {
                uniqueMatchesHigh.add(match.getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(match, uniqueMatchesSBHigh);
            } else if (isNotFalsePositive(potentialSecret)) {
                uniqueMatchesLow.add(match.getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(match, uniqueMatchesSBLow);
            }
        }
    }

    private void processBasicAuthSecrets(String responseBodyString,
                                       List<byte[]> uniqueMatchesLow, StringBuilder uniqueMatchesSBLow,
                                       List<byte[]> uniqueMatchesHigh, StringBuilder uniqueMatchesSBHigh) {
        Matcher httpBasicAuthMatcher = HTTP_BASIC_AUTH_SECRETS.matcher(responseBodyString);
        while (httpBasicAuthMatcher.find()) {
            try {
                String base64String = httpBasicAuthMatcher.group(2);
                String decoded = api.utilities().base64Utils().decode(base64String).toString();
                String fullMatch = httpBasicAuthMatcher.group();

                if (Utilities.isHighEntropy(decoded)) {
                    uniqueMatchesHigh.add(fullMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(fullMatch, uniqueMatchesSBHigh);
                } else {
                    uniqueMatchesLow.add(fullMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(fullMatch, uniqueMatchesSBLow);
                }
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid base64 in Basic Auth: " + e.getMessage());
            }
        }
    }

    private void reportFindings(StringBuilder uniqueMatchesSBLow, List<byte[]> uniqueMatchesLow,
                              StringBuilder uniqueMatchesSBHigh, List<byte[]> uniqueMatchesHigh) {
        if (uniqueMatchesSBHigh.length() > 0) {
            List<int[]> responseHighlights = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatchesHigh);
            
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    "[JS Miner] High Entropy Secrets",
                    "High entropy secrets found in static file",
                    uniqueMatchesSBHigh.toString(),
                    "High",
                    "Firm"
            ));
        }

        if (uniqueMatchesSBLow.length() > 0) {
            List<int[]> responseHighlights = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatchesLow);
            
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    "[JS Miner] Potential Secrets",
                    "Potential secrets found in static file",
                    uniqueMatchesSBLow.toString(),
                    "Medium",
                    "Tentative"
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
