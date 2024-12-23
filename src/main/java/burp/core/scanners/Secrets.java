package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.utils.Utilities;
import burp.core.TaskRepository;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;

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
        taskRepository.startTask(taskUUID);
        String responseBodyString = requestResponse.response().bodyToString();

        // Combined secrets
        List<byte[]> uniqueMatchesLow = new ArrayList<>();
        StringBuilder uniqueMatchesSBLow = new StringBuilder();

        List<byte[]> uniqueMatchesHigh = new ArrayList<>();
        StringBuilder uniqueMatchesSBHigh = new StringBuilder();

        // Process secrets regex matches
        Matcher matcherSecrets = SECRETS_REGEX.matcher(responseBodyString);
        while (matcherSecrets.find()) {
            if (Utilities.isHighEntropy(matcherSecrets.group(20))) {
                uniqueMatchesHigh.add(matcherSecrets.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(matcherSecrets.group(), uniqueMatchesSBHigh);
            } else {
                if (isNotFalsePositive(matcherSecrets.group(20))) {
                    uniqueMatchesLow.add(matcherSecrets.group().getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(matcherSecrets.group(), uniqueMatchesSBLow);
                }
            }
        }

        // Process HTTP basic auth secrets
        Matcher httpBasicAuthMatcher = HTTP_BASIC_AUTH_SECRETS.matcher(responseBodyString);
        if (httpBasicAuthMatcher.find()) {
            String base64String = httpBasicAuthMatcher.group(2);
            try {
                String decoded = api.utilities().base64Utils().decode(base64String).toString();
                if (Utilities.isHighEntropy(decoded)) {
                    uniqueMatchesHigh.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBHigh);
                } else {
                    uniqueMatchesLow.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBLow);
                }
            } catch (IllegalArgumentException e) {
                // Not valid base64, skip
                api.logging().logToError("Invalid base64 string found: " + e.getMessage());
            }
        }

        reportFinding(uniqueMatchesSBLow, uniqueMatchesLow, uniqueMatchesSBHigh, uniqueMatchesHigh);
        taskRepository.completeTask(taskUUID);
    }

    private void reportFinding(StringBuilder uniqueMatchesSBLow, List<byte[]> uniqueMatchesLow,
                             StringBuilder uniqueMatchesSBHigh, List<byte[]> uniqueMatchesHigh) {
        if (uniqueMatchesSBHigh.length() > 0) {
            List<int[]> secretsMatchesHigh = Utilities.getMatches(requestResponse.response().body(), uniqueMatchesHigh);
            
            AuditIssue issue = AuditIssue.auditIssue(
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with High entropy) were found in a static file.",
                    "High entropy strings that match common secret patterns were identified in the response. " +
                    "These could represent hardcoded credentials or API keys.",
                    requestResponse.request().url(),
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    "Review the identified strings and ensure no sensitive data is exposed.",
                    uniqueMatchesSBHigh.toString(),
                    "Remove any hardcoded secrets from the code and store them securely.",
                    List.of(requestResponse)
            );
            
            api.siteMap().add(issue);
        }

        if (uniqueMatchesSBLow.length() > 0) {
            List<int[]> secretsMatchesLow = getMatches(requestResponse.response().body(), uniqueMatchesLow);
            
            AuditIssue issue = AuditIssue.auditIssue(
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with Low entropy) were found in a static file.",
                    "Potential secrets matching common patterns were identified in the response. " +
                    "These could represent hardcoded credentials or configuration values.",
                    requestResponse.request().url(),
                    AuditIssue.AuditIssueSeverity.MEDIUM,
                    AuditIssue.AuditIssueConfidence.TENTATIVE,
                    "Review the identified strings to determine if they contain sensitive data.",
                    uniqueMatchesSBLow.toString(),
                    "If confirmed as secrets, remove them from the code and store them securely.",
                    List.of(requestResponse)
            );
            
            api.siteMap().add(issue);
        }
    }

    private static boolean isNotFalsePositive(String secret) {
        String[] falsePositives = {"basic", "bearer", "token"};
        secret = secret.replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("*", "");
                
        if (secret.length() <= 4) {
            return false;
        }

        for (String fp: falsePositives) {
            if (secret.equalsIgnoreCase(fp)) {
                return false;
            }
        }

        return true;
    }

    private void appendFoundMatches(String match, StringBuilder sb) {
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(match);
    }
}
