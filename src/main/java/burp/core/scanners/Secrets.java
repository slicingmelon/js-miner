package burp.core.scanners;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.BurpExtender;
import burp.utils.Utilities;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.*;

public class Secrets implements Runnable {
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;

    public Secrets(HttpRequestResponse requestResponse, UUID taskUUID) {
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);
        HttpResponse response = requestResponse.response();
        String responseBodyString = response.bodyToString();

        // Combined secrets
        List<byte[]> uniqueMatchesLow = new ArrayList<>();
        StringBuilder uniqueMatchesSBLow = new StringBuilder();

        List<byte[]> uniqueMatchesHigh = new ArrayList<>();
        StringBuilder uniqueMatchesSBHigh = new StringBuilder();

        // Process secrets regex matches
        Matcher matcherSecrets = SECRETS_REGEX.matcher(responseBodyString);
        while (matcherSecrets.find() && BurpExtender.isLoaded()) {
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
            if (isValidBase64(base64String) && Utilities.isHighEntropy(Utilities.b64Decode(base64String))) {
                uniqueMatchesHigh.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBHigh);
            } else {
                uniqueMatchesLow.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBLow);
            }
        }

        reportFinding(requestResponse, uniqueMatchesSBLow, uniqueMatchesLow, uniqueMatchesSBHigh, uniqueMatchesHigh);
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    private static void reportFinding(HttpRequestResponse requestResponse, StringBuilder uniqueMatchesSBLow, List<byte[]> uniqueMatchesLow,
                                      StringBuilder uniqueMatchesSBHigh, List<byte[]> uniqueMatchesHigh) {
        if (uniqueMatchesSBHigh.length() > 0) {
            List<int[]> secretsMatchesHigh = getMatches(requestResponse.response().body(), uniqueMatchesHigh);
            AuditIssue.AuditIssueSeverity severity = AuditIssue.AuditIssueSeverity.MEDIUM;
            AuditIssue.AuditIssueConfidence confidence = AuditIssue.AuditIssueConfidence.FIRM;
            
            AuditIssue issue = AuditIssue.auditIssue(
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with High entropy) were found in a static file.",
                    "High entropy strings that match common secret patterns were identified in the response. " +
                    "These could represent hardcoded credentials or API keys.",
                    requestResponse.request().url(),
                    severity,
                    confidence,
                    "Review the identified strings and ensure no sensitive data is exposed.",
                    uniqueMatchesSBHigh.toString(),
                    "Remove any hardcoded secrets from the code and store them securely.",
                    List.of(requestResponse)
            );
            
            BurpExtender.api.siteMap().add(issue);
        }

        if (uniqueMatchesSBLow.length() > 0) {
            List<int[]> secretsMatchesLow = getMatches(requestResponse.response().body(), uniqueMatchesLow);
            AuditIssue.AuditIssueSeverity severity = AuditIssue.AuditIssueSeverity.MEDIUM;
            AuditIssue.AuditIssueConfidence confidence = AuditIssue.AuditIssueConfidence.TENTATIVE;
            
            AuditIssue issue = AuditIssue.auditIssue(
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with Low entropy) were found in a static file.",
                    "Potential secrets matching common patterns were identified in the response. " +
                    "These could represent hardcoded credentials or configuration values.",
                    requestResponse.request().url(),
                    severity,
                    confidence,
                    "Review the identified strings to determine if they contain sensitive data.",
                    uniqueMatchesSBLow.toString(),
                    "If confirmed as secrets, remove them from the code and store them securely.",
                    List.of(requestResponse)
            );
            
            BurpExtender.api.siteMap().add(issue);
        }
    }

    private static boolean isNotFalsePositive(String secret) {
        String[] falsePositives = {"basic", "bearer", "token"};
        // cleanup the secret string
        secret = secret.replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("*", "");
        // at least the secret should equal 4 characters
        if (secret.length() <= 4) {
            return false;
        }

        // Check if secret string is not in the pre-defined blacklist
        for (String fp: falsePositives) {
            if (secret.equalsIgnoreCase(fp)) {
                return false;
            }
        }

        return true;
    }
}
