package burp.utils;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.net.URL;
import java.util.List;

public class CustomScanIssue {
    public static AuditIssue from(
            HttpRequestResponse requestResponse,
            String name,
            String detail,
            String background,
            String severity,
            String confidence) {
            
        AuditIssueSeverity issueSeverity = convertSeverity(severity);
        AuditIssueConfidence issueConfidence = convertConfidence(confidence);
        
        return AuditIssue.auditIssue(
                name,
                detail,
                background,
                requestResponse.request().url(),
                issueSeverity,
                issueConfidence,
                null, // remediation background
                null, // remediation detail
                List.of(requestResponse)
        );
    }
    
    private static AuditIssueSeverity convertSeverity(String severity) {
        return switch (severity.toLowerCase()) {
            case "high" -> AuditIssueSeverity.HIGH;
            case "medium" -> AuditIssueSeverity.MEDIUM;
            case "low" -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }
    
    private static AuditIssueConfidence convertConfidence(String confidence) {
        return switch (confidence.toLowerCase()) {
            case "certain" -> AuditIssueConfidence.CERTAIN;
            case "firm" -> AuditIssueConfidence.FIRM;
            case "tentative" -> AuditIssueConfidence.TENTATIVE;
            default -> AuditIssueConfidence.TENTATIVE;
        };
    }
}