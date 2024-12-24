package burp.utils;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class CustomScanIssue {
    public static AuditIssue from(
            HttpRequestResponse requestResponse,
            String name,
            String detail,
            String background,
            String severity,
            String confidence) {
            
        return auditIssue(
                name,
                detail,
                background,
                requestResponse.request().url(),
                convertSeverity(severity),
                convertConfidence(confidence),
                null,
                null,
                convertSeverity(severity),
                requestResponse
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