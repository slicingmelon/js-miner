package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.CustomScanIssue;
import burp.core.TaskRepository;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.utils.Constants.*;

public class SubDomains implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;

    public SubDomains(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        taskRepository.startTask(taskUUID);

        String responseBody = requestResponse.response().bodyToString();
        String requestDomain = requestResponse.request().url().toString();
        try {
            requestDomain = new java.net.URL(requestDomain).getHost();
        } catch (Exception e) {
            api.logging().logToError("Error extracting domain: " + e.getMessage());
            taskRepository.completeTask(taskUUID);
            return;
        }
        
        String rootDomain = getRootDomain(requestDomain);

        if (rootDomain != null) {
            List<byte[]> uniqueMatches = new ArrayList<>();
            StringBuilder uniqueMatchesSB = new StringBuilder();

            Pattern subDomainsRegex = Pattern.compile("([a-z0-9-]+[.])+" + rootDomain, Pattern.CASE_INSENSITIVE);
            Matcher matcherSubDomains = subDomainsRegex.matcher(responseBody);
            
            while (matcherSubDomains.find()) {
                String match = matcherSubDomains.group();
                if (isValidSubdomain(match, rootDomain, requestDomain)) {
                    String decodedMatch = api.utilities().urlUtils().decode(match);
                    uniqueMatches.add(decodedMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatch(decodedMatch, uniqueMatchesSB);
                }
            }
            
            reportFinding(uniqueMatchesSB, uniqueMatches);
        }
        
        taskRepository.completeTask(taskUUID);
    }

    private String getRootDomain(String domain) {
        Pattern rootDomainRegex = Pattern.compile("[a-z0-9]+\\.[a-z0-9]+$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = rootDomainRegex.matcher(domain);
        return matcher.find() ? matcher.group() : null;
    }

    private boolean isValidSubdomain(String subdomain, String rootDomain, String requestDomain) {
        return subdomain.endsWith(rootDomain) && 
               !subdomain.equals(rootDomain) && 
               !subdomain.equals(requestDomain);
    }

    private void appendFoundMatch(String match, StringBuilder sb) {
        if (sb.length() > 0) {
            sb.append("\n");
        }
        sb.append(match);
    }

    private void reportFinding(StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    "[JS Miner-NG] Subdomains",
                    "The following subdomains were found in a static file.",
                    allMatchesSB.toString(),
                    "Information",
                    "Certain"
            ));
        }
    }
}
