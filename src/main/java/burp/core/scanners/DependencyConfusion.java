package burp.core.scanners;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.utils.NPMPackage;
import burp.utils.Utilities;
import burp.utils.CustomScanIssue;
import burp.core.TaskRepository;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;

import static burp.utils.Constants.*;

public class DependencyConfusion implements Runnable {
    private final MontoyaApi api;
    private final TaskRepository taskRepository;
    private final HttpRequestResponse requestResponse;
    private final UUID taskUUID;
    private final boolean findDependenciesWithRegex;

    public DependencyConfusion(MontoyaApi api, HttpRequestResponse requestResponse, UUID taskUUID, boolean findDependenciesWithRegex) {
        this.api = api;
        this.taskRepository = TaskRepository.getInstance();
        this.requestResponse = requestResponse;
        this.taskUUID = taskUUID;
        this.findDependenciesWithRegex = findDependenciesWithRegex;
    }

    @Override
    public void run() {
        taskRepository.startTask(taskUUID);

        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseBody = requestResponse.response().bodyToString();

        // Removing unwanted spaces, new lines and so on
        Matcher dependenciesListMatcher = EXTRACT_DEPENDENCIES_REGEX.matcher(responseBody
                .replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", ""));

        HashSet<NPMPackage> uniquePackageNames = new HashSet<>();

        if (findDependenciesWithRegex) {
            while (dependenciesListMatcher.find()) {
                String dependencyList = dependenciesListMatcher.group(2);
                String[] dependencyListArray = dependencyList.split(",");
                for (String dependency : dependencyListArray) {
                    NPMPackage npmPackage = new NPMPackage(dependency);
                    if (npmPackage.isNameValid()) {
                        uniquePackageNames.add(npmPackage);
                        uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                        appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
                    }
                }
            }
        }

        Matcher fromNodeModulesPathMatcher = extractFromNodeModules.matcher(responseBody);
        while (fromNodeModulesPathMatcher.find()) {
            NPMPackage npmPackage = new NPMPackage(fromNodeModulesPathMatcher.group(1), true);
            if (npmPackage.isNameValid()) {
                uniquePackageNames.add(npmPackage);
                uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
            }
        }

        if (uniqueMatchesSB.length() > 0) {
            List<int[]> allDependenciesMatches = Utilities.getMatches(requestResponse.response().toByteArray(), uniqueMatches);
            reportDependencies(uniqueMatchesSB.toString(), allDependenciesMatches);

            for (NPMPackage npmPackage : uniquePackageNames) {
                List<int[]> depMatches = Utilities.getMatches(requestResponse.response().toByteArray(), npmPackage.toString().getBytes());
                try {
                    if (isConnectionOK()) {
                        verifyDependencyConfusion(npmPackage, depMatches);
                        taskRepository.completeTask(taskUUID);
                    } else {
                        taskRepository.failTask(taskUUID);
                    }
                } catch (IOException e) {
                    api.logging().logToError("Error verifying dependency confusion: " + e.getMessage());
                }
            }
        } else {
            taskRepository.completeTask(taskUUID);
        }
    }

    private boolean isConnectionOK() {
        try {
            URL npmUrl = new URL("https://www.npmjs.com/robots.txt");
            URL registryUrl = new URL("https://registry.npmjs.org/");

            HttpRequest npmRequest = HttpRequest.httpRequestFromUrl(npmUrl.toString());
            HttpRequest registryRequest = HttpRequest.httpRequestFromUrl(registryUrl.toString());

            HttpRequestResponse npmResponse = api.http().sendRequest(npmRequest);
            HttpRequestResponse registryResponse = api.http().sendRequest(registryRequest);

            return npmResponse.response() != null && registryResponse.response() != null;
        } catch (MalformedURLException e) {
            api.logging().logToError("Error checking connection: " + e.getMessage());
            return false;
        }
    }

    private void reportDependencies(String dependenciesList, List<int[]> depMatches) {
        api.siteMap().add(CustomScanIssue.from(
                requestResponse,
                "[JS Miner] Dependencies",
                "The following dependencies were found in a static file.",
                dependenciesList,
                "Information",
                "Certain"
        ));
    }

    private void verifyDependencyConfusion(NPMPackage npmPackage, List<int[]> depMatches) throws IOException {
        String findingTitle = null;
        String findingDetail = null;
        String severity = null;

        if (!npmPackage.isVersionValidNPM()) {
            findingTitle = "[JS Miner] Dependency (Non-NPM registry package)";
            findingDetail = "The following non-NPM dependency was found in a static file. The version might contain a public repository URL, a private repository URL or a file path. Manual review is advised.";
            severity = SEVERITY_INFORMATION;
        } else if (npmPackage.getName().startsWith("@")) {
            String organizationName = npmPackage.getOrgNameFromScopedDependency();
            HttpRequest request = HttpRequest.httpRequestFromUrl("https://www.npmjs.com/org/" + organizationName);
            HttpRequestResponse response = api.http().sendRequest(request);

            if (response.response() != null && response.response().statusCode() == 404) {
                findingTitle = "[JS Miner] Dependency (organization not found)";
                findingDetail = "The following potentially exploitable dependency was found in a static file. The organization does not seem to be available, which indicates that it can be registered: https://www.npmjs.com/org/" + organizationName;
                severity = SEVERITY_HIGH;
            }
        } else {
            HttpRequest request = HttpRequest.httpRequestFromUrl("https://registry.npmjs.org/" + npmPackage.getName());
            HttpRequestResponse response = api.http().sendRequest(request);

            if (response.response() != null && response.response().statusCode() == 404) {
                findingTitle = "[JS Miner] Dependency Confusion";
                findingDetail = "The following potentially exploitable dependency was found in a static file. There was no entry for this package on the 'npm js' registry: https://registry.npmjs.org/" + npmPackage.getName();
                severity = SEVERITY_HIGH;
            }
        }

        if (findingTitle != null) {
            api.siteMap().add(CustomScanIssue.from(
                    requestResponse,
                    findingTitle,
                    findingDetail,
                    npmPackage.toString(),
                    severity,
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
