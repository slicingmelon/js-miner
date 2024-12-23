package burp.utils;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.BurpExtender.*;
import static burp.utils.Constants.*;

public final class Utilities {
    private static final Pattern FILE_NAME_REGEX = Pattern.compile("(.*)\\.(.*)");

    private Utilities() {
    }

    /*
     *  This is mainly used by the "querySiteMap" function
     *  Checks if the HTTP Response is not null and that the Requested file is either JS or JSON
     */
    public static boolean isValidScanTarget(HttpRequestResponse requestResponse, String[] queryFileExtensions) {
        if (requestResponse.response() != null && BurpExtender.isLoaded()) {
            for (String fileExtension: queryFileExtensions) {
                if (requestResponse.request().url().getPath().endsWith("." + fileExtension)) {
                    return true;
                }
            }
        }
        return false;
    }

    /*
     *  Query Site Map for specific extensions (including children of the passed Request URL)
     */
    public static Set<HttpRequestResponse> querySiteMap(HttpRequestResponse[] httpReqResArray, String[] queryFileExtensions) {
        HashSet<HttpRequestResponse> uniqueRequests = new HashSet<>();
        for (HttpRequestResponse baseRequestResponse : httpReqResArray) {
            URL url = baseRequestResponse.request().url();
            // Get all child URLs from Site Map
            List<HttpRequestResponse> siteMapEntries = BurpExtender.api.siteMap().filterBy(request -> 
                request.url().toString().startsWith(getURL(url)));
            
            for (HttpRequestResponse requestResponse : siteMapEntries) {
                if (isValidScanTarget(requestResponse, queryFileExtensions)) {
                    uniqueRequests.add(requestResponse);
                }
            }
        }
        return uniqueRequests;
    }

    // Append found matches to be listed in Burp's issues
    public static void appendFoundMatches(String finding, StringBuilder uniqueMatchesSB) {
        if (uniqueMatchesSB.indexOf(HTML_LIST_BULLET_OPEN + finding + HTML_LIST_BULLET_CLOSED) == -1) {
            uniqueMatchesSB.append(HTML_LIST_BULLET_OPEN);
            uniqueMatchesSB.append(finding);
            uniqueMatchesSB.append(HTML_LIST_BULLET_CLOSED);
        }
    }

    /**
     * Get matches in response body with Montoya API
     */
    public static List<int[]> getMatches(ByteArray response, List<byte[]> uniqueMatches) {
        List<int[]> matches = new ArrayList<>();

        for (byte[] match: uniqueMatches) {
            if (matches.size() < 500) {
                int start = 0;
                while (start < response.length()) {
                    start = response.indexOf(ByteArray.byteArray(match), start);
                    if (start == -1)
                        break;
                    matches.add(new int[] { start, start + match.length });
                    start += match.length;
                }
            } else {
                break;
            }
        }

        matches.sort(Comparator.comparingInt(o -> o[0]));

        // Fix overlapping offsets
        for (int i = 0; i < matches.size() - 1; i++) {
            if (matches.get(i)[1] > matches.get(i + 1)[0]) {
                matches.set(i, new int[]{matches.get(i)[0], matches.get(i + 1)[0]});
            }
        }

        return matches;
    }

    public static byte[] getHTTPResponseBodyHash(HttpRequestResponse requestResponse) {
        if (requestResponse.response() != null) {
            byte[] responseBodyBytes = requestResponse.response().body().getBytes();
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return digest.digest(responseBodyBytes);
            } catch (NoSuchAlgorithmException e) {
                BurpExtender.api.logging().logToError(e.getMessage());
                return new byte[0];
            }
        }
        return new byte[0];
    }

}
