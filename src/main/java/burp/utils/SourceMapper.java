package burp.utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;

import static burp.BurpExtender.mStdErr;

/**
 * Class to construct the front-end source code from the passed JS map files
 */

public class SourceMapper {

    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

    private final IHttpRequestResponse httpRequestResponse;
    private final String jsonMapFile; // json string that potentially contains JS map file
    private final Path outputDirPath; // where we are going to store the source files

    /**
     * @param httpRequestResponse The HTTP request/response that should be included in Burp's scan alert
     * @param jsonMapFile         A json string that potentially contains JS map files
     * @param outputDirPath       The output directory where we store the constructed source code
     */
    public SourceMapper(IHttpRequestResponse httpRequestResponse, String jsonMapFile, Path outputDirPath) {
        this.httpRequestResponse = httpRequestResponse;
        this.jsonMapFile = jsonMapFile;
        this.outputDirPath = outputDirPath;
        parseMapFile();
    }

    // Function 1 - parse Map Files
    public void parseMapFile() {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            JSMapFile mapFile = objectMapper.readValue(jsonMapFile, JSMapFile.class);
            for (int i = 0; i <= mapFile.getSources().length - 1; i++) {
                if (FileUtils.saveFile(
                        mapFile.getSources()[i]
                                .replaceAll("\\?.*", "") // remove app.vue?d123 .. make it app.vue
                                .replaceAll("[?%*|:\"<>~]", ""),
                        helpers.stringToBytes(mapFile.getSourcesContent()[i]),
                        outputDirPath
                )) {
                    sendJSMapperIssue();
                }
            }
        } catch (Exception e) {
            mStdErr.println("[-] Error processing the file - parseMapFile Exception.");
        }
    }

    private void sendJSMapperIssue() {
        IScanIssue scanIssue = null;
        try {
            scanIssue = new CustomScanIssue(
                    httpRequestResponse.getHttpService(),
                    helpers.analyzeRequest(httpRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{httpRequestResponse},
                    "[JS Miner][legacy] JavaScript Source Mapper",
                    "This issue was generated by \"" + BurpExtender.EXTENSION_NAME + "\" Burp extension.<br><br>" +
                            "It was possible to retrieve JavaScript source map files of the target host." +
                            "The retrieved (front-end) source code is available (for manual review) in the following location:<br><br>"
                            + "<b>" + outputDirPath + "</b>",
                    null,
                    "Information",
                    "Certain");
        } catch (Exception e) {
            mStdErr.println("[-] createDirectoriesIfNotExist Exception.");
        }
        Utilities.reportIssueIfNotDuplicate(scanIssue, httpRequestResponse);
    }
}
