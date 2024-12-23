package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.ui.menu.MenuItem;
import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.TaskRepository;
import burp.core.ScannerBuilder;


import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements BurpExtension {
    public static MontoyaApi api;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static final TaskRepository taskRepository = TaskRepository.getInstance();
    private static final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    public static final String EXTENSION_NAME = "JS Miner-NG";
    private static final String EXTENSION_VERSION = "2.0";
    private int taskCount = 0;

    @Override
    public void initialize(MontoyaApi api) {
        BurpExtender.api = api;
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize components
        TaskRepository.setApi(api);


        // Register unloading handler
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                taskRepository.destroy();
                api.logging().logToOutput("Sending shutdown signal to terminate any running threads...");
                executorServiceManager.getExecutorService().shutdownNow();
                api.logging().logToOutput("Extension was unloaded");
                api.logging().logToOutput("=================================================");
            }
        });
        
        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(this::createMenuItems);
        
        // Register HTTP handler for passive scanning
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (extensionConfig.isPassiveEnabled()) {
                    doPassiveScan(responseReceived);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.logging().logToOutput("Loading " + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        api.logging().logToOutput("Original Author: Mina M. Edwar");
        api.logging().logToOutput("Forked by: pedro (slicingmelon)");
        
        loadExtensionConfig();
    }

    private List<MenuItem> createMenuItems(ContextMenuEvent event) {
        if (!event.messageEditorRequestResponse().isPresent() && 
            !event.selectedRequestResponses().isEmpty()) {
            
            List<MenuItem> menuItems = new ArrayList<>();
            List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
            
            // Main menu item
            menuItems.add(MenuItem.builder()
                .text("Run JS Auto-Mine (check everything)")
                .action(e -> runAutoMine(selectedMessages))
                .build());
            
            // Add submenus
            menuItems.add(Menu.builder()
                .text("Scans")
                .menuItems(createScanMenuItems(selectedMessages))
                .build());
                
            menuItems.add(Menu.builder()
                .text("Config")
                .menuItems(createConfigMenuItems())
                .build());
                
            menuItems.add(Menu.builder()
                .text("Log")
                .menuItems(createLogMenuItems())
                .build());
                
            return menuItems;
        }

        private void runAutoMine(List<HttpRequestResponse> messages) {
            new Thread(() -> {
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder()
                    .withHttpRequestResponses(messages)
                    .runAllPassiveScans()
                    .taskId(++taskCount)
                    .timeStamp(ts)
                    .build();
                scannerBuilder.runScans();
            }).start();
        }

        private void doPassiveScan(HttpResponseReceived response) {
            new Thread(() -> {
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder()
                    .withHttpResponse(response)
                    .runAllPassiveScans()
                    .timeStamp(ts)
                    .build();
                scannerBuilder.runScans();
            }).start();
        }

    private void updateExtensionConfig() {
        api.extension().saveSetting(SETTING_VERBOSE_LOGGING, String.valueOf(extensionConfig.isVerboseLogging()));
        api.extension().saveSetting(SETTING_BURP_PASSIVE, String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    public void loadExtensionConfig() {
        if (api.extension().loadSetting(SETTING_VERBOSE_LOGGING) != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(api.extension().loadSetting(SETTING_VERBOSE_LOGGING)));
        }

        if (api.extension().loadSetting(SETTING_BURP_PASSIVE) != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(api.extension().loadSetting(SETTING_BURP_PASSIVE)));
        }

    }


    /*
     *  Context menu items
     */
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenu scanItems = new JMenu("Scans");
        JMenu logItems = new JMenu("Log");
        JMenu configItems = new JMenu("Config");

        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE == invocation.getInvocationContext()
        ) {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

            // === Main Scans Menu Items ==== //
            JMenuItem autoMineItem = new JMenuItem("Run JS Auto-Mine (check everything)");
            JSAutoMineItemAction autoMineItemActionAction = new JSAutoMineItemAction(selectedMessages);
            autoMineItem.addActionListener(autoMineItemActionAction);
            items.add(autoMineItem);

            JMenuItem findInterestingStuffItem = new JMenuItem("Run all passive scans ");
            AllPassiveScansItemAction findStuffAction = new AllPassiveScansItemAction(selectedMessages);
            findInterestingStuffItem.addActionListener(findStuffAction);
            items.add(findInterestingStuffItem);

            // === Specific Scans Menu Items ==== //
            JMenuItem jsSourceMapItem = new JMenuItem("JS source mapper (active)");
            ActiveSourceMapsItemAction jsMapAction = new ActiveSourceMapsItemAction(selectedMessages);
            jsSourceMapItem.addActionListener(jsMapAction);
            scanItems.add(jsSourceMapItem);

            JMenuItem secretsMenuItem = new JMenuItem("Secrets");
            secretsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanSecrets()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(secretsMenuItem);

            JMenuItem dependencyConfusionMenuItem = new JMenuItem("Dependency Confusion");
            dependencyConfusionMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanDependencyConfusion()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(dependencyConfusionMenuItem);

            JMenuItem subDomainsMenuItem = new JMenuItem("SubDomains");
            subDomainsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanSubDomains()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(subDomainsMenuItem);

            JMenuItem cloudURLsMenuItem = new JMenuItem("Cloud URLs");
            cloudURLsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanCloudURLs()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(cloudURLsMenuItem);

            JMenuItem inlineSourceMapsMenuItem = new JMenuItem("Inline B64 JS Source Maps");
            inlineSourceMapsMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    long ts = Instant.now().toEpochMilli();
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .scanInlineSourceMapFiles()
                            .taskId(++taskCount)
                            .timeStamp(ts)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(inlineSourceMapsMenuItem);

            JMenuItem dumpStaticFilesMenuItem = new JMenuItem("Dump Static Files");
            dumpStaticFilesMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    long ts = Instant.now().toEpochMilli();
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .dumpStaticFiles()
                            .taskId(++taskCount)
                            .timeStamp(ts)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(dumpStaticFilesMenuItem);

            JMenuItem endpointsFinderMenuItem = new JMenuItem("API Endpoints Finder");
            endpointsFinderMenuItem.addActionListener(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(selectedMessages)
                            .endpointsFinder()
                            .taskId(++taskCount)
                            .build();
                    scannerBuilder.runScans();
                }).start();
            });
            scanItems.add(endpointsFinderMenuItem);

            // === Logging Menu Items ==== //
            JMenuItem checkTasksMenuItem = new JMenuItem("Tasks Summary");
            checkTasksMenuItem.addActionListener(e -> {
                api.logging().logToOutput("[=============== Tasks Summary =============]");
                api.logging().logToOutput("Total Tasks: " + taskRepository.getSize());
                api.logging().logToOutput("Queued tasks: " + taskRepository.getQueuedTasks().size());
                api.logging().logToOutput("Completed tasks: " + taskRepository.getCompletedTasks().size());
                api.logging().logToOutput("Running tasks: " + taskRepository.getRunningTasks().size());
                api.logging().logToOutput("Failed tasks: " + taskRepository.getFailedTasks().size());
                api.logging().logToOutput("============================================");
            });
            logItems.add(checkTasksMenuItem);

            JMenuItem runningMenuItem = new JMenuItem("Log Uncompleted Tasks");
            runningMenuItem.addActionListener(e -> {
                api.logging().logToOutput("[=============== Uncompleted Tasks =============]");

                int runningTasksSize = taskRepository.getRunningTasks().size();
                // If there was some timed out tasks, print them for troubleshooting or local checking
                if (runningTasksSize > 0) {
                    api.logging().logToOutput("Running tasks:" + taskRepository.printRunningTasks().toString());
                    api.logging().logToOutput("=============================================");
                }

                int failedTasksSize = taskRepository.getFailedTasks().size();
                // If there was some timed out tasks, print them for troubleshooting or local checking
                if (failedTasksSize > 0) {
                    api.logging().logToOutput("Failed tasks:" + taskRepository.printFailedTasks().toString());
                    api.logging().logToOutput("=============================================");
                }
            });
            logItems.add(runningMenuItem);

            // === Configuration Menu Items ==== //
            JMenuItem toggleLoggingMenuItem = new JMenuItem(extensionConfig.loggingConfigMenuItemText());
            toggleLoggingMenuItem.addActionListener(e -> {
                extensionConfig.toggleLogging();
                updateExtensionConfig();
            });
            configItems.add(toggleLoggingMenuItem);

            JMenuItem toggleBurpPassiveScanMenuItem = new JMenuItem(extensionConfig.passiveConfigMenuItemText());
            toggleBurpPassiveScanMenuItem.addActionListener(e -> {
                extensionConfig.togglePassiveScans();
                updateExtensionConfig();
            });
            configItems.add(toggleBurpPassiveScanMenuItem);

            items.add(configItems);
            items.add(scanItems);
            items.add(logItems);
        }
        return items;
    }

    private List<MenuItem> createScanMenuItems(List<HttpRequestResponse> messages) {
        List<MenuItem> menuItems = new ArrayList<>();
        
        // All passive scans
        menuItems.add(MenuItem.builder()
            .text("Run all passive scans")
            .action(e -> {
                new Thread(() -> {
                    long ts = Instant.now().toEpochMilli();
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0]))
                        .runAllPassiveScans()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                    scannerBuilder.runScans();
                }).start();
            })
            .build());
            
        // JS source mapper
        // Source Mapper
        menuItems.add(MenuItem.builder()
            .text("JS source mapper (active)")
            .action(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0]))
                        .scanSourceMapper()
                        .taskId(++taskCount)
                        .build();
                    scannerBuilder.runScans();
                }).start();
            })
            .build());
            
              // Add other scan items using the same pattern
              addScanMenuItem(menuItems, "Secrets", messages, ScannerBuilder.Builder::scanSecrets);
              addScanMenuItem(menuItems, "Dependency Confusion", messages, ScannerBuilder.Builder::scanDependencyConfusion);
              addScanMenuItem(menuItems, "SubDomains", messages, ScannerBuilder.Builder::scanSubdomains);
              addScanMenuItem(menuItems, "Cloud URLs", messages, ScannerBuilder.Builder::scanCloudURLs);
              addScanMenuItem(menuItems, "Inline B64 JS Source Maps", messages, b -> b.scanSourceMapper().timeStamp(Instant.now().toEpochMilli()));
              addScanMenuItem(menuItems, "Dump Static Files", messages, b -> b.dumpStaticFiles().timeStamp(Instant.now().toEpochMilli()));
              addScanMenuItem(menuItems, "API Endpoints Finder", messages, ScannerBuilder.Builder::scanEndpoints);
              
              return menuItems;
        }

    private void addScanMenuItem(List<MenuItem> menuItems, String text, List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        menuItems.add(MenuItem.builder()
            .text(text)
            .action(e -> {
                new Thread(() -> {
                    ScannerBuilder scannerBuilder = scanType.apply(new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0])))
                        .taskId(++taskCount)
                        .build();
                    scannerBuilder.runScans();
                }).start();
            })
            .build());
    }

    private void runScan(List<HttpRequestResponse> messages, Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        new Thread(() -> {
            ScannerBuilder scannerBuilder = scanType.apply(new ScannerBuilder.Builder(messages.toArray(new HttpRequestResponse[0])))
                .taskId(++taskCount)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private List<MenuItem> createConfigMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.loggingConfigMenuItemText())
            .action(e -> {
                extensionConfig.toggleLogging();
                updateExtensionConfig();
            })
            .build());
            
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.passiveConfigMenuItemText())
            .action(e -> {
                extensionConfig.togglePassiveScans();
                updateExtensionConfig();
            })
            .build());
            
        return menuItems;
    }

    private List<MenuItem> createLogMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        
        menuItems.add(MenuItem.builder()
            .text("Check tasks")
            .action(e -> {
                api.logging().logToOutput("[=============== Tasks Summary =============]");
                api.logging().logToOutput("Total Tasks: " + taskRepository.getSize());
                api.logging().logToOutput("Queued tasks: " + taskRepository.getQueuedTasks().size());
                api.logging().logToOutput("Completed tasks: " + taskRepository.getCompletedTasks().size());
                api.logging().logToOutput("Running tasks: " + taskRepository.getRunningTasks().size());
                api.logging().logToOutput("Failed tasks: " + taskRepository.getFailedTasks().size());
                api.logging().logToOutput("============================================");
            })
            .build());
            
        menuItems.add(MenuItem.builder()
            .text("Print uncompleted tasks")
            .action(e -> {
                api.logging().logToOutput("[=============== Uncompleted Tasks =============]");
                int runningTasksSize = taskRepository.getRunningTasks().size();
                if (runningTasksSize > 0) {
                    api.logging().logToOutput("Running tasks:" + taskRepository.printRunningTasks());
                    api.logging().logToOutput("=============================================");
                }
                int failedTasksSize = taskRepository.getFailedTasks().size();
                if (failedTasksSize > 0) {
                    api.logging().logToOutput("Failed tasks:" + taskRepository.printFailedTasks());
                    api.logging().logToOutput("=============================================");
                }
            })
            .build());
            
        return menuItems;
    }

}