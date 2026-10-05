package com.threatloop.pipeline;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdExtractor;
import com.threatloop.pipeline.diff.DiffResult;
import com.threatloop.pipeline.diff.ThreatDiffEngine;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;
import com.threatloop.pipeline.report.JsonReportWriter;
import com.threatloop.pipeline.report.RunRecord;
import com.threatloop.pipeline.rules.*;
import com.threatloop.pipeline.ticketing.GitHubIssuesClient;
import com.threatloop.pipeline.ticketing.Ticket;
import com.threatloop.pipeline.ticketing.TicketGenerator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;

public class Main {
    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        
        String projectRoot = null;
        String outputDir = null;
        String repo = System.getenv("GITHUB_REPOSITORY");
        String token = System.getenv("GITHUB_TOKEN");
        String disabledCategoriesStr = null;
        String runId = UUID.randomUUID().toString();
        String sha = "unknown";
        String branch = "unknown";
        boolean dryRun = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--project-root": projectRoot = args[++i]; break;
                case "--output-dir": outputDir = args[++i]; break;
                case "--repo": repo = args[++i]; break;
                case "--token": token = args[++i]; break;
                case "--disabled-categories": disabledCategoriesStr = args[++i]; break;
                case "--run-id": runId = args[++i]; break;
                case "--sha": sha = args[++i]; break;
                case "--branch": branch = args[++i]; break;
                case "--dry-run": dryRun = true; break;
            }
        }

        if (projectRoot == null || outputDir == null) {
            System.err.println("Usage: --project-root <path> --output-dir <path> [options]");
            System.exit(1);
        }

        try {
            DfdExtractor extractor = new DfdExtractor();
            DataFlowDiagram dfd = extractor.extract(Paths.get(projectRoot));

            Set<StrideCategory> enabledCategories = new HashSet<>(Arrays.asList(StrideCategory.values()));
            if (disabledCategoriesStr != null && !disabledCategoriesStr.isEmpty()) {
                for (String c : disabledCategoriesStr.split(",")) {
                    enabledCategories.remove(StrideCategory.valueOf(c.trim()));
                }
            }

            List<ThreatRule> rules = Arrays.asList(
                new SpoofingRule(),
                new TamperingRule(),
                new RepudiationRule(),
                new InfoDisclosureRule(),
                new DenialOfServiceRule(),
                new ElevationOfPrivilegeRule()
            );

            StrideRuleEngine engine = new StrideRuleEngine(rules, enabledCategories);
            List<Threat> currentThreats = engine.run(dfd);

            List<Threat> previousThreats = new ArrayList<>();
            Path prevThreatsPath = Paths.get(outputDir, "threats.json");
            ObjectMapper mapper = new ObjectMapper();
            if (Files.exists(prevThreatsPath)) {
                JsonNode root = mapper.readTree(Files.readString(prevThreatsPath));
                JsonNode threatsNode = root.get("threats");
                if (threatsNode != null) {
                    previousThreats = mapper.readValue(threatsNode.traverse(), new TypeReference<List<Threat>>() {});
                }
            }

            ThreatDiffEngine diffEngine = new ThreatDiffEngine();
            DiffResult diffResult = diffEngine.diff(currentThreats, previousThreats);

            List<Ticket> tickets = new ArrayList<>();
            if (!dryRun) {
                if (repo != null && repo.contains("/") && token != null) {
                    String[] parts = repo.split("/");
                    GitHubIssuesClient ghClient = new GitHubIssuesClient(token, parts[0], parts[1]);
                    TicketGenerator ticketGenerator = new TicketGenerator(ghClient);
                    tickets = ticketGenerator.generateTickets(diffResult.newThreats());
                } else {
                    System.err.println("Warning: --repo or --token not provided (or invalid). Skipping ticket generation.");
                }
            }

            long durationMs = System.currentTimeMillis() - startTime;
            RunRecord runRecord = new RunRecord(runId, sha, branch, Instant.now().toString(), durationMs, diffResult.newThreats().size(), "SUCCESS");

            JsonReportWriter reportWriter = new JsonReportWriter(Paths.get(outputDir));
            reportWriter.write(currentThreats, tickets, runRecord);

            System.out.printf("ThreatLoop run %s: %d new, %d changed, %d resolved threats\n",
                runId, diffResult.newThreats().size(), diffResult.changedThreats().size(), diffResult.resolvedThreats().size());
            System.exit(0);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
