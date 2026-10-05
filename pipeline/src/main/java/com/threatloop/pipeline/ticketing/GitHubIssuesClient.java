package com.threatloop.pipeline.ticketing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.threatloop.pipeline.model.Threat;
import okhttp3.*;

import java.io.IOException;

public class GitHubIssuesClient implements IssueTrackerClient {
    private final String token;
    private final String repoOwner;
    private final String repoName;
    private final OkHttpClient client;
    private final ObjectMapper mapper;

    public GitHubIssuesClient(String token, String repoOwner, String repoName) {
        this.token = token;
        this.repoOwner = repoOwner;
        this.repoName = repoName;
        this.client = new OkHttpClient();
        this.mapper = new ObjectMapper();
    }

    @Override
    public Ticket file(Threat threat) throws Exception {
        ObjectNode bodyObj = mapper.createObjectNode();
        bodyObj.put("title", "[STRIDE-" + threat.category() + "] " + threat.title());
        
        String body = String.format("**Severity**: %s\n**Affected**: %s\n\n**Description**:\n%s\n\n**Mitigation**:\n%s\n\n---\n_Auto-filed by ThreatLoop pipeline. Run ID: %s_",
            threat.severity(), threat.affectedElementId(), threat.description(), threat.mitigation(), threat.runId());
        bodyObj.put("body", body);

        ArrayNode labels = mapper.createArrayNode();
        labels.add(threat.category().name().toLowerCase());
        labels.add(threat.severity().name().toLowerCase());
        labels.add("threat-model");
        bodyObj.set("labels", labels);

        RequestBody reqBody = RequestBody.create(mapper.writeValueAsString(bodyObj), MediaType.get("application/json"));

        String url = String.format("https://api.github.com/repos/%s/%s/issues", repoOwner, repoName);
        Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer " + token)
            .addHeader("Accept", "application/vnd.github.v3+json")
            .post(reqBody)
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }

            JsonNode resNode = mapper.readTree(response.body().string());
            int number = resNode.get("number").asInt();
            String htmlUrl = resNode.get("html_url").asText();
            
            return new Ticket(threat.id(), String.valueOf(number), htmlUrl, "OPEN");
        }
    }
}
