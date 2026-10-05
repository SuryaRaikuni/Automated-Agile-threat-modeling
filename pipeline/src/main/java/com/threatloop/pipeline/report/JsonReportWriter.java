package com.threatloop.pipeline.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.threatloop.pipeline.model.Threat;
import com.threatloop.pipeline.ticketing.Ticket;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public class JsonReportWriter {
    private final Path outputDir;
    private final ObjectMapper mapper;

    public JsonReportWriter(Path outputDir) {
        this.outputDir = outputDir;
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.mapper.enable(SerializationFeature.WRITE_ENUMS_USING_TO_STRING);
    }

    public void write(List<Threat> allThreats, List<Ticket> tickets, RunRecord run) throws IOException {
        Files.createDirectories(outputDir);

        ObjectNode threatsObj = mapper.createObjectNode();
        threatsObj.put("generatedAt", Instant.now().toString());
        ArrayNode threatsArr = mapper.valueToTree(allThreats);
        threatsObj.set("threats", threatsArr);
        Files.writeString(outputDir.resolve("threats.json"), mapper.writeValueAsString(threatsObj));

        Path runsPath = outputDir.resolve("runs.json");
        ObjectNode runsObj;
        ArrayNode runsArr;
        if (Files.exists(runsPath)) {
            runsObj = (ObjectNode) mapper.readTree(Files.readString(runsPath));
            runsArr = (ArrayNode) runsObj.get("runs");
        } else {
            runsObj = mapper.createObjectNode();
            runsArr = mapper.createArrayNode();
            runsObj.set("runs", runsArr);
        }
        runsArr.add(mapper.valueToTree(run));
        Files.writeString(runsPath, mapper.writeValueAsString(runsObj));

        ObjectNode backlogObj = mapper.createObjectNode();
        ArrayNode backlogArr = mapper.valueToTree(tickets);
        backlogObj.set("tickets", backlogArr);
        Files.writeString(outputDir.resolve("backlog.json"), mapper.writeValueAsString(backlogObj));
    }
}
