const targetInput = document.getElementById("target");
const headersInput = document.getElementById("headers");
const analyzeButton = document.getElementById("analyze");
const analysisStatus = document.getElementById("analysis-status");

const engineSummary = document.getElementById("engine-summary");
const engineNotes = document.getElementById("engine-notes");

const auditSummary = document.getElementById("audit-summary");
const auditOutput = document.getElementById("audit-output");

const objectsSummary = document.getElementById("objects-summary");
const objectsList = document.getElementById("objects-list");

const graphStatus = document.getElementById("graph-status");
const graphContainer = document.getElementById("schema-graph");

const queryInput = document.getElementById("query");
const variablesInput = document.getElementById("variables");
const operationNameInput = document.getElementById("operationName");
const runQueryButton = document.getElementById("run-query");
const queryOutput = document.getElementById("query-output");

function apiPost(url, payload) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).then(async (response) => {
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || JSON.stringify(data));
    }
    return data;
  });
}

function renderEngine(engine) {
  engineSummary.textContent = `Detected engine: ${engine.engine} (confidence score: ${engine.confidence}).`;
  engineNotes.innerHTML = "";
  engine.security_notes.forEach((note) => {
    const li = document.createElement("li");
    li.textContent = note;
    engineNotes.appendChild(li);
  });
}

function renderAudit(audit) {
  const positives = audit.filter((finding) => finding.result);
  auditSummary.textContent = `Detected ${positives.length} positive findings out of ${audit.length} checks.`;
  auditOutput.textContent = JSON.stringify(audit, null, 2);
}

function renderObjects(schema) {
  objectsSummary.textContent = `Loaded ${schema.object_count} object types.`;
  objectsList.innerHTML = "";

  schema.objects.forEach((objectType) => {
    const card = document.createElement("div");
    card.className = "object-card";

    const title = document.createElement("h3");
    title.textContent = `${objectType.name} (${objectType.field_count} fields)`;

    const fields = document.createElement("p");
    fields.textContent = objectType.fields.join(", ");

    card.appendChild(title);
    card.appendChild(fields);
    objectsList.appendChild(card);
  });
}

function renderGraph(graph) {
  graphStatus.textContent = "Interactive schema graph loaded.";

  cytoscape({
    container: graphContainer,
    elements: [...graph.nodes, ...graph.edges],
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#3b82f6",
          label: "data(label)",
          color: "#e5e7eb",
          "font-size": 10,
          "text-valign": "center",
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.4,
          "line-color": "#64748b",
          "target-arrow-color": "#64748b",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": 8,
          color: "#cbd5e1",
        },
      },
    ],
    layout: {
      name: "cose",
      animate: false,
      fit: true,
      padding: 30,
    },
  });
}

analyzeButton.addEventListener("click", async () => {
  const payload = {
    target: targetInput.value.trim(),
    headers: headersInput.value.trim(),
  };

  if (!payload.target) {
    alert("Please provide a target endpoint.");
    return;
  }

  analysisStatus.textContent = "Running full analysis...";
  graphStatus.textContent = "Rendering schema graph...";

  try {
    const data = await apiPost("/api/analyze", payload);
    renderEngine(data.engine);
    renderAudit(data.audit);
    renderObjects(data.schema);
    renderGraph(data.schema.graph);
    analysisStatus.textContent = "Analysis complete.";
  } catch (error) {
    analysisStatus.textContent = `Analysis failed: ${error.message}`;
  }
});

runQueryButton.addEventListener("click", async () => {
  const payload = {
    target: targetInput.value.trim(),
    headers: headersInput.value.trim(),
    query: queryInput.value,
    variables: variablesInput.value.trim(),
    operationName: operationNameInput.value.trim(),
  };

  if (!payload.target || !payload.query.trim()) {
    alert("Target and query are required.");
    return;
  }

  queryOutput.textContent = "Running query...";

  try {
    const data = await apiPost("/api/query", payload);
    queryOutput.textContent = JSON.stringify(data.result, null, 2);
  } catch (error) {
    queryOutput.textContent = `Query failed: ${error.message}`;
  }
});
