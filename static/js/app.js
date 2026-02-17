const targetInput = document.getElementById("target");
const headersInput = document.getElementById("headers");
const runAllButton = document.getElementById("run-all");

const copSummary = document.getElementById("cop-summary");
const copOutput = document.getElementById("cop-output");
const w00fSummary = document.getElementById("w00f-summary");
const w00fOutput = document.getElementById("w00f-output");
const voyagerStatus = document.getElementById("voyager-status");

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

function renderCop(findings) {
  const failing = findings.filter((item) => item.result);
  copSummary.textContent = `Detected ${failing.length} positive findings out of ${findings.length} tests.`;
  copOutput.textContent = JSON.stringify(findings, null, 2);
}

function renderGraphw00f(output) {
  w00fSummary.textContent = "Fingerprint detection complete.";
  w00fOutput.textContent = output || "No output returned.";
}

function renderVoyager(introspection) {
  voyagerStatus.textContent = "Interactive schema graph loaded.";
  GraphQLVoyager.init(document.getElementById("voyager"), {
    introspection,
    hideDocs: false,
  });
}

runAllButton.addEventListener("click", async () => {
  const payload = {
    target: targetInput.value.trim(),
    headers: headersInput.value.trim(),
  };

  if (!payload.target) {
    alert("Please enter a target GraphQL endpoint.");
    return;
  }

  copSummary.textContent = "Running GraphQL Cop...";
  w00fSummary.textContent = "Running Graphw00f...";
  voyagerStatus.textContent = "Loading introspection for Voyager...";

  try {
    const copData = await apiPost("/api/graphql-cop", payload);
    renderCop(copData.findings);
  } catch (error) {
    copSummary.textContent = `GraphQL Cop failed: ${error.message}`;
  }

  try {
    const w00fData = await apiPost("/api/graphw00f", payload);
    renderGraphw00f(w00fData.output);
  } catch (error) {
    w00fSummary.textContent = `Graphw00f failed: ${error.message}`;
    w00fOutput.textContent = "";
  }

  try {
    const introspectionData = await apiPost("/api/introspection", payload);
    renderVoyager(introspectionData.introspection);
  } catch (error) {
    voyagerStatus.textContent = `Voyager load failed: ${error.message}`;
  }
});
