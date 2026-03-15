const form = document.getElementById("review-form");
const fileInput = document.getElementById("archive");
const submitButton = document.getElementById("submit-button");
const statusNode = document.getElementById("status");
const resultShell = document.getElementById("result-shell");
const summaryGrid = document.getElementById("summary-grid");
const checksNode = document.getElementById("checks");
const issuesNode = document.getElementById("issues");
const observationsNode = document.getElementById("observations");

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function badgeClass(level) {
  const normalized = String(level || "low").toLowerCase();
  return `badge badge-${normalized}`;
}

function levelText(level) {
  const normalized = String(level || "low").toLowerCase();
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  return "Low";
}

function renderSummary(data) {
  const cards = [
    ["Archive File", data.filename || "-", "summary-value filename-value"],
    ["Overall Level", levelText(data.overall_level), "summary-value"],
    ["Risk Score", data.risk_score ?? 0, "summary-value"],
    ["Issue Count", data.issue_count ?? 0, "summary-value"],
    ["Observation Count", data.observation_count ?? 0, "summary-value"],
    ["Uncompressed Size", data.archive?.uncompressed_size_text || "-", "summary-value"],
  ];

  summaryGrid.innerHTML = cards
    .map(
      ([label, value, valueClass]) => `
        <article class="summary-card">
          <p class="summary-label">${escapeHtml(label)}</p>
          <p class="${escapeHtml(valueClass || "summary-value")}">${escapeHtml(value)}</p>
        </article>
      `
    )
    .join("");
}

function renderChecks(checks) {
  checksNode.innerHTML = (checks || [])
    .map(
      (item) => `
        <article class="check-card">
          <div class="card-top">
            <h3>${escapeHtml(item.id || "check")}</h3>
            <span class="${badgeClass(item.level)}">${escapeHtml(levelText(item.level))}</span>
          </div>
          <p>${escapeHtml(item.summary || "")}</p>
          <ul class="fact-list">
            ${(item.facts || [])
              .map((fact) => `<li>${escapeHtml(fact)}</li>`)
              .join("")}
          </ul>
        </article>
      `
    )
    .join("");
}

function renderFindings(container, items, emptyText, includeSeverity) {
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
    return;
  }

  container.innerHTML = items
    .map((item) => {
      const meta = [];
      if (includeSeverity) {
        meta.push(`<span class="${badgeClass(item.severity)}">${escapeHtml(levelText(item.severity))}</span>`);
      }
      if (item.type) {
        meta.push(`<span class="meta-line">${escapeHtml(item.type)}</span>`);
      }
      if (item.file) {
        meta.push(`<span class="meta-line">${escapeHtml(item.file)}</span>`);
      }

      return `
        <article class="finding-card">
          <div class="card-top">
            <h3>${escapeHtml(item.title || "Untitled item")}</h3>
            <div>${meta.join(" ")}</div>
          </div>
          <p>${escapeHtml(item.detail || "")}</p>
        </article>
      `;
    })
    .join("");
}

async function submitReview(event) {
  event.preventDefault();

  if (!fileInput.files || fileInput.files.length === 0) {
    statusNode.textContent = "Choose a ZIP file before we start the review.";
    return;
  }

  const formData = new FormData();
  formData.append("archive", fileInput.files[0]);

  submitButton.disabled = true;
  statusNode.textContent = "Scanning archive contents, please wait...";

  try {
    const response = await fetch("/api/review", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Review failed. Please try again.");
    }

    renderSummary(data);
    renderChecks(data.checks || []);
    renderFindings(issuesNode, data.issues || [], "No explicit issue signals were identified in this run.", true);
    renderFindings(observationsNode, data.observations || [], "No additional observations were recorded in this run.", false);
    resultShell.classList.remove("is-hidden");
    statusNode.textContent = `Review complete: ${data.filename || "archive.zip"}.`;
  } catch (error) {
    statusNode.textContent = error.message || "Review failed. Please try again.";
  } finally {
    submitButton.disabled = false;
  }
}

form.addEventListener("submit", submitReview);

fileInput.addEventListener("change", () => {
  const [file] = fileInput.files || [];
  statusNode.textContent = file ? `Selected: ${file.name}` : "Waiting for a file upload.";
});



