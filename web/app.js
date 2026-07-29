"use strict";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
let current = null;

const $ = (id) => document.getElementById(id);
const riskEl = $("risk");
const totalEl = $("findings-total");
const filesEl = $("files-scanned");
const severityEl = $("severity-list");
const typeEl = $("type-list");
const findingsEl = $("findings");
const filterEl = $("severity-filter");
const inputEl = $("report-input");

function rows(target, items, empty) {
  target.textContent = "";
  if (!items.length) {
    const p = document.createElement("p");
    p.className = "metric-label";
    p.textContent = empty;
    target.appendChild(p);
    return;
  }
  for (const [label, value] of items) {
    const row = document.createElement("div");
    row.className = "metric-row";
    const l = document.createElement("span");
    l.className = "metric-label";
    l.textContent = label;
    const v = document.createElement("span");
    v.className = "metric-value";
    v.textContent = String(value);
    row.append(l, v);
    target.appendChild(row);
  }
}

function renderFindings(findings) {
  findingsEl.textContent = "";
  const selected = filterEl.value;
  const filtered = selected === "ALL" ? findings : findings.filter((f) => f.severity === selected);
  if (!filtered.length) {
    const p = document.createElement("p");
    p.className = "metric-label";
    p.textContent = "No findings match this filter.";
    findingsEl.appendChild(p);
    return;
  }
  for (const finding of filtered) {
    const card = document.createElement("article");
    card.className = `finding ${finding.severity}`;
    const title = document.createElement("div");
    title.className = "finding-title";
    const left = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = finding.secret_type;
    const meta = document.createElement("div");
    meta.className = "finding-meta";
    meta.textContent = `${finding.file}:${finding.line_number} | redacted match: ${finding.matched_text}`;
    left.append(strong, meta);
    const badge = document.createElement("span");
    badge.className = `badge ${finding.severity}`;
    badge.textContent = finding.severity;
    title.append(left, badge);
    const snippet = document.createElement("pre");
    snippet.className = "snippet";
    snippet.textContent = finding.line_content;
    card.append(title, snippet);
    findingsEl.appendChild(card);
  }
}

function render(report) {
  current = report;
  const summary = report.summary || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  riskEl.textContent = summary.risk_level || (findings.length ? "REVIEW" : "LOW");
  totalEl.textContent = String(report.total_findings ?? findings.length);
  filesEl.textContent = String(report.files_scanned ?? 0);
  rows(severityEl, SEVERITIES.map((s) => [s, (summary.severity_counts || {})[s] || 0]), "No severity data.");
  rows(typeEl, Object.entries(summary.secret_type_counts || {}), "No secret type data.");
  renderFindings(findings);
}

filterEl.addEventListener("change", () => current && renderFindings(current.findings || []));
inputEl.addEventListener("change", async (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  render(JSON.parse(await file.text()));
});

fetch("./sample-report.json")
  .then((response) => response.json())
  .then(render)
  .catch(() => { findingsEl.textContent = "Could not load sample-report.json."; });
