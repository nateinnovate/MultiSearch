"use strict";

const params = new URLSearchParams(window.location.search);
const runId = params.get("run");
const isTest = params.get("test") === "1";

const ui = {
    identifier: document.getElementById("runIdentifier"),
    state: document.getElementById("runState"),
    progressText: document.getElementById("progressText"),
    progressBar: document.getElementById("progressBar"),
    progressTrack: document.getElementById("progressTrack"),
    error: document.getElementById("runError"),
    installHelp: document.getElementById("installHelp"),
    installCommand: document.getElementById("installCommand"),
    summary: document.getElementById("summaryGrid"),
    results: document.getElementById("resultsList")
};

let pollHandle = null;
let isFinished = false;

function setState(value, stateClass) {
    ui.state.textContent = value;
    ui.state.className = `holehe-state ${stateClass || ""}`.trim();
}

function showError(message, installCommand = null) {
    ui.error.textContent = message;
    ui.error.hidden = false;
    setState("Failed", "is-failed");
    ui.progressText.textContent = "The run did not start or could not complete.";
    if (installCommand) {
        ui.installCommand.textContent = installCommand;
        ui.installHelp.hidden = false;
    }
}

function updateProgress(completed, total) {
    const percentage = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
    ui.progressBar.style.width = `${percentage}%`;
    ui.progressTrack.setAttribute("aria-valuenow", String(percentage));
    ui.progressText.textContent = total > 0
        ? `${completed} of ${total} checks completed (${percentage}%).`
        : "Preparing the Holehe modules…";
}

function renderSummary(summary) {
    const entries = [
        ["checked", "Checks"],
        ["registered", "Registered"],
        ["notFound", "Not found"],
        ["rateLimited", "Rate-limited"],
        ["errors", "Errors / unknown"]
    ];
    ui.summary.replaceChildren();
    entries.forEach(([key, label]) => {
        const item = document.createElement("div");
        item.className = "holehe-summary-item";
        const value = document.createElement("strong");
        value.textContent = String(Number(summary?.[key] || 0));
        const caption = document.createElement("span");
        caption.textContent = label;
        item.append(value, caption);
        ui.summary.appendChild(item);
    });
    ui.summary.hidden = false;
}

function renderResults(results) {
    ui.results.replaceChildren();
    if (!Array.isArray(results) || results.length === 0) {
        const empty = document.createElement("p");
        empty.className = "empty-message";
        empty.textContent = "Holehe did not return any site results for this run.";
        ui.results.appendChild(empty);
        return;
    }

    const labels = {
        registered: "Account indicated",
        not_found: "No account indicated",
        rate_limited: "Rate-limited · inconclusive",
        error: "Check error · inconclusive",
        unknown: "Unknown · inconclusive"
    };
    results.forEach(result => {
        const row = document.createElement("div");
        row.className = "holehe-result-row";
        const site = document.createElement("span");
        site.className = "holehe-result-site";
        site.textContent = result.site || "Unknown service";
        const status = document.createElement("span");
        status.className = "holehe-result-status";
        status.textContent = labels[result.status] || "Unknown · inconclusive";
        row.append(site, status);
        ui.results.appendChild(row);
    });
}

async function checkInstall() {
    ui.identifier.textContent = "Checking whether Holehe is installed in the Python environment used by OIW.";
    try {
        const response = await fetch("/api/holehe/status", { cache: "no-store" });
        const status = await response.json();
        if (!response.ok) throw new Error(status.error || `HTTP ${response.status}`);
        if (status.installed) {
            setState("Installed", "is-completed");
            ui.progressText.textContent = `Holehe ${status.version || "version unknown"} is available. No search was submitted.`;
        } else {
            showError("Holehe is not installed in the Python environment that starts OIW.",
                "python -m pip install -r requirements-holehe.txt");
        }
    } catch (error) {
        showError(`Unable to check the Holehe installation: ${error.message}`);
    }
}

async function pollRun() {
    if (isFinished) return;
    try {
        const response = await fetch(`/api/holehe/runs/${encodeURIComponent(runId)}`, {
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });
        const job = await response.json();
        if (!response.ok) throw new Error(job.error || `HTTP ${response.status}`);

        ui.identifier.textContent = `Target: ${job.emailMasked || "hidden"} · Run ID: ${job.runId}`;
        const completed = Number(job.progress?.completed || 0);
        const total = Number(job.progress?.total || 0);
        updateProgress(completed, total);

        if (job.status === "queued") {
            setState("Queued", "is-running");
        } else if (job.status === "running") {
            setState("Running", "is-running");
        } else if (job.status === "completed") {
            isFinished = true;
            setState("Completed", "is-completed");
            updateProgress(total, total);
            ui.progressText.textContent = `Completed ${total} module checks.`;
            renderSummary(job.summary || {});
            renderResults(job.results || []);
        } else if (job.status === "failed") {
            isFinished = true;
            showError(job.error || "Holehe could not complete this run.");
        } else {
            throw new Error("The run returned an unrecognised status.");
        }
    } catch (error) {
        isFinished = true;
        showError(`Unable to retrieve Holehe results: ${error.message}`);
    }

    if (!isFinished) pollHandle = window.setTimeout(pollRun, 1200);
}

async function initialise() {
    const error = params.get("error");
    const command = params.get("command");
    if (error) {
        ui.identifier.textContent = "Holehe run could not be started.";
        showError(error, command);
        return;
    }
    if (isTest) {
        await checkInstall();
        return;
    }
    if (!runId) {
        ui.identifier.textContent = "No Holehe run was specified.";
        showError("Return to OIW, select an email address and launch the Local Holehe provider.");
        return;
    }
    await pollRun();
}

window.addEventListener("beforeunload", () => {
    if (pollHandle !== null) window.clearTimeout(pollHandle);
});

initialise();
