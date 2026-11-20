"use strict";

// ==================================================
// OSINT INVESTIGATION WORKSTATION
// Version 0.3.4
// ==================================================

const IDENTIFIER_TYPES = ["username", "email", "phone", "name", "domain", "ip"];
const MAX_PROVIDERS = 200;

const ui = {
    platformContainer: document.getElementById("platforms"),
    searchType: document.getElementById("searchType"),
    searchTerm: document.getElementById("searchTerm"),
    launchButton: document.getElementById("launchButton"),
    selectionCount: document.getElementById("selectionCount"),
    selectAllButton: document.getElementById("selectAll"),
    selectNoneButton: document.getElementById("selectNone"),
    manageProvidersButton: document.getElementById("manageProviders"),
    providerDialog: document.getElementById("providerDialog"),
    closeProviderManagerButton: document.getElementById("closeProviderManager"),
    providerSearch: document.getElementById("providerSearch"),
    categoryFilter: document.getElementById("categoryFilter"),
    providerTotal: document.getElementById("providerTotal"),
    addProviderButton: document.getElementById("addProvider"),
    providerList: document.getElementById("providerList"),
    editProviderDialog: document.getElementById("editProviderDialog"),
    editorTitle: document.getElementById("editorTitle"),
    editorDescription: document.getElementById("editorDescription"),
    closeEditorButton: document.getElementById("closeEditor"),
    providerForm: document.getElementById("providerForm"),
    providerId: document.getElementById("providerId"),
    providerName: document.getElementById("providerName"),
    providerCategory: document.getElementById("providerCategory"),
    providerUrlGroup: document.getElementById("providerUrlGroup"),
    providerUrl: document.getElementById("providerUrl"),
    providerMode: document.getElementById("providerMode"),
    providerIntegrationNote: document.getElementById("providerIntegrationNote"),
    templateGroup: document.getElementById("templateGroup"),
    providerTemplateFields: document.getElementById("providerTemplateFields"),
    cancelProviderButton: document.getElementById("cancelProvider")
};

let appConfig = { version: "2.0", providers: [] };
let providers = [];
let editorOriginalProvider = null;
let editorTemplateValues = {};
let isSaving = false;

function showNotification(message) {
    window.alert(message);
}

function cloneObject(value) {
    return JSON.parse(JSON.stringify(value));
}

function isHttpsUrl(value) {
    if (typeof value !== "string" || !value.trim()) return false;
    try {
        const parsed = new URL(value.trim());
        return parsed.protocol === "https:" && Boolean(parsed.hostname) &&
            !parsed.username && !parsed.password && !parsed.hash;
    } catch (error) {
        return false;
    }
}

function isValidTemplate(value) {
    if (typeof value !== "string" || !value.includes("{query}")) return false;
    return isHttpsUrl(value.replaceAll("{query}", "oiw-validation-test"));
}

function getTemplate(provider, identifierType) {
    if (provider.urlTemplates && typeof provider.urlTemplates[identifierType] === "string") {
        return provider.urlTemplates[identifierType];
    }
    // Compatibility for older query-template provider definitions.
    if (provider.mode === "query" && typeof provider.url === "string") {
        return provider.url;
    }
    return null;
}

function isHoleheIntegration(provider) {
    return provider && provider.integration === "holehe";
}

function getManualUrl(provider) {
    if (isHoleheIntegration(provider)) return null;
    if (typeof provider.manualUrl === "string") return provider.manualUrl;
    if (provider.mode === "manual" && typeof provider.url === "string") return provider.url;
    return null;
}

function providerIsAutomatic(provider, identifierType) {
    return Boolean(getTemplate(provider, identifierType));
}

function buildProviderUrl(provider, identifierType, term) {
    const template = getTemplate(provider, identifierType);
    if (template) {
        if (!isValidTemplate(template)) {
            throw new Error("Invalid HTTPS search template.");
        }
        const target = template.replaceAll("{query}", encodeURIComponent(term));
        const parsed = new URL(target);
        if (parsed.protocol !== "https:") {
            throw new Error("Only HTTPS provider URLs are permitted.");
        }
        return target;
    }

    const manualUrl = getManualUrl(provider);
    if (manualUrl && isHttpsUrl(manualUrl)) return manualUrl;
    throw new Error(`No valid URL is configured for ${identifierType}.`);
}

// --------------------------------------------------
// PROVIDER CONFIGURATION API
// --------------------------------------------------

async function loadProviders() {
    try {
        const response = await fetch("/api/providers", {
            method: "GET",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });
        if (!response.ok) throw new Error(`Server returned HTTP ${response.status}.`);

        const config = await response.json();
        if (!config || !Array.isArray(config.providers)) {
            throw new Error("The provider configuration has an invalid structure.");
        }
        appConfig = config;
        providers = config.providers;
        window.providers = providers;
        renderProviders();
        ui.manageProvidersButton.disabled = false;
        console.info(`OIW: ${providers.length} providers loaded.`);
    } catch (error) {
        console.error("OIW provider load failed:", error);
        ui.platformContainer.replaceChildren();
        const message = document.createElement("p");
        message.className = "empty-message";
        message.textContent = `Unable to load providers: ${error.message}`;
        ui.platformContainer.appendChild(message);
        ui.manageProvidersButton.disabled = true;
        ui.launchButton.disabled = true;
    }
}

async function persistConfig(nextConfig) {
    if (isSaving) throw new Error("A provider configuration change is already being saved.");
    isSaving = true;
    try {
        const response = await fetch("/api/providers", {
            method: "PUT",
            cache: "no-store",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify(nextConfig)
        });
        let result = {};
        try {
            result = await response.json();
        } catch (error) {
            // Keep the HTTP status as the useful error when the server sends no JSON.
        }
        if (!response.ok || result.success === false) {
            throw new Error(result.error || `Server returned HTTP ${response.status}.`);
        }
        appConfig = nextConfig;
        providers = nextConfig.providers;
        window.providers = providers;
        renderProviders();
        renderProviderManager();
        return result;
    } finally {
        isSaving = false;
    }
}

// --------------------------------------------------
// SEARCH PROVIDER SELECTION
// --------------------------------------------------

function getCompatibleProviders() {
    const identifierType = ui.searchType.value;
    return providers.filter(provider =>
        provider.enabled === true &&
        Array.isArray(provider.types) &&
        provider.types.includes(identifierType)
    );
}

function renderProviders() {
    const compatible = getCompatibleProviders();
    ui.platformContainer.replaceChildren();

    if (!compatible.length) {
        const empty = document.createElement("p");
        empty.className = "empty-message";
        empty.textContent = "No enabled providers support this identifier type. Use Manage Providers to add or enable one.";
        ui.platformContainer.appendChild(empty);
        updateSelectionCount();
        return;
    }

    compatible.forEach(provider => {
        const label = document.createElement("label");
        label.className = "platform";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = provider.id;
        checkbox.checked = true;
        checkbox.addEventListener("change", updateSelectionCount);

        const details = document.createElement("div");
        const name = document.createElement("div");
        name.className = "platform-name";
        name.textContent = provider.name;

        const category = document.createElement("div");
        category.className = "platform-category";
        const behaviour = isHoleheIntegration(provider)
            ? " · Local Holehe Python check"
            : (providerIsAutomatic(provider, ui.searchType.value)
                ? " · Automatic URL search"
                : " · Manual website");
        category.textContent = provider.category + behaviour;

        details.append(name, category);
        label.append(checkbox, details);
        ui.platformContainer.appendChild(label);
    });

    updateSelectionCount();
}

function getSelectedProviders() {
    const selectedIds = new Set(
        Array.from(ui.platformContainer.querySelectorAll('input[type="checkbox"]:checked'))
            .map(input => input.value)
    );
    return getCompatibleProviders().filter(provider => selectedIds.has(provider.id));
}

function updateSelectionCount() {
    const count = getSelectedProviders().length;
    ui.selectionCount.textContent = `${count} platform${count === 1 ? "" : "s"} selected`;
    ui.launchButton.disabled = count === 0;
}

function selectAllProviders(checked) {
    ui.platformContainer.querySelectorAll('input[type="checkbox"]').forEach(input => {
        input.checked = checked;
    });
    updateSelectionCount();
}

// --------------------------------------------------
// LAUNCH SEARCHES / OPEN MANUAL PROVIDERS
// --------------------------------------------------

async function copyIdentifier(term) {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") return false;
    try {
        await navigator.clipboard.writeText(term);
        return true;
    } catch (error) {
        console.warn("OIW: Clipboard access was unavailable.");
        return false;
    }
}

async function launchSearches() {
    const enteredTerm = ui.searchTerm.value;
    const selected = getSelectedProviders();
    if (!selected.length) {
        showNotification("Please select at least one provider.");
        return;
    }

    const usesHolehe = selected.some(isHoleheIntegration);
    // General web searches keep the existing whitespace trim. Local Holehe is
    // deliberately strict: the exact entered string is sent, without rewriting.
    const term = usesHolehe ? enteredTerm : enteredTerm.trim();
    if (!term.trim()) {
        showNotification("Please enter a search identifier.");
        ui.searchTerm.focus();
        return;
    }

    if (usesHolehe) {
        if (ui.searchType.value !== "email") {
            showNotification("Local Holehe accepts email addresses only.");
            return;
        }
        if (enteredTerm !== enteredTerm.trim()) {
            showNotification("Holehe will not alter the email address. Remove leading or trailing spaces yourself, then launch again.");
            ui.searchTerm.focus();
            return;
        }
        const exactEmailPattern = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
        if (!exactEmailPattern.test(enteredTerm)) {
            showNotification("Enter a valid email address. OIW will pass it to Holehe exactly as entered; it will not create alternatives or change characters.");
            ui.searchTerm.focus();
            return;
        }
    }

    const identifierType = ui.searchType.value;
    const errors = [];
    let automaticOpened = 0;
    let manualOpened = 0;
    let holeheStarted = 0;
    let blocked = 0;
    const holeheTabs = [];

    // Open all tabs synchronously from the user action so popup blockers are less likely to interfere.
    for (const provider of selected) {
        try {
            if (isHoleheIntegration(provider)) {
                if (identifierType !== "email") {
                    errors.push(`${provider.name}: Holehe supports email addresses only.`);
                    continue;
                }
                const tab = window.open("/holehe-results.html", "_blank");
                if (!tab) {
                    blocked += 1;
                    continue;
                }
                try { tab.opener = null; } catch (error) { /* Tab may already be navigating. */ }
                holeheTabs.push({ provider, tab });
                continue;
            }

            const automatic = providerIsAutomatic(provider, identifierType);
            const url = buildProviderUrl(provider, identifierType, term);
            const tab = window.open(url, "_blank");
            if (!tab) {
                blocked += 1;
                continue;
            }
            try { tab.opener = null; } catch (error) { /* Tab may already have navigated. */ }
            if (automatic) automaticOpened += 1;
            else manualOpened += 1;
        } catch (error) {
            errors.push(`${provider.name}: ${error.message}`);
            console.warn(`OIW: Could not open provider ${provider.id}.`);
        }
    }

    // Start each local Holehe run only after its dedicated result tab has been opened.
    for (const item of holeheTabs) {
        if (item.tab.closed) continue;
        try {
            const response = await fetch("/api/holehe/runs", {
                method: "POST",
                cache: "no-store",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ email: term })
            });
            let payload = {};
            try { payload = await response.json(); } catch (error) { /* Use HTTP status below. */ }
            if (!response.ok || !payload.runId) {
                throw new Error(payload.error || `Server returned HTTP ${response.status}.`);
            }
            item.tab.location.href = `/holehe-results.html?run=${encodeURIComponent(payload.runId)}`;
            holeheStarted += 1;
        } catch (error) {
            errors.push(`${item.provider.name}: ${error.message}`);
            try {
                item.tab.location.href = `/holehe-results.html?error=${encodeURIComponent(error.message)}`;
            } catch (navigationError) {
                console.warn("OIW: Could not display the Holehe startup error in its tab.");
            }
        }
    }

    const copyRequired = selected.some(provider =>
        !isHoleheIntegration(provider) &&
        !providerIsAutomatic(provider, identifierType) &&
        provider.clipboard === true
    );
    let copied = false;
    if (copyRequired) copied = await copyIdentifier(term);

    ui.selectionCount.textContent =
        `${automaticOpened} automatic · ${manualOpened} manual · ${holeheStarted} Holehe · ${blocked} blocked`;

    const summary = [
        `Automatic URL searches opened: ${automaticOpened}`,
        `Manual provider pages opened: ${manualOpened}`,
        `Local Holehe runs started: ${holeheStarted}`,
        `Pop-up windows blocked: ${blocked}`
    ];
    if (manualOpened > 0) {
        summary.push("Manual provider pages do not receive or submit the identifier automatically.");
    }
    if (holeheStarted > 0) {
        summary.push("Holehe is running locally. Its progress and results are in the separate OIW tab.");
        summary.push("Holehe uses its upstream no-password-recovery module selection by default.");
    }
    if (copyRequired) {
        summary.push(copied
            ? "Identifier copied to the clipboard for manual entry."
            : "Clipboard access failed; enter the identifier manually in the provider page.");
    }
    if (errors.length) summary.push("\nProvider errors:\n" + errors.join("\n"));
    showNotification(summary.join("\n"));
}

// --------------------------------------------------
// PROVIDER MANAGER
// --------------------------------------------------

function createActionButton(text, className, action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = text;
    button.addEventListener("click", action);
    return button;
}

function describeProvider(provider) {
    if (isHoleheIntegration(provider)) return "Local Python integration · email only";
    const automaticTypes = provider.types.filter(type => Boolean(getTemplate(provider, type)));
    const manual = Boolean(getManualUrl(provider));
    const details = [];
    if (automaticTypes.length) details.push(`Automatic: ${automaticTypes.join(", ")}`);
    if (manual) details.push(provider.clipboard ? "Manual · clipboard enabled" : "Manual · clipboard off");
    return details.join(" | ") || "No usable search route configured";
}

function renderProviderManager() {
    if (!ui.providerList) return;
    const query = ui.providerSearch.value.trim().toLowerCase();
    const category = ui.categoryFilter.value;
    const filtered = providers.filter(provider => {
        const matchesText = !query ||
            provider.name.toLowerCase().includes(query) ||
            provider.id.toLowerCase().includes(query) ||
            provider.category.toLowerCase().includes(query) ||
            provider.types.some(type => type.toLowerCase().includes(query));
        const matchesCategory = !category || provider.category === category;
        return matchesText && matchesCategory;
    });

    ui.providerTotal.textContent = `${filtered.length} shown · ${providers.length} total`;
    ui.providerList.replaceChildren();

    if (!filtered.length) {
        const empty = document.createElement("div");
        empty.className = "manager-empty";
        empty.textContent = providers.length
            ? "No providers match the current search or category filter."
            : "No providers configured yet. Select Add Provider to create one.";
        ui.providerList.appendChild(empty);
        return;
    }

    filtered.forEach(provider => {
        const card = document.createElement("article");
        card.className = "provider-card";

        const information = document.createElement("div");
        information.className = "provider-information";
        const title = document.createElement("h3");
        title.textContent = provider.name;
        const categoryLine = document.createElement("p");
        categoryLine.textContent = provider.category;
        const typesLine = document.createElement("small");
        typesLine.textContent = `Types: ${provider.types.join(", ")}`;
        const behaviourLine = document.createElement("small");
        behaviourLine.textContent = describeProvider(provider);
        const status = document.createElement("span");
        status.className = provider.enabled ? "status-enabled" : "status-disabled";
        status.textContent = provider.enabled ? "Enabled" : "Disabled";
        information.append(title, categoryLine, typesLine, behaviourLine, status);

        const actions = document.createElement("div");
        actions.className = "provider-actions";
        actions.append(
            createActionButton("Edit", "small-button", () => openProviderEditor(provider)),
            createActionButton("Duplicate", "small-button", () => duplicateProvider(provider)),
            createActionButton("Test", "small-button", () => testProvider(provider)),
            createActionButton(provider.enabled ? "Disable" : "Enable", "small-button", () => toggleProvider(provider)),
            createActionButton("Delete", "small-button danger-button", () => deleteProvider(provider))
        );
        card.append(information, actions);
        ui.providerList.appendChild(card);
    });
}

function openProviderManager() {
    renderProviderManager();
    if (!ui.providerDialog.open) ui.providerDialog.showModal();
}

function closeProviderManager() {
    if (ui.editProviderDialog.open) ui.editProviderDialog.close();
    if (ui.providerDialog.open) ui.providerDialog.close();
}

function providerIdFromName(name) {
    const slug = name.toLowerCase()
        .normalize("NFKD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 54);
    return slug || "provider";
}

function uniqueProviderId(baseId, ignoredId = null) {
    const used = new Set(providers.filter(provider => provider.id !== ignoredId).map(provider => provider.id));
    baseId = String(baseId).slice(0, 64);
    let candidate = baseId;
    let suffix = 2;
    while (used.has(candidate)) {
        const ending = `-${suffix}`;
        candidate = `${baseId.slice(0, 64 - ending.length)}${ending}`;
        suffix += 1;
    }
    return candidate;
}

function selectedEditorTypes() {
    return Array.from(ui.providerForm.querySelectorAll('input[name="providerType"]:checked'))
        .map(input => input.value);
}

function refreshTemplateInputs() {
    ui.providerTemplateFields.replaceChildren();
    const selectedTypes = selectedEditorTypes();
    selectedTypes.forEach(type => {
        const wrapper = document.createElement("div");
        wrapper.className = "template-field";
        const label = document.createElement("label");
        const input = document.createElement("input");
        const inputId = `template-${type}`;
        label.htmlFor = inputId;
        label.textContent = `${type.charAt(0).toUpperCase()}${type.slice(1)} search template`;
        input.id = inputId;
        input.type = "text";
        input.autocomplete = "off";
        input.spellcheck = false;
        input.placeholder = "https://example.com/search?q={query}";
        input.required = ui.providerMode.value === "automatic";
        input.value = editorTemplateValues[type] || "";
        input.dataset.identifierType = type;
        input.addEventListener("input", () => {
            editorTemplateValues[type] = input.value;
        });
        wrapper.append(label, input);
        ui.providerTemplateFields.appendChild(wrapper);
    });
}

function updateEditorMode() {
    const automatic = ui.providerMode.value === "automatic";
    const localHolehe = ui.providerMode.value === "holehe_local";
    ui.templateGroup.hidden = !automatic;
    ui.providerUrlGroup.hidden = automatic || localHolehe;
    ui.providerUrl.required = !automatic && !localHolehe;
    ui.providerIntegrationNote.hidden = !localHolehe;

    ui.providerForm.querySelectorAll('input[name="providerType"]').forEach(input => {
        if (localHolehe) {
            input.disabled = true;
            input.checked = input.value === "email";
        } else {
            input.disabled = false;
        }
    });
    if (localHolehe) ui.providerCategory.value = "Email intelligence";

    ui.providerTemplateFields.querySelectorAll("input").forEach(input => {
        input.required = automatic;
    });
    refreshTemplateInputs();
}

function openProviderEditor(provider = null) {
    editorOriginalProvider = provider ? cloneObject(provider) : null;
    editorTemplateValues = {};
    ui.providerForm.reset();
    ui.providerId.value = provider ? provider.id : "";
    ui.editorTitle.textContent = provider ? "Edit Provider" : "Add Provider";
    ui.editorDescription.textContent = provider
        ? "Changes are saved to the local provider configuration."
        : "Create an automatic URL search or a manual provider entry.";

    if (provider) {
        ui.providerName.value = provider.name;
        ui.providerCategory.value = provider.category;
        ui.providerUrl.value = getManualUrl(provider) || "";
        const templateTypes = Object.keys(provider.urlTemplates || {});
        templateTypes.forEach(type => { editorTemplateValues[type] = provider.urlTemplates[type]; });
        const mode = isHoleheIntegration(provider)
            ? "holehe_local"
            : (templateTypes.length
                ? "automatic"
                : (provider.clipboard === true ? "manual_clipboard" : "manual"));
        ui.providerMode.value = mode;
        ui.providerForm.querySelectorAll('input[name="providerType"]').forEach(input => {
            input.checked = provider.types.includes(input.value);
        });
    } else {
        ui.providerMode.value = "automatic";
        ui.providerCategory.value = "Search engines";
        ui.providerForm.querySelectorAll('input[name="providerType"]').forEach(input => {
            input.checked = false;
        });
    }

    refreshTemplateInputs();
    updateEditorMode();
    if (!ui.editProviderDialog.open) ui.editProviderDialog.showModal();
    ui.providerName.focus();
}

function closeProviderEditor() {
    if (ui.editProviderDialog.open) ui.editProviderDialog.close();
}

async function saveProviderFromForm(event) {
    event.preventDefault();
    if (isSaving) return;

    const name = ui.providerName.value.trim();
    const mode = ui.providerMode.value;
    const types = mode === "holehe_local" ? ["email"] : selectedEditorTypes();
    if (!name) return showNotification("Enter a provider name.");
    if (!types.length) return showNotification("Select at least one supported identifier type.");
    if (providers.length >= MAX_PROVIDERS && !editorOriginalProvider) {
        return showNotification(`The application supports up to ${MAX_PROVIDERS} providers.`);
    }

    const id = editorOriginalProvider
        ? editorOriginalProvider.id
        : uniqueProviderId(providerIdFromName(name));
    const duplicate = providers.some(provider => provider.id === id &&
        (!editorOriginalProvider || provider.id !== editorOriginalProvider.id));
    if (duplicate) return showNotification("A provider with this ID already exists.");

    const nextProvider = editorOriginalProvider ? cloneObject(editorOriginalProvider) : {};
    nextProvider.id = id;
    nextProvider.name = name;
    nextProvider.category = mode === "holehe_local" ? "Email intelligence" : ui.providerCategory.value;
    nextProvider.types = types;
    nextProvider.enabled = editorOriginalProvider ? editorOriginalProvider.enabled : true;

    if (mode === "holehe_local") {
        nextProvider.integration = "holehe";
        nextProvider.urlTemplates = {};
        delete nextProvider.manualUrl;
        delete nextProvider.clipboard;
    } else if (mode === "automatic") {
        delete nextProvider.integration;
        const templates = {};
        for (const type of types) {
            const template = (editorTemplateValues[type] || "").trim();
            if (!isValidTemplate(template)) {
                return showNotification(`Enter a valid HTTPS URL template containing {query} for ${type}.`);
            }
            templates[type] = template;
        }
        nextProvider.urlTemplates = templates;
        // Preserve a pre-existing manual fallback on hybrid providers.
        nextProvider.clipboard = editorOriginalProvider?.clipboard === true;
    } else {
        delete nextProvider.integration;
        const manualUrl = ui.providerUrl.value.trim();
        if (!isHttpsUrl(manualUrl)) {
            return showNotification("Enter a valid HTTPS manual provider website.");
        }
        nextProvider.urlTemplates = {};
        nextProvider.manualUrl = manualUrl;
        nextProvider.clipboard = mode === "manual_clipboard";
    }

    // Remove obsolete single-URL fields after converting the provider to the current schema.
    delete nextProvider.mode;
    delete nextProvider.url;

    const nextConfig = cloneObject(appConfig);
    const existingIndex = nextConfig.providers.findIndex(provider => provider.id === id);
    if (existingIndex >= 0) nextConfig.providers[existingIndex] = nextProvider;
    else nextConfig.providers.push(nextProvider);

    try {
        await persistConfig(nextConfig);
        closeProviderEditor();
        renderProviderManager();
        showNotification(`Provider "${name}" saved successfully.`);
    } catch (error) {
        showNotification(`Unable to save provider: ${error.message}`);
    }
}

async function toggleProvider(provider) {
    const nextConfig = cloneObject(appConfig);
    const target = nextConfig.providers.find(item => item.id === provider.id);
    if (!target) return;
    target.enabled = !target.enabled;
    try {
        await persistConfig(nextConfig);
    } catch (error) {
        showNotification(`Unable to update provider: ${error.message}`);
    }
}

async function duplicateProvider(provider) {
    if (providers.length >= MAX_PROVIDERS) {
        showNotification(`The application supports up to ${MAX_PROVIDERS} providers.`);
        return;
    }
    const duplicate = cloneObject(provider);
    duplicate.id = uniqueProviderId(`${provider.id}-copy`);
    duplicate.name = `${provider.name} (Copy)`;
    duplicate.enabled = false; // Keep the duplicate inactive until the user enables it.
    const nextConfig = cloneObject(appConfig);
    nextConfig.providers.push(duplicate);
    try {
        await persistConfig(nextConfig);
        showNotification(`A disabled copy of "${provider.name}" was created.`);
    } catch (error) {
        showNotification(`Unable to duplicate provider: ${error.message}`);
    }
}

async function deleteProvider(provider) {
    const confirmed = window.confirm(`Delete the provider "${provider.name}"? This cannot be undone.`);
    if (!confirmed) return;
    const nextConfig = cloneObject(appConfig);
    nextConfig.providers = nextConfig.providers.filter(item => item.id !== provider.id);
    try {
        await persistConfig(nextConfig);
    } catch (error) {
        showNotification(`Unable to delete provider: ${error.message}`);
    }
}

function testProvider(provider) {
    if (isHoleheIntegration(provider)) {
        const tab = window.open("/holehe-results.html?test=1", "_blank");
        if (tab) {
            try { tab.opener = null; } catch (error) { /* Tab may already be navigating. */ }
            showNotification("Holehe installation check opened in a separate OIW tab. No search was submitted.");
        } else {
            showNotification("The test tab was blocked by the browser. Allow pop-ups for this local application and try again.");
        }
        return;
    }

    const identifierType = provider.types.includes(ui.searchType.value)
        ? ui.searchType.value
        : provider.types[0];
    try {
        const isAutomatic = providerIsAutomatic(provider, identifierType);
        const url = buildProviderUrl(provider, identifierType, "oiw-test");
        const tab = window.open(url, "_blank");
        if (tab) {
            try { tab.opener = null; } catch (error) { /* Tab may already be navigating. */ }
            showNotification(isAutomatic
                ? `Test URL opened for ${provider.name} using the harmless placeholder "oiw-test".`
                : `${provider.name} website opened. Manual entry is still required.`);
        } else {
            showNotification("The test tab was blocked by the browser. Allow pop-ups for this local application and try again.");
        }
    } catch (error) {
        showNotification(`Provider test failed: ${error.message}`);
    }
}

// --------------------------------------------------
// EVENT WIRING
// --------------------------------------------------

ui.searchType.addEventListener("change", renderProviders);
ui.searchTerm.addEventListener("keydown", event => {
    if (event.key === "Enter") launchSearches();
});
ui.launchButton.addEventListener("click", launchSearches);
ui.selectAllButton.addEventListener("click", () => selectAllProviders(true));
ui.selectNoneButton.addEventListener("click", () => selectAllProviders(false));

ui.manageProvidersButton.addEventListener("click", openProviderManager);
ui.closeProviderManagerButton.addEventListener("click", closeProviderManager);
ui.providerSearch.addEventListener("input", renderProviderManager);
ui.categoryFilter.addEventListener("change", renderProviderManager);
ui.addProviderButton.addEventListener("click", () => openProviderEditor());
ui.closeEditorButton.addEventListener("click", closeProviderEditor);
ui.cancelProviderButton.addEventListener("click", closeProviderEditor);
ui.providerMode.addEventListener("change", updateEditorMode);
ui.providerForm.querySelectorAll('input[name="providerType"]').forEach(input => {
    input.addEventListener("change", refreshTemplateInputs);
});
ui.providerForm.addEventListener("submit", saveProviderFromForm);

// --------------------------------------------------
// INDEPENDENT WEBPAGE TEXT AND NLP ANALYSIS
// --------------------------------------------------

const webAnalysisUi = {
    form: document.getElementById("webAnalysisForm"),
    url: document.getElementById("webAnalysisUrl"),
    submit: document.getElementById("analyseWebpageButton"),
    dependencyStatus: document.getElementById("webAnalysisDependencyStatus"),
    runStatus: document.getElementById("webAnalysisRunStatus"),
    results: document.getElementById("webAnalysisResults"),
    source: document.getElementById("webAnalysisSource"),
    metrics: document.getElementById("webAnalysisMetrics"),
    themes: document.getElementById("webAnalysisThemes"),
    entities: document.getElementById("webAnalysisEntities"),
    keywords: document.getElementById("webAnalysisKeywords"),
    emails: document.getElementById("webAnalysisEmails"),
    phones: document.getElementById("webAnalysisPhones"),
    extractedText: document.getElementById("webAnalysisExtractedText"),
    truncationNote: document.getElementById("webAnalysisTruncationNote"),
    download: document.getElementById("downloadWebAnalysisReport")
};

let lastWebAnalysis = null;
let webAnalysisBusy = false;

function setWebAnalysisStatus(message, state = "") {
    webAnalysisUi.runStatus.textContent = message;
    webAnalysisUi.runStatus.className = `analysis-status ${state}`.trim();
}

async function checkWebAnalysisDependencies() {
    try {
        const response = await fetch("/api/web-analysis/status", {
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });
        const status = await response.json();
        if (!response.ok) throw new Error(status.error || `HTTP ${response.status}`);

        if (!status.installed) {
            webAnalysisUi.dependencyStatus.textContent =
                "Webpage NLP is not installed. Run: python -m pip install -r requirements-web-analysis.txt";
            webAnalysisUi.dependencyStatus.className = "analysis-status analysis-warning";
        } else if (!status.modelInstalled) {
            webAnalysisUi.dependencyStatus.textContent =
                `spaCy ${status.spacyVersion} is installed, but the English model is missing. Run: python -m spacy download en_core_web_sm`;
            webAnalysisUi.dependencyStatus.className = "analysis-status analysis-warning";
        } else {
            webAnalysisUi.dependencyStatus.textContent =
                `Ready · spaCy ${status.spacyVersion} · en_core_web_sm`;
            webAnalysisUi.dependencyStatus.className = "analysis-status analysis-ready";
        }
    } catch (error) {
        webAnalysisUi.dependencyStatus.textContent =
            `Unable to check webpage NLP dependencies: ${error.message}`;
        webAnalysisUi.dependencyStatus.className = "analysis-status analysis-warning";
    }
}

function appendAnalysisEmpty(container, message) {
    const empty = document.createElement("p");
    empty.className = "analysis-empty";
    empty.textContent = message;
    container.appendChild(empty);
}

function renderAnalysisMetrics(data) {
    const items = [
        [data.totalWords, "Words"],
        [data.totalCharacters.toLocaleString(), "Characters"],
        [data.uniqueEntities, "Named entities"],
        [data.keywords.length, "Frequent keywords"],
        [data.themes.length, "Recurring themes"],
        [(data.emails || []).length, "Email addresses"],
        [(data.phones || []).length, "Telephone numbers"]
    ];
    webAnalysisUi.metrics.replaceChildren();
    items.forEach(([value, label]) => {
        const card = document.createElement("article");
        card.className = "analysis-metric";
        const strong = document.createElement("strong");
        strong.textContent = String(value);
        const caption = document.createElement("span");
        caption.textContent = label;
        card.append(strong, caption);
        webAnalysisUi.metrics.appendChild(card);
    });
}

function renderAnalysisThemes(items) {
    webAnalysisUi.themes.replaceChildren();
    if (!items.length) {
        appendAnalysisEmpty(webAnalysisUi.themes,
            "No repeated multi-word noun phrases were identified. Review the frequent keywords below.");
        return;
    }
    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "analysis-item-row";
        const label = document.createElement("span");
        label.className = "analysis-item-label";
        label.textContent = item.theme;
        const count = document.createElement("span");
        count.className = "analysis-item-count";
        count.textContent = `${item.count} mentions`;
        row.append(label, count);
        webAnalysisUi.themes.appendChild(row);
    });
}

function renderAnalysisEntities(items) {
    webAnalysisUi.entities.replaceChildren();
    if (!items.length) {
        appendAnalysisEmpty(webAnalysisUi.entities, "No named entities were identified.");
        return;
    }
    items.forEach(item => {
        const card = document.createElement("article");
        card.className = "analysis-entity-card";
        const top = document.createElement("div");
        top.className = "analysis-entity-top";
        const name = document.createElement("strong");
        name.textContent = item.entity;
        const count = document.createElement("span");
        count.className = "analysis-item-count";
        count.textContent = `${item.count} mentions`;
        top.append(name, count);
        const type = document.createElement("p");
        type.className = "analysis-entity-type";
        type.textContent = `${item.type} · ${item.description}`;
        card.append(top, type);

        const variations = Object.entries(item.variations || {});
        if (variations.length > 1 || (variations.length === 1 && variations[0][0] !== item.entity)) {
            const variationLine = document.createElement("small");
            variationLine.textContent = "Original forms: " + variations
                .map(([value, countValue]) => `${value} (${countValue})`)
                .join(", ");
            card.appendChild(variationLine);
        }
        webAnalysisUi.entities.appendChild(card);
    });
}

function renderAnalysisKeywords(items) {
    webAnalysisUi.keywords.replaceChildren();
    if (!items.length) {
        appendAnalysisEmpty(webAnalysisUi.keywords, "No frequent keywords were identified.");
        return;
    }
    items.forEach(item => {
        const pill = document.createElement("span");
        pill.className = "analysis-keyword";
        pill.textContent = `${item.keyword} · ${item.count}`;
        webAnalysisUi.keywords.appendChild(pill);
    });
}

function renderAnalysisEmails(items) {
    webAnalysisUi.emails.replaceChildren();
    if (!items.length) {
        appendAnalysisEmpty(webAnalysisUi.emails, "No email addresses were identified.");
        return;
    }
    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "analysis-item-row";
        const address = document.createElement("span");
        address.className = "analysis-item-label";
        address.textContent = typeof item === "string" ? item : (item.email || item.address || "");
        row.appendChild(address);
        if (typeof item === "object" && item.source) {
            const source = document.createElement("span");
            source.className = "analysis-item-count";
            source.textContent = item.source;
            row.appendChild(source);
        }
        webAnalysisUi.emails.appendChild(row);
    });
}

function renderAnalysisPhones(items) {
    webAnalysisUi.phones.replaceChildren();
    if (!items.length) {
        appendAnalysisEmpty(webAnalysisUi.phones, "No telephone numbers were identified.");
        return;
    }
    items.forEach(item => {
        const card = document.createElement("article");
        card.className = "analysis-entity-card";
        const number = typeof item === "string" ? item : (item.original || item.international || item.national || item.e164 || "");
        const heading = document.createElement("strong");
        heading.textContent = number;
        card.appendChild(heading);
        if (typeof item === "object") {
            const details = [
                item.international && `International: ${item.international}`,
                item.national && `National: ${item.national}`,
                item.e164 && `E.164: ${item.e164}`,
                item.region && `Region: ${item.region}`
            ].filter(Boolean);
            if (details.length) {
                const detail = document.createElement("p");
                detail.className = "analysis-entity-type";
                detail.textContent = details.join(" · ");
                card.appendChild(detail);
            }
        }
        webAnalysisUi.phones.appendChild(card);
    });
}

function renderWebAnalysis(data) {
    lastWebAnalysis = data;
    webAnalysisUi.source.textContent = data.finalUrl && data.finalUrl !== data.sourceUrl
        ? `Requested: ${data.sourceUrl} · Analysed: ${data.finalUrl}`
        : `Source: ${data.sourceUrl}`;
    renderAnalysisMetrics(data);
    renderAnalysisThemes(data.themes || []);
    renderAnalysisEntities(data.entities || []);
    renderAnalysisKeywords(data.keywords || []);
    renderAnalysisEmails(data.emails || []);
    renderAnalysisPhones(data.phones || []);
    webAnalysisUi.extractedText.textContent = data.extractedText || "";
    webAnalysisUi.truncationNote.hidden = !data.truncated;
    webAnalysisUi.results.hidden = false;
}

async function analyseWebpage(event) {
    event.preventDefault();
    if (webAnalysisBusy) return;

    const url = webAnalysisUi.url.value;
    if (!url) {
        setWebAnalysisStatus("Enter a webpage URL first.", "analysis-warning");
        webAnalysisUi.url.focus();
        return;
    }
    if (url !== url.trim()) {
        setWebAnalysisStatus("The URL has leading or trailing whitespace. Correct it manually; OIW will not silently change it.", "analysis-warning");
        webAnalysisUi.url.focus();
        return;
    }
    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
            throw new Error("Enter a public HTTP or HTTPS URL without embedded credentials.");
        }
    } catch (error) {
        setWebAnalysisStatus(error.message || "Enter a valid webpage URL.", "analysis-warning");
        webAnalysisUi.url.focus();
        return;
    }

    webAnalysisBusy = true;
    webAnalysisUi.submit.disabled = true;
    webAnalysisUi.submit.textContent = "Analysing…";
    webAnalysisUi.results.hidden = true;
    lastWebAnalysis = null;
    setWebAnalysisStatus("Downloading the webpage, extracting text and running spaCy analysis. This may take a little while on the first run…", "analysis-running");

    try {
        const response = await fetch("/api/web-analysis", {
            method: "POST",
            cache: "no-store",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });
        let payload = {};
        try { payload = await response.json(); } catch (error) { /* Use HTTP status below. */ }
        if (!response.ok) throw new Error(payload.error || `Server returned HTTP ${response.status}.`);

        renderWebAnalysis(payload);
        setWebAnalysisStatus(
            `Analysis complete · ${payload.totalWords.toLocaleString()} words · ${payload.uniqueEntities} named entities · ${payload.themes.length} recurring themes · ${(payload.emails || []).length} emails · ${(payload.phones || []).length} telephone numbers.`,
            "analysis-ready"
        );
    } catch (error) {
        setWebAnalysisStatus(`Analysis could not be completed: ${error.message}`, "analysis-warning");
    } finally {
        webAnalysisBusy = false;
        webAnalysisUi.submit.disabled = false;
        webAnalysisUi.submit.textContent = "Analyse Webpage";
    }
}

function downloadWebAnalysisReport() {
    if (!lastWebAnalysis) return;
    const data = lastWebAnalysis;
    const lines = [
        "WEBPAGE ENTITY ANALYSIS REPORT",
        "=".repeat(75),
        `Source URL: ${data.sourceUrl}`,
        `Final URL: ${data.finalUrl}`,
        `Date collected: ${data.collectedAt}`,
        `Total characters: ${data.totalCharacters}`,
        `Total words: ${data.totalWords}`,
        `Unique entities: ${data.uniqueEntities}`,
        `Unique keywords: ${data.uniqueKeywords}`,
        "",
        "RECURRING THEMES / NOUN PHRASES",
        "=".repeat(75)
    ];
    if ((data.themes || []).length) {
        data.themes.forEach(item => lines.push(`${item.theme}\t${item.count} mentions`));
    } else {
        lines.push("No repeated multi-word noun phrases identified.");
    }
    lines.push("", "ENTITY FREQUENCY ANALYSIS", "=".repeat(75));
    let previousType = null;
    (data.entities || []).forEach(item => {
        if (item.type !== previousType) {
            lines.push("", `[${item.type}]`, "-".repeat(55));
            previousType = item.type;
        }
        lines.push(`Entity: ${item.entity}`, `Total mentions: ${item.count}`, `Description: ${item.description}`, "Original variations:");
        Object.entries(item.variations || {}).forEach(([variation, count]) => lines.push(`  - ${variation}: ${count}`));
        lines.push("-".repeat(45));
    });
    lines.push("", "KEYWORD FREQUENCY ANALYSIS", "=".repeat(75));
    (data.keywords || []).forEach(item => lines.push(`${item.keyword.padEnd(35)} ${String(item.count).padStart(10)}`));

    lines.push("", "EMAIL ADDRESSES", "=".repeat(75));
    if ((data.emails || []).length) {
        data.emails.forEach(item => {
            lines.push(typeof item === "string" ? item : (item.email || item.address || ""));
        });
    } else {
        lines.push("No email addresses identified.");
    }

    lines.push("", "TELEPHONE NUMBERS", "=".repeat(75));
    if ((data.phones || []).length) {
        data.phones.forEach(item => {
            if (typeof item === "string") {
                lines.push(item);
            } else {
                lines.push(
                    `Original: ${item.original || ""}`,
                    `International: ${item.international || ""}`,
                    `National: ${item.national || ""}`,
                    `E.164: ${item.e164 || ""}`,
                    `Region: ${item.region || ""}`,
                    ""
                );
            }
        });
    } else {
        lines.push("No telephone numbers identified.");
    }

    lines.push("", "FULL EXTRACTED WEBPAGE TEXT", "=".repeat(75), "", data.extractedText || "");

    const blob = new Blob([lines.join("\r\n")], { type: "text/plain;charset=utf-8" });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const host = (() => {
        try { return new URL(data.finalUrl).hostname.replace(/[^a-z0-9.-]/gi, "_"); }
        catch (error) { return "webpage"; }
    })();
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    link.href = objectUrl;
    link.download = `webpage_analysis_${host}_${stamp}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
}

webAnalysisUi.form.addEventListener("submit", analyseWebpage);
webAnalysisUi.download.addEventListener("click", downloadWebAnalysisReport);
checkWebAnalysisDependencies();

console.info("OSINT Investigation Workstation v0.3.4 initialising...");
loadProviders();