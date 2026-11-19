"use strict";

// ==================================================
// OSINT INVESTIGATION WORKSTATION
// Version 0.2.2
// ==================================================


// --------------------------------------------------
// APPLICATION STATE
// --------------------------------------------------

window.providers = [];

const platformContainer = document.getElementById("platforms");
const searchType = document.getElementById("searchType");
const searchTerm = document.getElementById("searchTerm");
const launchButton = document.getElementById("launchButton");
const selectionCount = document.getElementById("selectionCount");


// --------------------------------------------------
// NOTIFICATION SYSTEM
// --------------------------------------------------

function showNotification(message) {

    alert(message);

}


// --------------------------------------------------
// LOAD PROVIDER CONFIGURATION
// --------------------------------------------------

window.loadProviders = async function () {

    try {

        console.log("OIW: Loading providers...");

        const response = await fetch(
            "/config/providers.json",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {

            throw new Error(
                `HTTP error ${response.status}`
            );

        }

        const config = await response.json();

        if (!Array.isArray(config.providers)) {

            throw new Error(
                "Invalid provider configuration."
            );

        }

        window.providers = config.providers.filter(
            provider => provider.enabled === true
        );

        console.log(
            "OIW: Providers loaded:",
            window.providers.length
        );

        renderProviders();

    } catch (error) {

        console.error(
            "OIW CONFIGURATION ERROR:",
            error
        );

        platformContainer.replaceChildren();

        const message = document.createElement("p");

        message.textContent =
            "Unable to load providers: " + error.message;

        message.style.color = "#ff7777";

        platformContainer.appendChild(message);

    }

};


// --------------------------------------------------
// GET COMPATIBLE PROVIDERS
// --------------------------------------------------

function getCompatibleProviders() {

    const type = searchType.value;

    return window.providers.filter(
        provider =>
            Array.isArray(provider.types) &&
            provider.types.includes(type)
    );

}


// --------------------------------------------------
// RENDER PROVIDER SELECTION
// --------------------------------------------------

function renderProviders() {

    const compatible = getCompatibleProviders();

    platformContainer.replaceChildren();

    compatible.forEach(provider => {

        const label = document.createElement("label");

        label.className = "platform";

        const checkbox = document.createElement("input");

        checkbox.type = "checkbox";
        checkbox.value = provider.id;
        checkbox.checked = true;

        checkbox.addEventListener(
            "change",
            updateCount
        );

        const details = document.createElement("div");

        const name = document.createElement("div");

        name.className = "platform-name";
        name.textContent = provider.name;

        const category = document.createElement("div");

        category.className = "platform-category";

        const automatic =
            !!provider.urlTemplates?.[searchType.value] ||
            (
                provider.mode === "query" &&
                !!provider.url
            );

        category.textContent =
            provider.category +
            (
                automatic
                    ? " · Automatic search"
                    : " · Manual search"
            );

        details.appendChild(name);
        details.appendChild(category);

        label.appendChild(checkbox);
        label.appendChild(details);

        platformContainer.appendChild(label);

    });

    updateCount();

}


// --------------------------------------------------
// GET SELECTED PROVIDERS
// --------------------------------------------------

function selectedProviders() {

    const checked = Array.from(

        platformContainer.querySelectorAll(
            'input[type="checkbox"]:checked'
        )

    ).map(input => input.value);

    return window.providers.filter(
        provider => checked.includes(provider.id)
    );

}


// --------------------------------------------------
// UPDATE PROVIDER COUNT
// --------------------------------------------------

function updateCount() {

    const count = selectedProviders().length;

    selectionCount.textContent =
        `${count} platform${count === 1 ? "" : "s"} selected`;

    launchButton.disabled = count === 0;

}


// --------------------------------------------------
// BUILD PROVIDER URL
// --------------------------------------------------

function buildURL(provider, term) {

    const identifierType = searchType.value;

    let template =
        provider.urlTemplates?.[identifierType];

    // Backward compatibility with original configuration.

    if (!template && provider.mode === "query") {

        template = provider.url;

    }

    // Automatic search.

    if (template) {

        if (
            typeof template !== "string" ||
            !template.includes("{query}")
        ) {

            throw new Error(
                `Invalid URL template for ${provider.name}`
            );

        }

        const url = template.replace(
            "{query}",
            encodeURIComponent(term)
        );

        const parsed = new URL(url);

        if (parsed.protocol !== "https:") {

            throw new Error(
                "Only HTTPS provider URLs are permitted."
            );

        }

        return url;

    }

    // Manual search.

    const manualUrl =
        provider.manualUrl ||
        (
            provider.mode === "manual"
                ? provider.url
                : null
        );

    if (manualUrl) {

        const parsed = new URL(manualUrl);

        if (parsed.protocol !== "https:") {

            throw new Error(
                "Only HTTPS provider URLs are permitted."
            );

        }

        return manualUrl;

    }

    throw new Error(
        `${provider.name}: no configured URL for ${identifierType}`
    );

}


// --------------------------------------------------
// COPY SEARCH IDENTIFIER
// --------------------------------------------------

async function copyIdentifier(term) {

    try {

        if (
            navigator.clipboard &&
            navigator.clipboard.writeText
        ) {

            await navigator.clipboard.writeText(term);

            return true;

        }

        return false;

    } catch (error) {

        console.error(
            "OIW clipboard error:",
            error
        );

        return false;

    }

}


// --------------------------------------------------
// LAUNCH SEARCHES
// --------------------------------------------------

async function launchSearches() {

    const term = searchTerm.value.trim();

    if (!term) {

        showNotification(
            "Please enter a search identifier."
        );

        return;

    }

    const selected = selectedProviders();

    if (!selected.length) {

        showNotification(
            "Please select at least one platform."
        );

        return;

    }

    let opened = 0;
    let blocked = 0;

    const errors = [];

    const epieosSelected = selected.some(
        provider => provider.id === "epieos"
    );

    // Open provider tabs synchronously within the click handler.
    // This helps Chrome recognise them as user-initiated tabs.

    for (const provider of selected) {

        try {

            const url = buildURL(provider, term);

            const tab = window.open(
                url,
                "_blank"
            );

            if (tab) {

                try {
                    tab.opener = null;
                } catch (error) {
                    // Tab may already have navigated.
                }

                opened++;

            } else {

                blocked++;

            }

        } catch (error) {

            errors.push(
                `${provider.name}: ${error.message}`
            );

            console.error(
                "OIW launch error:",
                provider.id,
                error
            );

        }

    }

    // Update launch information.

    selectionCount.textContent =
        `${opened} tabs opened · ${blocked} blocked`;

    // Epieos clipboard handling.

    if (epieosSelected) {

        const copied = await copyIdentifier(term);

        if (copied) {

            showNotification(

                "Epieos opened!\n\n" +
                "Your search identifier has been copied " +
                "to the clipboard.\n\n" +
                "Switch to Epieos, EmailRep or other manual-search provider and paste it into the search field."

            );

        } else {

            showNotification(

                "Epieos opened, but clipboard access failed.\n\n" +
                "Please copy this identifier manually:\n\n" +
                term

            );

        }

    }

    // Report other errors.

    if (errors.length || blocked > 0) {

        let summary =
            "Launch summary:\n\n" +
            `${opened} tabs opened\n` +
            `${blocked} blocked\n`;

        if (errors.length) {

            summary +=
                "\nProvider errors:\n" +
                errors.join("\n");

        }

        showNotification(summary);

    }

}


// --------------------------------------------------
// SELECT ALL PROVIDERS
// --------------------------------------------------

const selectAllButton =
    document.getElementById("selectAll");

if (selectAllButton) {

    selectAllButton.addEventListener(
        "click",
        () => {

            platformContainer
                .querySelectorAll(
                    'input[type="checkbox"]'
                )
                .forEach(input => {
                    input.checked = true;
                });

            updateCount();

        }
    );

}


// --------------------------------------------------
// DESELECT ALL PROVIDERS
// --------------------------------------------------

const selectNoneButton =
    document.getElementById("selectNone");

if (selectNoneButton) {

    selectNoneButton.addEventListener(
        "click",
        () => {

            platformContainer
                .querySelectorAll(
                    'input[type="checkbox"]'
                )
                .forEach(input => {
                    input.checked = false;
                });

            updateCount();

        }
    );

}


// --------------------------------------------------
// IDENTIFIER TYPE CHANGE
// --------------------------------------------------

searchType.addEventListener(
    "change",
    renderProviders
);


// --------------------------------------------------
// LAUNCH BUTTON
// --------------------------------------------------

launchButton.addEventListener(
    "click",
    launchSearches
);


// --------------------------------------------------
// ENTER KEY SEARCH
// --------------------------------------------------

searchTerm.addEventListener(
    "keydown",
    event => {

        if (event.key === "Enter") {

            launchSearches();

        }

    }
);


// --------------------------------------------------
// INITIALISE APPLICATION
// --------------------------------------------------

console.log(
    "OSINT Investigation Workstation initialising..."
);

window.loadProviders();