/* Shared theme handling for index.html / logener.html / api.html.
 *
 * Split in two deliberately:
 *   - applyStoredTheme() runs inline in <head>, right after the
 *     <link id="theme-stylesheet"> tag, so the correct stylesheet is
 *     requested before first paint (no dark->light flash on load).
 *   - wireThemeSwitcher() runs once the switcher buttons exist and just
 *     hooks up clicks; it's safe to call even on pages that don't render
 *     the switcher markup.
 * Previously this logic was copy-pasted inline only in index.html, so
 * /logener and /api always showed the dark theme regardless of what the
 * user picked.
 */
"use strict";

const NEKOWATCH_THEME_MAP = {
  nekowatch: "/static/css/nekowatch.css",
  lemongrass: "/static/css/lemongrass_nekowatch.css",
  sunset: "/static/css/alt_nekowatch.css",
};

function nekowatchStoredTheme() {
  try {
    return localStorage.getItem("nekowatch-theme") || "nekowatch";
  } catch (_) {
    return "nekowatch";
  }
}

function nekowatchApplyTheme(name) {
  const theme = NEKOWATCH_THEME_MAP[name] ? name : "nekowatch";
  const link = document.getElementById("theme-stylesheet");
  if (link) link.href = NEKOWATCH_THEME_MAP[theme];
  document.documentElement.dataset.theme = theme;
  document.querySelectorAll(".theme-switcher button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.theme === theme);
  });
  document.dispatchEvent(new CustomEvent("nekowatch-theme-changed", { detail: { theme } }));
  return theme;
}

/* Call this first, synchronously, in <head>. */
function nekowatchApplyStoredTheme() {
  nekowatchApplyTheme(nekowatchStoredTheme());
}

/* Call this after the DOM (including the switcher markup) is parsed. */
function nekowatchWireThemeSwitcher() {
  const switcher = document.getElementById("themeSwitcher");
  if (!switcher) return;
  // The buttons don't exist yet when nekowatchApplyStoredTheme() runs in
  // <head>, so the "active" class never landed on them — sync it now.
  const current = document.documentElement.dataset.theme || "nekowatch";
  switcher.querySelectorAll("button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.theme === current);
  });
  switcher.addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") return;
    const theme = nekowatchApplyTheme(e.target.dataset.theme);
    try {
      localStorage.setItem("nekowatch-theme", theme);
    } catch (_) {
      /* ignore — theme still applies for this page view */
    }
  });
}

nekowatchApplyStoredTheme();
