// Light/dark override. Loaded in <head> so a saved choice applies before first paint;
// with no saved choice the page follows the system setting.
(function () {
  const KEY = "nids-theme";
  const root = document.documentElement;
  let theme = null;
  try {
    const saved = localStorage.getItem(KEY);
    theme = saved === "light" || saved === "dark" ? saved : null;
  } catch {
    // Storage is a convenience only.
  }

  function apply() {
    if (theme) root.setAttribute("data-theme", theme);
    else root.removeAttribute("data-theme");
    try {
      if (theme) localStorage.setItem(KEY, theme);
      else localStorage.removeItem(KEY);
    } catch {
      // Ignore unavailable storage.
    }
    document.querySelectorAll("[data-theme-btn]").forEach((button) => {
      button.setAttribute("aria-checked", String(button.dataset.themeBtn === theme));
    });
  }

  apply();
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-theme-btn]").forEach((button) => {
      button.addEventListener("click", () => {
        theme = theme === button.dataset.themeBtn ? null : button.dataset.themeBtn;
        apply();
      });
    });
    apply();
  });
})();
