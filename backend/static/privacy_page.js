(async () => {
  try {
    const cfg = await window.__loadPublicConfig();
    const el = document.getElementById('retentionDays');
    if (el && cfg && cfg.data_retention_days) el.textContent = String(cfg.data_retention_days);

    const email = (cfg && cfg.support_email) ? cfg.support_email : null;
    if (email) {
      document.querySelectorAll('[data-support-email]').forEach(a => {
        a.textContent = email;
        a.setAttribute('href', 'mailto:' + email);
      });
    }
  } catch (e) {
    // ignore
  }
})();
