// FrameShift site scripts (harmless)
(function() {
    // Set a cookie to confirm JavaScript execution on the client.
    var secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = "_fs_js=1; path=/; max-age=86400; SameSite=Lax" + secure;
})();
