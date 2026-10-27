// Language switch between the two book builds, which live side by side
// under target/book/en and target/book/zh. Chapter file names mirror each
// other one to one, so the same path exists in the other language.
(function () {
    "use strict";

    var match = window.location.pathname.match(/\/(en|zh)\//);
    if (!match) {
        return;
    }
    var current = match[1];
    var other = current === "en" ? "zh" : "en";
    var target = window.location.pathname.replace(
        "/" + current + "/",
        "/" + other + "/"
    );

    function label() {
        return other === "zh" ? "中文" : "English";
    }

    function makeButton() {
        var a = document.createElement("a");
        a.href = target;
        a.title = "Switch language";
        a.setAttribute("aria-label", "Switch language");
        a.classList.add("lang-switch");
        var span = document.createElement("span");
        span.textContent = label();
        a.appendChild(span);
        return a;
    }

    function install() {
        var buttons = document.querySelector(".right-buttons");
        if (buttons) {
            buttons.insertBefore(makeButton(), buttons.firstChild);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", install);
    } else {
        install();
    }
})();
