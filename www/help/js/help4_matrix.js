/**
 * Matrix rain canvas animation
 * Original implementation — no third-party code.
 *
 * Draws falling character columns on a canvas element with id="c".
 * Throttled to ~12fps to keep CPU usage low on all devices.
 * Exposes window.stopMatrix() so the terminal script can halt it before redirect.
 * Adapts to window resize. Column count is capped to avoid overload on wide displays.
 */
(function () {
    "use strict";

    var FONT_SIZE   = 14;
    var COLOR_TEXT  = "#00d4ff";
    var COLOR_TRAIL = "rgba(13,13,26,0.07)";
    var CHARS       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>[]{}+-=/\\|";
    var RESET_PROB  = 0.975;   // probability a column resets after reaching bottom
    var INTERVAL_MS = 80;      // ~12fps drop speed — halves CPU vs. 25fps, still smooth
    var MAX_COLS    = 80;      // cap columns on wide/4K displays

    var canvas  = document.getElementById("c");
    var ctx     = canvas.getContext("2d");
    var drops   = [];
    var cols    = 0;
    var lastTime = 0;
    var rafId   = null;
    var stopped = false;

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
        cols  = Math.min(Math.floor(canvas.width / FONT_SIZE), MAX_COLS);
        drops = [];
        for (var i = 0; i < cols; i++) {
            drops[i] = Math.floor(Math.random() * -(canvas.height / FONT_SIZE));
        }
    }

    function randomChar() {
        return CHARS[Math.floor(Math.random() * CHARS.length)];
    }

    function draw() {
        ctx.fillStyle = COLOR_TRAIL;
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = COLOR_TEXT;
        ctx.font      = FONT_SIZE + "px monospace";

        for (var i = 0; i < cols; i++) {
            var y = drops[i] * FONT_SIZE;
            if (y > 0 && y < canvas.height) {
                ctx.fillText(randomChar(), i * FONT_SIZE, y);
            }
            drops[i]++;
            if (y > canvas.height && Math.random() > RESET_PROB) {
                drops[i] = 0;
            }
        }
    }

    function loop(timestamp) {
        if (stopped) return;
        if (timestamp - lastTime >= INTERVAL_MS) {
            draw();
            lastTime = timestamp;
        }
        rafId = requestAnimationFrame(loop);
    }

    // Called by help4_terminal.js before navigating away.
    window.stopMatrix = function () {
        stopped = true;
        if (rafId !== null) {
            cancelAnimationFrame(rafId);
            rafId = null;
        }
    };

    window.addEventListener("resize", resize);
    resize();
    rafId = requestAnimationFrame(loop);
}());
