/**
 * Matrix rain canvas animation
 * Original implementation — no third-party code.
 *
 * Draws falling character columns on a canvas element with id="c".
 * Adapts to window resize.
 */
(function () {
    "use strict";

    var FONT_SIZE   = 14;
    var COLOR_TEXT  = "#00d4ff";
    var COLOR_TRAIL = "rgba(13,13,26,0.07)";
    var CHARS       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>[]{}+-=/\\|";
    var RESET_PROB  = 0.975;   // probability a column resets after reaching bottom
    var INTERVAL_MS = 40;

    var canvas = document.getElementById("c");
    var ctx    = canvas.getContext("2d");
    var drops  = [];
    var cols   = 0;

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
        cols  = Math.floor(canvas.width / FONT_SIZE);
        drops = [];
        for (var i = 0; i < cols; i++) {
            // stagger starting positions so columns don't all start at top
            drops[i] = Math.floor(Math.random() * -(canvas.height / FONT_SIZE));
        }
    }

    function randomChar() {
        return CHARS[Math.floor(Math.random() * CHARS.length)];
    }

    function draw() {
        // semi-transparent fill creates the fading trail effect
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

    window.addEventListener("resize", resize);
    resize();
    setInterval(draw, INTERVAL_MS);
}());
