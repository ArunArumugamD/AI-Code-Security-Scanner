// tests/samples/vulnerable.js
function unsafeEval(userInput) {
    // Vulnerability: Code injection
    return eval(userInput);
}

function unsafeInnerHTML(data) {
    // Vulnerability: XSS
    document.getElementById('output').innerHTML = data;
}

function unsafeTimeout(code) {
    // Vulnerability: Code injection
    setTimeout(code, 1000);
}

const complexFunction = (a, b, c) => {
    // High complexity
    if (a) {
        if (b) {
            if (c) {
                return a && b && c;
            } else {
                return a && b;
            }
        } else {
            if (c) {
                return a && c;
            }
        }
    }
    return false;
};
