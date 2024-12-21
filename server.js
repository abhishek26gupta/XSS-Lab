const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const PORT = 3000;

// List of allowed origins for CORS (main site)
const allowedReferers = ['http://localhost:3000'];  // Change this to your actual main site's origin

// Middleware to enable CORS for specific origins



// Middleware to parse JSON payloads from the AJAX request
app.use(bodyParser.json());
app.use(express.static('public'));

app.use((req, res, next) => {
    res.removeHeader('Access-Control-Allow-Origin');
    res.removeHeader('Vary')
    next();
});

// POST route to reflect input
app.post('/reflect', (req, res) => {
    let userInput = req.body.userInput;

    // Convert everything to lowercase first
    let originalInput = userInput.toLowerCase();

    // Define blacklist for tags and attributes
    const blacklist = ["<script", "src=", "img","javascript", "alert"];
    const blackevents = ["onerror", "onload", "onfocus", "autofocus"];
    const maliciousPatterns = [/.*<.*print.*>/, /.*<.*prompt.*>/, /.*<.*onbegin.*>/];  // Malicious script injections
    let response 

    // Check for blacklisted event handlers first
    if (blackevents.some(keyword => originalInput.includes(keyword))) {
        response = "Blocked: Event Handler not allowed";
        return res.send(response); // Block input if event handler is found
    }

    // Sanitize the input by removing blacklisted tags and attributes
    let isSanitized = false;  // Flag to track if sanitization happens

// Sanitize the input by removing blacklisted tags and attributes
    blacklist.forEach(keyword => {
        if (userInput.includes(keyword)) {
            isSanitized = true;  // Set flag if something is sanitized
            userInput = userInput.replace(new RegExp(keyword, 'g'), '');
        }
    });

    // Check for malicious payloads after sanitization
    if (!isSanitized && maliciousPatterns.some(pattern => pattern.test(userInput))) {
        // Malicious payload detected, provide the flag endpoint
        response = `You Searched For, ${userInput}. Ahh, trying XSS? You are close. If you can execute the XSS, fetch the flag from /get-fl4g.`;
        return res.send(response); // Return the flag endpoint
    }

    // Return the sanitized input (will be inserted into the <p> tag)
    response = `You Searched for, ${userInput}`;
    res.send(response);
});

// Endpoint to fetch the flag (protected by CORS check)
app.get('/get-fl4g', (req, res) => {
    // Check if the request comes from an allowed origin (main site)

    const referer = req.get('Referer');

    if (allowedReferers.some(allowedReferer => referer && referer.startsWith(allowedReferer))) {
        return res.send('THMxPU{Th3_Xss_Ch4mpi0n}');  // Flag message
    } else {
        return res.status(403).send('Access Denied');  // Deny if referer is not allowed
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
