const axios = require("axios");

async function fetchPing() {
    try {
        const response = await axios.get("https://backend68.vercel.app/ping");
        console.log("Response data:", response.data);
    } catch (err) {
        console.error("Error fetching API:", err.message);
    }
}

fetchPing();
