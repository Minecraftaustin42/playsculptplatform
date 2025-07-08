// app.js

const express = require('express');
const app = express();
// Use process.env.PORT for deployment, fallback to 3000 for local development
const port = process.env.PORT || 3000;

// Define a route for the root URL (/)
app.get('/', (req, res) => {
  res.send('Hello World from Express!');
});

// Start the server
app.listen(port, () => {
  console.log(`Express app listening at http://localhost:${port}`);
});