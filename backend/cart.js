const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
require("dotenv").config(); // Load environment variables from .env

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Database Connection
const connection = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "your_database_name"
});

connection.connect((err) => {
    if (err) {
        console.error("Error connecting to the database:", err);
        process.exit(1);
    }
    console.log("Connected to the MySQL database.");
});

// Serve cart HTML
app.get("cart.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "cart.html"));
});

// Add to Cart Route
// Root Route
app.get("/cart", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "cart.html")); // Serve the cart.html file


    // Insert query to match your table structure
    const query = "INSERT INTO cart (product_name, product_quantity) VALUES (?, ?)";

    connection.query(query, [product_name, product_quantity], (err, result) => {
        if (err) {
            console.error("Error adding to cart:", err);
            return res.status(500).json({ message: "Failed to add item to cart" });
        }
        res.json({ message: "Item added to cart successfully!" });
    });
});

// Fetch Cart Items Route
app.get("/getcartItems", (req, res) => {
    const query = "SELECT * FROM cart";

    connection.query(query, (err, rows) => {
        if (err) {
            console.error("Error fetching cart items:", err);
            return res.status(500).json({ message: "Failed to fetch cart items" });
        }
        res.json(rows);
    });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
