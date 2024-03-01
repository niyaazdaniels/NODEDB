// Importing product-related functions from models.js
import { getProducts, getProduct, addProduct, editProduct, deleteProduct } from '../models/products.js';

export default {
    // Function to retrieve multiple products from the database
    getManyProducts: async (req, res) => {
        try {
            // Retrieve products from the database
            const products = await getProducts();
            // Send retrieved products as response
            res.send(products);
        } catch (error) {
            // Handle errors if any
            console.error("Error fetching products:", error);
            res.status(500).json({ error: "Error fetching products" });
        }
    },
    // Function to add a single product to the database
    addOneProduct: async (req, res) => {
        try {
            // Extract product data from the request body
            const { prodName, quantity, amount, Category, prodUrl } = req.body;
            // Add the product to the database
            const post = await addProduct(prodName, quantity, amount, Category, prodUrl);
            // Send updated list of products as response
            res.send(await getProducts());
        } catch (error) {
            // Handle errors if any
            console.error("Error adding product:", error);
            res.status(500).send({ error: "An error occurred while adding the product" });
        }
    },
    // Function to retrieve a single product from the database
    getOneProduct: async (req, res) => {
        try {
            // Extract product ID from request parameters
            const productId = +req.params.prodID;
            // Retrieve the product from the database
            const product = await getProduct(productId);
            // Check if the product exists
            if (product) {
                res.send(product);
            } else {
                // If product not found, send 404 error
                res.status(404).send({ error: "Product not found" });
            }
        } catch (error) {
            // Handle internal server error
            res.status(500).send({ error: "Internal Server Error" });
        }
    },
    // Function to edit a product in the database
    editOneProduct: async (req, res) => {
        try {
            // Retrieve existing product from the database
            const [product] = await getProduct(+req.params.prodID);
            // Extract updated product data from request body
            let { prodName, quantity, amount, Category, prodUrl } = req.body;
            // Set updated values or keep existing values if not provided
            prodName = prodName || product.prodName;
            quantity = quantity || product.quantity;
            amount = amount || product.amount;
            Category = Category || product.Category;
            prodUrl = prodUrl || product.prodUrl;
            // Update the product in the database
            await editProduct(prodName, quantity, amount, Category, prodUrl, +req.params.prodID);
            // Send updated list of products as response
            res.json(await getProducts());
        } catch (error) {
            // Handle errors if any
            res.status(500).json({ error: 'An error occurred while editing the product.' });
        }
    },
    // Function to delete a product from the database
    deleteOneProduct: async (req, res) => {
        try {
            // Extract product ID from request parameters
            const productId = +req.params.prodID;
            // Delete the product from the database
            const deletedProduct = await deleteProduct(productId);
            // Check if product was successfully deleted
            if (deletedProduct) {
                // Send success message if product was deleted
                res.send({ message: "Product deleted successfully" });
            } else {
                // If product not found, send 404 error
                res.status(404).send({ error: "Product not found" });
            }
        } catch (error) {
            // Handle internal server error
            res.status(500).send({ error: "Internal Server Error" });
        }
    }
};
