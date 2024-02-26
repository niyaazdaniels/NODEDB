// importing products from models.js
import {getProducts,getProduct,addProduct,editProduct,deleteProduct} from '../models/products.js'

export default{
    // getting all products from the database
    getManyProducts: async (req, res) => {
        try {
            const products = await getProducts();
            res.send(products);
        } catch (error) {
            console.error("Error fetching products:", error);
            res.status(500).json({ error: "Error fetching products" });
        }
    },    
    // adding an individual product to database
    addOneProduct: async (req, res) => {
        try {
            // Extracting data from request body
            const { prodName, quantity, amount, Category, prodUrl } = req.body;
            // Adding product to the database
            const post = await addProduct(prodName, quantity, amount, Category, prodUrl);
            // Sending updated list of products as response
            res.send(await getProducts());
        } catch (error) {
            // Handling errors
            console.error("Error adding product:", error);
            res.status(500).send({ error: "An error occurred while adding the product" });
        }
    },    
    // getting one product from the database
    getOneProduct: async (req, res) => {
        try {
            const productId = +req.params.prodID;
            const product = await getProduct(productId);
            
            if (product) {
                res.send(product);
            } else {
                res.status(404).send({ error: "Product not found" });
            }
        } catch (error) {
            res.status(500).send({ error: "Internal Server Error" });
        }
    },    
    // editing products in the database
    editOneProduct: async (req, res) => {
        try {
            const [product] = await getProduct(+req.params.prodID);
            let { prodName, quantity, amount, Category, prodUrl } = req.body;
            prodName = prodName || product.prodName;
            quantity = quantity || product.quantity;
            amount = amount || product.amount;
            Category = Category || product.Category;
            prodUrl = prodUrl || product.prodUrl;
            await editProduct(prodName, quantity, amount, Category, prodUrl, +req.params.prodID);
            res.json(await getProducts());
        } catch (error) {
            res.status(500).json({ error: 'An error occurred while editing the product.' });
        }
    },    
    // deleting a product in the database
    deleteOneProduct: async (req, res) => {
        try {
            const productId = +req.params.prodID;
            const deletedProduct = await deleteProduct(productId);
    
            if (deletedProduct) {
                res.send({ message: "Product deleted successfully" });
            } else {
                res.status(404).send({ error: "Product not found" });
            }
        } catch (error) {
            res.status(500).send({ error: "Internal Server Error" });
        }
    }
    
} 