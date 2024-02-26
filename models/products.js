// importing database from config
import {pool} from '../config/config.js';

// retrieve all products
const getProducts = async () => {
    const [result] = await pool.query
    (`SELECT * 
    FROM products`);
    return result
};
// retrieve individual products
const getProduct = async (prodID) => {
    const [result] = await pool.query (`
    SELECT * 
    FROM products
    WHERE prodID = ?
    `,[prodID]);
    return result
};
// adding a product
const addProduct = async (prodName, quantity, amount, category, prodUrl) => {
    const [product] = await pool.query (`
    INSERT INTO products (prodName, quantity, amount, category, prodUrl) VALUES(?,?,?,?,?)`,
    [prodName, quantity, amount, category, prodUrl]);
    return getProduct(product.insertId);
};
// editing individual product
const editProduct = async (prodID, prodName, quantity, amount, category, prodUrl) => {
    const product = await pool.query (`
    UPDATE products
    SET prodName = ?, quantity = ?, amount = ? , category = ?, prodUrl = ?
    where prodID = ?
    `,[prodID, prodName, quantity,amount, category, prodUrl]);
    const editedProduct = await getProducts(prodID)
    return editedProduct
}; 
// deleting individual product
const deleteProduct = async (prodID) => {
    const [product] = await pool.query(`
    DELETE FROM products
    WHERE prodID = ?
    `,[prodID]);
    return getProducts(product)
}
// exporting functions by making it global
export {getProducts,getProduct,addProduct,editProduct,deleteProduct}