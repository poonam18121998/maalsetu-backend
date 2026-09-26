const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const upload = require("./upload");
const db = require("./db");

const app = express();

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));
const PORT = 5000;

const JWT_SECRET = "maalsetu_secret_key_change_later";


// =====================================================
// AUTHENTICATION MIDDLEWARE
// =====================================================

function verifyToken(req, res, next) {

    const authHeader =
        req.headers.authorization;

    if (!authHeader) {

        return res.status(401).json({
            message: "Authentication required"
        });

    }

    const token =
        authHeader.split(" ")[1];

    if (!token) {

        return res.status(401).json({
            message: "Invalid token"
        });

    }

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            message: "Invalid or expired token"
        });

    }
}


// =====================================================
// ROLE MIDDLEWARE
// =====================================================

function requireRole(role) {

    return function(req, res, next) {

        if (
            !req.user ||
            req.user.role !== role
        ) {

            return res.status(403).json({
                message: "Access denied"
            });

        }

        next();

    };

}


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

    res.send("MaalSetu server is running");

});


// =====================================================
// REGISTER
// =====================================================

app.post("/api/register", async (req, res) => {

    try {

        const {
            name,
            mobile,
            email,
            password,
            role
        } = req.body;


        if (
            !name ||
            !mobile ||
            !password
        ) {

            return res.status(400).json({
                message:
                    "Name, mobile and password are required"
            });

        }


        // Public registration can create
        // only customer or seller

        let userRole = role;

        if (
            userRole !== "seller" &&
            userRole !== "customer"
        ) {

            userRole = "customer";

        }


        const [existingUsers] =
            await db.query(
                "SELECT id FROM users WHERE mobile = ?",
                [mobile]
            );


        if (existingUsers.length > 0) {

            return res.status(409).json({
                message:
                    "Mobile number already registered"
            });

        }


        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );


        const [result] =
            await db.query(
                `
                INSERT INTO users
                (
                    name,
                    mobile,
                    email,
                    password,
                    role
                )
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    name,
                    mobile,
                    email || null,
                    hashedPassword,
                    userRole
                ]
            );


        res.status(201).json({

            message:
                "Registration successful",

            userId:
                result.insertId

        });

    } catch (error) {

        console.error(
            "Register Error:",
            error
        );

        res.status(500).json({
            message:
                "Registration failed"
        });

    }

});


// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {

    try {

        const {
            mobile,
            password
        } = req.body;


        if (
            !mobile ||
            !password
        ) {

            return res.status(400).json({
                message:
                    "Mobile and password are required"
            });

        }


        const [users] =
            await db.query(
                `
                SELECT *
                FROM users
                WHERE mobile = ?
                `,
                [mobile]
            );


        if (users.length === 0) {

            return res.status(401).json({
                message:
                    "Invalid mobile or password"
            });

        }


        const user =
            users[0];


        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );


        if (!passwordMatch) {

            return res.status(401).json({
                message:
                    "Invalid mobile or password"
            });

        }


        const token =
            jwt.sign(
                {
                    id: user.id,
                    role: user.role
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );


        delete user.password;


        res.json({

            message:
                "Login successful",

            token: token,

            user: user

        });

    } catch (error) {

        console.error(
            "Login Error:",
            error
        );

        res.status(500).json({
            message:
                "Login failed"
        });

    }

});


// =====================================================
// CATEGORIES - PUBLIC GET
// =====================================================

app.get("/api/categories", async (req, res) => {

    try {

        const [rows] =
            await db.query(
                `
                SELECT *
                FROM categories
                ORDER BY name
                `
            );

        res.json(rows);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Unable to fetch categories"
        });

    }

});


// =====================================================
// ADMIN - ADD CATEGORY
// =====================================================

app.post(
    "/api/categories",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const {
                name,
                description
            } = req.body;


            if (!name) {

                return res.status(400).json({
                    message:
                        "Category name is required"
                });

            }


            const [result] =
                await db.query(
                    `
                    INSERT INTO categories
                    (
                        name,
                        description
                    )
                    VALUES (?, ?)
                    `,
                    [
                        name,
                        description || null
                    ]
                );


            res.status(201).json({

                message:
                    "Category created",

                id:
                    result.insertId

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to create category"
            });

        }

    }
);


// =====================================================
// ADMIN - UPDATE CATEGORY
// =====================================================

app.put(
    "/api/categories/:id",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const {
                name,
                description
            } = req.body;


            const [result] =
                await db.query(
                    `
                    UPDATE categories
                    SET
                        name = ?,
                        description = ?
                    WHERE id = ?
                    `,
                    [
                        name,
                        description || null,
                        req.params.id
                    ]
                );


            if (
                result.affectedRows === 0
            ) {

                return res.status(404).json({
                    message:
                        "Category not found"
                });

            }


            res.json({
                message:
                    "Category updated"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to update category"
            });

        }

    }
);


// =====================================================
// ADMIN - DELETE CATEGORY
// =====================================================

app.delete(
    "/api/categories/:id",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [result] =
                await db.query(
                    `
                    DELETE FROM categories
                    WHERE id = ?
                    `,
                    [req.params.id]
                );


            if (
                result.affectedRows === 0
            ) {

                return res.status(404).json({
                    message:
                        "Category not found"
                });

            }


            res.json({
                message:
                    "Category deleted"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to delete category"
            });

        }

    }
);


// =====================================================
// PRODUCTS - PUBLIC
// =====================================================

app.get("/api/products", async (req, res) => {

    try {

        const [rows] =
            await db.query(
                `
                SELECT
                    p.*,
                    c.name AS category_name,
                    u.name AS seller_name
                FROM products p
                LEFT JOIN categories c
                    ON p.category_id = c.id
                LEFT JOIN users u
                    ON p.seller_id = u.id
                ORDER BY p.created_at DESC
                `
            );


        res.json(rows);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Unable to fetch products"
        });

    }

});


// =====================================================
// PRODUCT BY ID
// =====================================================

app.get("/api/products/:id", async (req, res) => {

    try {

        const [rows] =
            await db.query(
                `
                SELECT
                    p.*,
                    c.name AS category_name,
                    u.name AS seller_name
                FROM products p
                LEFT JOIN categories c
                    ON p.category_id = c.id
                LEFT JOIN users u
                    ON p.seller_id = u.id
                WHERE p.id = ?
                `,
                [req.params.id]
            );


        if (rows.length === 0) {

            return res.status(404).json({
                message:
                    "Product not found"
            });

        }


        res.json(rows[0]);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Unable to fetch product"
        });

    }

});


// =====================================================
// SEARCH PRODUCTS
// =====================================================

app.get(
    "/api/products/search",
    async (req, res) => {

        try {

            const q =
                req.query.q || "";


            const [rows] =
                await db.query(
                    `
                    SELECT
                        p.*,
                        c.name AS category_name,
                        u.name AS seller_name
                    FROM products p
                    LEFT JOIN categories c
                        ON p.category_id = c.id
                    LEFT JOIN users u
                        ON p.seller_id = u.id
                    WHERE
                        p.name LIKE ?
                        OR p.description LIKE ?
                    ORDER BY p.created_at DESC
                    `,
                    [
                        `%${q}%`,
                        `%${q}%`
                    ]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Search failed"
            });

        }

    }
);


// =====================================================
// CATEGORY PRODUCTS
// =====================================================

app.get(
    "/api/categories/:categoryId/products",
    async (req, res) => {

        try {

            const [rows] =
                await db.query(
                    `
                    SELECT
                        p.*,
                        c.name AS category_name,
                        u.name AS seller_name
                    FROM products p
                    LEFT JOIN categories c
                        ON p.category_id = c.id
                    LEFT JOIN users u
                        ON p.seller_id = u.id
                    WHERE p.category_id = ?
                    ORDER BY p.created_at DESC
                    `,
                    [
                        req.params.categoryId
                    ]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch category products"
            });

        }

    }
);


// =====================================================
// AVAILABLE TODAY
// =====================================================

app.get(
    "/api/products/available-today",
    async (req, res) => {

        try {

            const [rows] =
                await db.query(
                    `
                    SELECT
                        p.*,
                        c.name AS category_name,
                        u.name AS seller_name
                    FROM products p
                    LEFT JOIN categories c
                        ON p.category_id = c.id
                    LEFT JOIN users u
                        ON p.seller_id = u.id
                    WHERE
                        p.status = 'active'
                        AND p.stock_quantity > 0
                    ORDER BY p.created_at DESC
                    `
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch available products"
            });

        }

    }
);


// =====================================================
// SELLER - ADD PRODUCT
// =====================================================

app.post(
    "/api/products",
    requireRole("seller", "admin"),
    upload.single("image"),
    async (req, res) => {
        try {
            const {
                seller_id,
                category_id,
                name,
                description,
                price,
                unit,
                stock_quantity
            } = req.body;

            if (
                !seller_id ||
                !category_id ||
                !name ||
                !price
            ) {
                return res.status(400).json({
                    message: "Required fields are missing"
                });
            }

            const image_url = req.file
                ? `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`
                : "";

            const [result] = await db.query(
                `INSERT INTO products
                (seller_id, category_id, name, description, price, unit, stock_quantity, image_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    seller_id,
                    category_id,
                    name,
                    description || "",
                    price,
                    unit || "",
                    stock_quantity || 0,
                    image_url
                ]
            );

            res.status(201).json({
                message: "Product added successfully",
                productId: result.insertId
            });

        } catch (error) {
            console.error("Add product error:", error);
            res.status(500).json({
                message: "Failed to add product"
            });
        }
    }
);
// =====================================================
// SELLER - GET OWN PRODUCTS
// =====================================================

app.get(
    "/api/sellers/:sellerId/products",
    verifyToken,
    requireRole("seller"),
    async (req, res) => {

        try {

            if (
                Number(req.params.sellerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [rows] =
                await db.query(
                    `
                    SELECT
                        p.*,
                        c.name AS category_name
                    FROM products p
                    LEFT JOIN categories c
                        ON p.category_id = c.id
                    WHERE p.seller_id = ?
                    ORDER BY p.created_at DESC
                    `,
                    [req.user.id]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch seller products"
            });

        }

    }
);


// =====================================================
// SELLER - UPDATE PRODUCT
// ADMIN CAN ALSO UPDATE
// =====================================================

app.put(
    "/api/products/:id",
    requireRole("seller", "admin"),
    upload.single("image"),
    async (req, res) => {
        try {
            const productId = req.params.id;

            const {
                category_id,
                name,
                description,
                price,
                unit,
                stock_quantity,
                status
            } = req.body;

            const [existing] = await db.query(
                "SELECT * FROM products WHERE id = ?",
                [productId]
            );

            if (existing.length === 0) {
                return res.status(404).json({
                    message: "Product not found"
                });
            }

            const oldProduct = existing[0];

            const image_url = req.file
                ? `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`
                : oldProduct.image_url || "";

            await db.query(
                `UPDATE products
                 SET category_id = ?,
                     name = ?,
                     description = ?,
                     price = ?,
                     unit = ?,
                     stock_quantity = ?,
                     image_url = ?,
                     status = ?
                 WHERE id = ?`,
                [
                    category_id,
                    name,
                    description || "",
                    price,
                    unit || "",
                    stock_quantity || 0,
                    image_url,
                    status || "active",
                    productId
                ]
            );

            res.json({
                message: "Product updated successfully"
            });

        } catch (error) {
            console.error("Update product error:", error);

            res.status(500).json({
                message: "Failed to update product"
            });
        }
    }
);

// =====================================================
// SELLER / ADMIN - DELETE PRODUCT
// =====================================================

app.delete(
    "/api/products/:id",
    verifyToken,
    async (req, res) => {

        try {

            const [products] =
                await db.query(
                    `
                    SELECT *
                    FROM products
                    WHERE id = ?
                    `,
                    [req.params.id]
                );


            if (products.length === 0) {

                return res.status(404).json({
                    message:
                        "Product not found"
                });

            }


            const product =
                products[0];


            if (
                req.user.role !== "admin" &&
                (
                    req.user.role !== "seller" ||
                    Number(product.seller_id) !==
                    Number(req.user.id)
                )
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [result] =
                await db.query(
                    `
                    DELETE FROM products
                    WHERE id = ?
                    `,
                    [req.params.id]
                );


            res.json({

                message:
                    "Product deleted",

                affectedRows:
                    result.affectedRows

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to delete product"
            });

        }

    }
);


// =====================================================
// SELLER - UPDATE STOCK
// =====================================================

app.put(
    "/api/sellers/:sellerId/products/:productId/stock",
    verifyToken,
    requireRole("seller"),
    async (req, res) => {

        try {

            if (
                Number(req.params.sellerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const stock =
                Number(
                    req.body.stock_quantity
                );


            if (
                !Number.isInteger(stock) ||
                stock < 0
            ) {

                return res.status(400).json({
                    message:
                        "Stock must be a valid non-negative number"
                });

            }


            const [result] =
                await db.query(
                    `
                    UPDATE products
                    SET stock_quantity = ?
                    WHERE
                        id = ?
                        AND seller_id = ?
                    `,
                    [
                        stock,
                        req.params.productId,
                        req.user.id
                    ]
                );


            if (
                result.affectedRows === 0
            ) {

                return res.status(404).json({
                    message:
                        "Product not found"
                });

            }


            res.json({
                message:
                    "Stock updated successfully"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to update stock"
            });

        }

    }
);


// =====================================================
// CUSTOMER - CREATE ORDER
// =====================================================

app.post(
    "/api/orders",
    verifyToken,
    requireRole("customer"),
    async (req, res) => {

        try {

            const {
                total_amount,
                delivery_address,
                mobile
            } = req.body;


            const total =
                Number(total_amount);


            if (
                !Number.isFinite(total) ||
                total <= 0
            ) {

                return res.status(400).json({
                    message:
                        "Invalid order amount"
                });

            }


            if (
                !delivery_address ||
                !mobile
            ) {

                return res.status(400).json({
                    message:
                        "Delivery address and mobile are required"
                });

            }


            const [result] =
                await db.query(
                    `
                    INSERT INTO orders
                    (
                        customer_id,
                        total_amount,
                        delivery_address,
                        mobile,
                        status
                    )
                    VALUES (?, ?, ?, ?, 'pending')
                    `,
                    [
                        req.user.id,
                        total,
                        delivery_address,
                        mobile
                    ]
                );


            res.status(201).json({

                message:
                    "Order created successfully",

                id:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "Create Order Error:",
                error
            );

            res.status(500).json({
                message:
                    "Unable to create order"
            });

        }

    }
);


// =====================================================
// CUSTOMER - ADD ORDER ITEM
// STOCK IS REDUCED HERE
// =====================================================

app.post(
    "/api/order-items",
    verifyToken,
    requireRole("customer"),
    async (req, res) => {

        try {

            const {
                order_id,
                product_id,
                quantity,
                price
            } = req.body;


            const qty =
                Number(quantity);


            const productId =
                Number(product_id);


            const orderId =
                Number(order_id);


            if (
                !Number.isInteger(qty) ||
                qty <= 0
            ) {

                return res.status(400).json({
                    message:
                        "Quantity must be a positive whole number"
                });

            }


            // Check order belongs to customer

            const [orders] =
                await db.query(
                    `
                    SELECT *
                    FROM orders
                    WHERE
                        id = ?
                        AND customer_id = ?
                    `,
                    [
                        orderId,
                        req.user.id
                    ]
                );


            if (orders.length === 0) {

                return res.status(403).json({
                    message:
                        "Order does not belong to this customer"
                });

            }


            // Check product

            const [products] =
                await db.query(
                    `
                    SELECT *
                    FROM products
                    WHERE id = ?
                    `,
                    [productId]
                );


            if (products.length === 0) {

                return res.status(404).json({
                    message:
                        "Product not found"
                });

            }


            const product =
                products[0];


            if (
                product.status !== "active"
            ) {

                return res.status(400).json({
                    message:
                        "Product is not available"
                });

            }


            if (
                Number(product.stock_quantity) < qty
            ) {

                return res.status(400).json({
                    message:
                        `Only ${product.stock_quantity} item(s) available for ${product.name}`
                });

            }


            // IMPORTANT:
            // Atomically reduce stock only if
            // enough stock is still available.

            const [stockUpdate] =
                await db.query(
                    `
                    UPDATE products
                    SET
                        stock_quantity =
                            stock_quantity - ?
                    WHERE
                        id = ?
                        AND status = 'active'
                        AND stock_quantity >= ?
                    `,
                    [
                        qty,
                        productId,
                        qty
                    ]
                );


            if (
                stockUpdate.affectedRows === 0
            ) {

                return res.status(400).json({
                    message:
                        "Requested quantity is no longer available"
                });

            }


            // Save order item using actual
            // current product price.

            const actualPrice =
                Number(product.price);


            const [result] =
                await db.query(
                    `
                    INSERT INTO order_items
                    (
                        order_id,
                        product_id,
                        quantity,
                        price
                    )
                    VALUES (?, ?, ?, ?)
                    `,
                    [
                        orderId,
                        productId,
                        qty,
                        actualPrice
                    ]
                );


            res.status(201).json({

                message:
                    "Order item added and stock updated",

                id:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "Order Item Error:",
                error
            );

            res.status(500).json({
                message:
                    "Unable to add order item"
            });

        }

    }
);


// =====================================================
// CUSTOMER - MY ORDERS
// =====================================================

app.get(
    "/api/customers/:customerId/orders",
    verifyToken,
    requireRole("customer"),
    async (req, res) => {

        try {

            if (
                Number(req.params.customerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [rows] =
                await db.query(
                    `
                    SELECT
                        o.id AS order_id,
                        o.total_amount,
                        o.delivery_address,
                        o.mobile,
                        o.status,
                        o.created_at,

                        oi.product_id,
                        oi.quantity,
                        oi.price,

                        p.name AS product_name,
                        p.image_url

                    FROM orders o

                    INNER JOIN order_items oi
                        ON o.id = oi.order_id

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    WHERE
                        o.customer_id = ?

                    ORDER BY
                        o.created_at DESC,
                        oi.id ASC
                    `,
                    [req.user.id]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch customer orders"
            });

        }

    }
);


// =====================================================
// SELLER - ORDERS
// =====================================================

app.get(
    "/api/sellers/:sellerId/orders",
    verifyToken,
    requireRole("seller"),
    async (req, res) => {

        try {

            if (
                Number(req.params.sellerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [rows] =
                await db.query(
                    `
                    SELECT

                        o.id AS order_id,
                        o.customer_id,
                        o.total_amount,
                        o.delivery_address,
                        o.mobile,
                        o.status,
                        o.created_at,

                        oi.id AS order_item_id,
                        oi.product_id,
                        oi.quantity,
                        oi.price,

                        p.name AS product_name

                    FROM orders o

                    INNER JOIN order_items oi
                        ON o.id = oi.order_id

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    WHERE
                        p.seller_id = ?

                    ORDER BY
                        o.created_at DESC
                    `,
                    [req.user.id]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch seller orders"
            });

        }

    }
);


// =====================================================
// SELLER - DASHBOARD
// =====================================================

app.get(
    "/api/sellers/:sellerId/dashboard",
    verifyToken,
    requireRole("seller"),
    async (req, res) => {

        try {

            if (
                Number(req.params.sellerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [products] =
                await db.query(
                    `
                    SELECT COUNT(*) AS total_products
                    FROM products
                    WHERE seller_id = ?
                    `,
                    [req.user.id]
                );


            const [orders] =
                await db.query(
                    `
                    SELECT
                        COUNT(DISTINCT oi.order_id)
                        AS total_orders

                    FROM order_items oi

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    WHERE
                        p.seller_id = ?
                    `,
                    [req.user.id]
                );


            const [earnings] =
                await db.query(
                    `
                    SELECT
                        COALESCE(
                            SUM(
                                oi.quantity *
                                oi.price
                            ),
                            0
                        ) AS total_earnings

                    FROM order_items oi

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    INNER JOIN orders o
                        ON oi.order_id = o.id

                    WHERE
                        p.seller_id = ?

                        AND o.status != 'cancelled'
                    `,
                    [req.user.id]
                );


            res.json({

                total_products:
                    products[0].total_products,

                total_orders:
                    orders[0].total_orders,

                total_earnings:
                    earnings[0].total_earnings

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch dashboard"
            });

        }

    }
);


// =====================================================
// SELLER - EARNINGS
// =====================================================

app.get(
    "/api/sellers/:sellerId/earnings",
    verifyToken,
    requireRole("seller"),
    async (req, res) => {

        try {

            if (
                Number(req.params.sellerId) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [rows] =
                await db.query(
                    `
                    SELECT

                        o.id AS order_id,
                        o.status,
                        o.created_at,

                        p.name AS product_name,

                        oi.quantity,
                        oi.price,

                        (
                            oi.quantity *
                            oi.price
                        ) AS amount

                    FROM order_items oi

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    INNER JOIN orders o
                        ON oi.order_id = o.id

                    WHERE
                        p.seller_id = ?

                    ORDER BY
                        o.created_at DESC
                    `,
                    [req.user.id]
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch earnings"
            });

        }

    }
);


// =====================================================
// UPDATE ORDER STATUS
// ADMIN OR SELLER
// =====================================================

app.put(
    "/api/orders/:id/status",
    verifyToken,
    async (req, res) => {

        try {

            const {
                status
            } = req.body;


            const allowedStatuses = [
                "pending",
                "confirmed",
                "cancelled",
                "completed"
            ];


            if (
                !allowedStatuses.includes(status)
            ) {

                return res.status(400).json({
                    message:
                        "Invalid order status"
                });

            }


            const [orders] =
                await db.query(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    `,
                    [req.params.id]
                );


            if (orders.length === 0) {

                return res.status(404).json({
                    message:
                        "Order not found"
                });

            }


            const order =
                orders[0];


            // Seller can update only orders
            // containing seller's products.

            if (
                req.user.role === "seller"
            ) {

                const [sellerItems] =
                    await db.query(
                        `
                        SELECT oi.id

                        FROM order_items oi

                        INNER JOIN products p
                            ON oi.product_id = p.id

                        WHERE
                            oi.order_id = ?
                            AND p.seller_id = ?

                        LIMIT 1
                        `,
                        [
                            req.params.id,
                            req.user.id
                        ]
                    );


                if (
                    sellerItems.length === 0
                ) {

                    return res.status(403).json({
                        message:
                            "You cannot update this order"
                    });

                }

            } else if (
                req.user.role !== "admin"
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const oldStatus =
                order.status;


            // If cancelling an order,
            // restore stock only once.

            if (
                status === "cancelled" &&
                oldStatus !== "cancelled"
            ) {

                const [items] =
                    await db.query(
                        `
                        SELECT
                            product_id,
                            quantity
                        FROM order_items
                        WHERE order_id = ?
                        `,
                        [req.params.id]
                    );


                for (
                    const item
                    of items
                ) {

                    await db.query(
                        `
                        UPDATE products
                        SET
                            stock_quantity =
                                stock_quantity + ?
                        WHERE id = ?
                        `,
                        [
                            item.quantity,
                            item.product_id
                        ]
                    );

                }

            }


            // Prevent restoring stock again
            // when cancelled order is changed
            // from cancelled to another status.

            if (
                oldStatus === "cancelled" &&
                status !== "cancelled"
            ) {

                return res.status(400).json({
                    message:
                        "Cancelled orders cannot be reopened"
                });

            }


            const [result] =
                await db.query(
                    `
                    UPDATE orders
                    SET status = ?
                    WHERE id = ?
                    `,
                    [
                        status,
                        req.params.id
                    ]
                );


            res.json({

                message:
                    "Order status updated",

                affectedRows:
                    result.affectedRows

            });

        } catch (error) {

            console.error(
                "Order Status Error:",
                error
            );

            res.status(500).json({
                message:
                    "Unable to update order status"
            });

        }

    }
);


// =====================================================
// ADMIN - ALL USERS
// =====================================================

app.get(
    "/api/users",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [rows] =
                await db.query(
                    `
                    SELECT
                        id,
                        name,
                        mobile,
                        email,
                        role,
                        created_at
                    FROM users
                    ORDER BY created_at DESC
                    `
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch users"
            });

        }

    }
);


// =====================================================
// ADMIN - ALL ORDERS
// =====================================================

app.get(
    "/api/orders",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [rows] =
                await db.query(
                    `
                    SELECT
                        o.*,
                        u.name AS customer_name
                    FROM orders o

                    INNER JOIN users u
                        ON o.customer_id = u.id

                    ORDER BY
                        o.created_at DESC
                    `
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch orders"
            });

        }

    }
);


// =====================================================
// ADMIN - ALL ORDER ITEMS
// =====================================================

app.get(
    "/api/order-items",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [rows] =
                await db.query(
                    `
                    SELECT
                        oi.*,
                        p.name AS product_name
                    FROM order_items oi

                    INNER JOIN products p
                        ON oi.product_id = p.id

                    ORDER BY oi.id DESC
                    `
                );


            res.json(rows);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Unable to fetch order items"
            });

        }

    }
);


// =====================================================
// SERVER START
// =====================================================

app.listen(
    PORT,
    () => {

        console.log(
            `MaalSetu server running on port ${PORT}`
        );

    }
);