const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


const db = require("./db");
const upload = require("./upload");

const app = express();

const PORT = 5000;
const JWT_SECRET = "maalsetu_secret_key_change_later";


// =====================================================
// MIDDLEWARE
// =====================================================

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/uploads", express.static("uploads"));


// =====================================================
// DATABASE TEST
// =====================================================

async function testDatabaseConnection() {
    try {
        const connection = await db.getConnection();

        console.log("MaalSetu Database Connected!");

        connection.release();

    } catch (error) {

        console.error(
            "Database connection failed:",
            error.message
        );
    }
}

testDatabaseConnection();


// =====================================================
// BASIC TEST ROUTE
// =====================================================

app.get("/", (req, res) => {

    res.json({
        message: "MaalSetu API is running",
        status: "success",
        port: PORT
    });

});


// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function verifyToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {

        return res.status(401).json({
            message: "Authorization token required"
        });

    }

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {

        return res.status(401).json({
            message: "Invalid authorization format"
        });

    }

    const token = parts[1];

    try {

        const decoded = jwt.verify(
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

function requireRole(...roles) {

    return function (req, res, next) {

        if (!req.user) {

            return res.status(401).json({
                message: "Authentication required"
            });

        }

        if (!roles.includes(req.user.role)) {

            return res.status(403).json({
                message: "Access denied"
            });

        }

        next();

    };

}


// =====================================================
// REGISTER
// =====================================================

app.post("/api/register", async (req, res) => {
    console.log("=================================");
    console.log("REGISTER API HIT");
    console.log("BODY:", req.body);

    try {
        const {
            name,
            mobile,
            email,
            password,
            role
        } = req.body;

        console.log("STEP 1 - Values received:", {
            name,
            mobile,
            email,
            role
        });

        if (!name || !mobile || !password) {
            console.log("STEP 2 - Validation failed");

            return res.status(400).json({
                success: false,
                message: "Name, mobile and password are required"
            });
        }

        // IMPORTANT: normal JavaScript regex
       if (!/^[0-9]{10}$/.test(String(mobile))) {
            console.log("STEP 3 - Mobile validation failed");

            return res.status(400).json({
                success: false,
                message: "Please enter a valid 10-digit mobile number"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters"
            });
        }

        let userRole = role || "customer";

        if (!["customer", "seller", "admin"].includes(userRole)) {
            userRole = "customer";
        }

        console.log("STEP 4 - Checking mobile");

        const [mobileUsers] = await db.query(
            "SELECT id FROM users WHERE mobile = ? LIMIT 1",
            [mobile]
        );

        console.log("STEP 5 - Mobile check completed");

        if (mobileUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Mobile number is already registered"
            });
        }

        if (email) {
            console.log("STEP 6 - Checking email");

            const [emailUsers] = await db.query(
                "SELECT id FROM users WHERE email = ? LIMIT 1",
                [email]
            );

            console.log("STEP 7 - Email check completed");

            if (emailUsers.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: "Email is already registered"
                });
            }
        }

        console.log("STEP 8 - Hashing password");

        const hashedPassword = await bcrypt.hash(password, 10);

        console.log("STEP 9 - Inserting user");

        const [result] = await db.query(
            `INSERT INTO users
            (name, mobile, email, password, role)
            VALUES (?, ?, ?, ?, ?)`,
            [
                name,
                mobile,
                email || null,
                hashedPassword,
                userRole
            ]
        );

        console.log(
            "STEP 10 - Registration successful. User ID:",
            result.insertId
        );

        return res.status(201).json({
            success: true,
            message: "Account created successfully",
            userId: result.insertId,
            role: userRole
        });

    } catch (error) {

        console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        console.error("REGISTER ERROR");
        console.error("MESSAGE:", error.message);
        console.error("CODE:", error.code);
        console.error("SQL MESSAGE:", error.sqlMessage);
        console.error("FULL ERROR:", error);
        console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        return res.status(500).json({
            success: false,
            message: "Registration failed",
            error: error.message,
            code: error.code || null
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
            email,
            password
        } = req.body;


        if ((!mobile && !email) || !password) {

            return res.status(400).json({
                message:
                    "Mobile/email and password are required"
            });

        }


        let users;


        if (mobile) {

            [users] = await db.query(
                "SELECT * FROM users WHERE mobile = ? LIMIT 1",
                [mobile]
            );

        } else {

            [users] = await db.query(
                "SELECT * FROM users WHERE email = ? LIMIT 1",
                [email]
            );

        }


        if (users.length === 0) {

            return res.status(401).json({
                message:
                    "Invalid login credentials"
            });

        }


        const user = users[0];


        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );


        if (!passwordMatch) {

            return res.status(401).json({
                message:
                    "Invalid login credentials"
            });

        }


        const token =
            jwt.sign(
                {
                    id: user.id,
                    name: user.name,
                    mobile: user.mobile,
                    email: user.email,
                    role: user.role
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );


        return res.json({

            success: true,

            message:
                "Login successful",

            token,

            user: {
                id: user.id,
                name: user.name,
                mobile: user.mobile,
                email: user.email,
                role: user.role
            }

        });

    } catch (error) {

        console.error(
            "Login error:",
            error
        );


        return res.status(500).json({
            message:
                "Login failed",
            error:
                error.message
        });

    }

});


// =====================================================
// CATEGORIES
// =====================================================

app.get("/api/categories", async (req, res) => {

    try {

        const [rows] = await db.query(
            "SELECT * FROM categories ORDER BY name ASC"
        );

        res.json(rows);

    } catch (error) {

        console.error(
            "Categories error:",
            error
        );

        res.status(500).json({
            message:
                "Failed to load categories"
        });

    }

});


app.get("/api/categories/:id/products", async (req, res) => {

    try {

        const [rows] = await db.query(
            `SELECT
                p.*,
                c.name AS category_name
             FROM products p
             LEFT JOIN categories c
             ON p.category_id = c.id
             WHERE p.category_id = ?
             ORDER BY p.created_at DESC`,
            [req.params.id]
        );

        res.json(rows);

    } catch (error) {

        console.error(
            "Category products error:",
            error
        );

        res.status(500).json({
            message:
                "Failed to load category products"
        });

    }

});


// =====================================================
// ADMIN CATEGORY
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


            const [result] = await db.query(
                `INSERT INTO categories
                (name, description)
                VALUES (?, ?)`,
                [
                    name,
                    description || ""
                ]
            );


            res.status(201).json({

                message:
                    "Category added successfully",

                categoryId:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "Add category error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to add category"
            });

        }

    }
);


app.delete(
    "/api/categories/:id",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            await db.query(
                "DELETE FROM categories WHERE id = ?",
                [req.params.id]
            );

            res.json({
                message:
                    "Category deleted successfully"
            });

        } catch (error) {

            console.error(
                "Delete category error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to delete category"
            });

        }

    }
);


// =====================================================
// PRODUCTS
// =====================================================

app.get("/api/products", async (req, res) => {

    try {

        const [rows] = await db.query(
            `SELECT
                p.*,
                c.name AS category_name,
                u.name AS seller_name
             FROM products p
             LEFT JOIN categories c
             ON p.category_id = c.id
             LEFT JOIN users u
             ON p.seller_id = u.id
             ORDER BY p.created_at DESC`
        );

        res.json(rows);

    } catch (error) {

        console.error(
            "Products error:",
            error
        );

        res.status(500).json({
            message:
                "Failed to load products"
        });

    }

});


app.get("/api/products/search", async (req, res) => {

    try {

        const q =
            String(req.query.q || "").trim();


        const [rows] = await db.query(
            `SELECT
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
                OR c.name LIKE ?
             ORDER BY p.created_at DESC`,
            [
                `%${q}%`,
                `%${q}%`,
                `%${q}%`
            ]
        );


        res.json(rows);

    } catch (error) {

        console.error(
            "Product search error:",
            error
        );

        res.status(500).json({
            message:
                "Search failed"
        });

    }

});


app.get("/api/products/:id", async (req, res) => {

    try {

        const [rows] = await db.query(
            `SELECT
                p.*,
                c.name AS category_name,
                u.name AS seller_name
             FROM products p
             LEFT JOIN categories c
             ON p.category_id = c.id
             LEFT JOIN users u
             ON p.seller_id = u.id
             WHERE p.id = ?`,
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

        console.error(
            "Product details error:",
            error
        );

        res.status(500).json({
            message:
                "Failed to load product"
        });

    }

});


// =====================================================
// ADD PRODUCT
// =====================================================

app.post(
    "/api/products",
    verifyToken,
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
                price === undefined
            ) {

                return res.status(400).json({
                    message:
                        "Required fields are missing"
                });

            }


            const image_url =
                req.file
                    ? `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`
                    : "";


            const [result] = await db.query(
                `INSERT INTO products
                (
                    seller_id,
                    category_id,
                    name,
                    description,
                    price,
                    unit,
                    stock_quantity,
                    image_url
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    seller_id,
                    category_id,
                    name,
                    description || "",
                    price,
                    unit || "",
                    Number(stock_quantity) || 0,
                    image_url
                ]
            );


            res.status(201).json({

                message:
                    "Product added successfully",

                productId:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "Add product error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to add product",
                error:
                    error.message
            });

        }

    }
);


// =====================================================
// UPDATE PRODUCT
// =====================================================

app.put(
    "/api/products/:id",
    verifyToken,
    requireRole("seller", "admin"),
    upload.single("image"),
    async (req, res) => {

        try {

            const productId =
                req.params.id;


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
                    message:
                        "Product not found"
                });

            }


            const oldProduct =
                existing[0];


            const image_url =
                req.file
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
                    Number(stock_quantity) || 0,
                    image_url,
                    status || "active",
                    productId
                ]
            );


            res.json({
                message:
                    "Product updated successfully"
            });

        } catch (error) {

            console.error(
                "Update product error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to update product",
                error:
                    error.message
            });

        }

    }
);


// =====================================================
// DELETE PRODUCT
// =====================================================

app.delete(
    "/api/products/:id",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        try {

            await db.query(
                "DELETE FROM products WHERE id = ?",
                [req.params.id]
            );


            res.json({
                message:
                    "Product deleted successfully"
            });

        } catch (error) {

            console.error(
                "Delete product error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to delete product"
            });

        }

    }
);


// =====================================================
// SELLER PRODUCTS
// =====================================================

app.get(
    "/api/sellers/:sellerId/products",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        try {

            const [rows] = await db.query(
                `SELECT
                    p.*,
                    c.name AS category_name
                 FROM products p
                 LEFT JOIN categories c
                 ON p.category_id = c.id
                 WHERE p.seller_id = ?
                 ORDER BY p.created_at DESC`,
                [req.params.sellerId]
            );


            res.json(rows);

        } catch (error) {

            console.error(
                "Seller products error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load seller products"
            });

        }

    }
);


// =====================================================
// SELLER STOCK
// =====================================================

app.put(
    "/api/sellers/:sellerId/products/:productId/stock",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        try {

            const {
                stock_quantity
            } = req.body;


            await db.query(
                `UPDATE products
                 SET stock_quantity = ?
                 WHERE id = ?
                 AND seller_id = ?`,
                [
                    Number(stock_quantity) || 0,
                    req.params.productId,
                    req.params.sellerId
                ]
            );


            res.json({
                message:
                    "Stock updated successfully"
            });

        } catch (error) {

            console.error(
                "Stock update error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to update stock"
            });

        }

    }
);


// =====================================================
// CREATE ORDER
// =====================================================

app.post(
    "/api/orders",
    verifyToken,
    requireRole("customer"),
    async (req, res) => {

        try {

            const {
                customer_id,
                total_amount,
                delivery_address,
                mobile
            } = req.body;


            const customerId =
                Number(customer_id) || req.user.id;


            if (
                !total_amount ||
                !delivery_address ||
                !mobile
            ) {

                return res.status(400).json({
                    message:
                        "Order details are incomplete"
                });

            }


            const [result] = await db.query(
                `INSERT INTO orders
                (
                    customer_id,
                    total_amount,
                    delivery_address,
                    mobile
                )
                VALUES (?, ?, ?, ?)`,
                [
                    customerId,
                    total_amount,
                    delivery_address,
                    mobile
                ]
            );


            res.status(201).json({

                message:
                    "Order created successfully",

                orderId:
                    result.insertId

            });

        } catch (error) {

            console.error(
                "Create order error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to create order"
            });

        }

    }
);


// =====================================================
// ADD ORDER ITEM + STOCK UPDATE
// =====================================================

app.post(
    "/api/order-items",
    verifyToken,
    requireRole("customer"),
    async (req, res) => {

        const connection =
            await db.getConnection();


        try {

            const {
                order_id,
                product_id,
                quantity,
                price
            } = req.body;


            if (
                !order_id ||
                !product_id ||
                !quantity ||
                price === undefined
            ) {

                connection.release();

                return res.status(400).json({
                    message:
                        "Order item details are incomplete"
                });

            }


            await connection.beginTransaction();


            const [products] =
                await connection.query(
                    `SELECT
                        stock_quantity,
                        status
                     FROM products
                     WHERE id = ?
                     FOR UPDATE`,
                    [product_id]
                );


            if (products.length === 0) {

                await connection.rollback();
                connection.release();

                return res.status(404).json({
                    message:
                        "Product not found"
                });

            }


            const product =
                products[0];


            if (
                product.status !== "active" ||
                Number(product.stock_quantity) <
                Number(quantity)
            ) {

                await connection.rollback();
                connection.release();

                return res.status(400).json({
                    message:
                        "Insufficient stock"
                });

            }


            await connection.query(
                `INSERT INTO order_items
                (
                    order_id,
                    product_id,
                    quantity,
                    price
                )
                VALUES (?, ?, ?, ?)`,
                [
                    order_id,
                    product_id,
                    quantity,
                    price
                ]
            );


            await connection.query(
                `UPDATE products
                 SET stock_quantity =
                     stock_quantity - ?
                 WHERE id = ?`,
                [
                    quantity,
                    product_id
                ]
            );


            await connection.commit();

            connection.release();


            res.status(201).json({

                message:
                    "Order item added successfully"

            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error(
                    "Rollback error:",
                    rollbackError
                );
            }

            connection.release();


            console.error(
                "Order item error:",
                error
            );


            res.status(500).json({
                message:
                    "Failed to add order item"
            });

        }

    }
);


// =====================================================
// CUSTOMER ORDERS
// =====================================================

app.get(
    "/api/customers/:customerId/orders",
    verifyToken,
    async (req, res) => {

        try {

            const customerId =
                Number(req.params.customerId);


            if (
                req.user.role !== "admin" &&
                req.user.id !== customerId
            ) {

                return res.status(403).json({
                    message:
                        "Access denied"
                });

            }


            const [orders] = await db.query(
                `SELECT *
                 FROM orders
                 WHERE customer_id = ?
                 ORDER BY created_at DESC`,
                [customerId]
            );


            for (const order of orders) {

                const [items] =
                    await db.query(
                        `SELECT
                            oi.*,
                            p.name,
                            p.image_url,
                            p.unit
                         FROM order_items oi
                         LEFT JOIN products p
                         ON oi.product_id = p.id
                         WHERE oi.order_id = ?`,
                        [order.id]
                    );


                order.items = items;

            }


            res.json(orders);

        } catch (error) {

            console.error(
                "Customer orders error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load customer orders"
            });

        }

    }
);


// =====================================================
// SELLER ORDERS
// =====================================================

app.get(
    "/api/sellers/:sellerId/orders",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        try {

            const sellerId =
                Number(req.params.sellerId);


            const [orders] = await db.query(
                `SELECT DISTINCT
                    o.*
                 FROM orders o
                 INNER JOIN order_items oi
                 ON o.id = oi.order_id
                 INNER JOIN products p
                 ON oi.product_id = p.id
                 WHERE p.seller_id = ?
                 ORDER BY o.created_at DESC`,
                [sellerId]
            );


            for (const order of orders) {

                const [items] =
                    await db.query(
                        `SELECT
                            oi.*,
                            p.name,
                            p.image_url,
                            p.unit,
                            p.seller_id
                         FROM order_items oi
                         INNER JOIN products p
                         ON oi.product_id = p.id
                         WHERE oi.order_id = ?
                         AND p.seller_id = ?`,
                        [
                            order.id,
                            sellerId
                        ]
                    );


                order.items = items;

            }


            res.json(orders);

        } catch (error) {

            console.error(
                "Seller orders error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load seller orders"
            });

        }

    }
);


// =====================================================
// ORDER STATUS
// =====================================================

app.put(
    "/api/orders/:id/status",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        const connection =
            await db.getConnection();


        try {

            const orderId =
                Number(req.params.id);


            const {
                status
            } = req.body;


            const allowedStatuses = [
                "pending",
                "confirmed",
                "cancelled",
                "completed"
            ];


            if (!allowedStatuses.includes(status)) {

                connection.release();

                return res.status(400).json({
                    message:
                        "Invalid order status"
                });

            }


            await connection.beginTransaction();


            const [orders] =
                await connection.query(
                    "SELECT * FROM orders WHERE id = ? FOR UPDATE",
                    [orderId]
                );


            if (orders.length === 0) {

                await connection.rollback();
                connection.release();

                return res.status(404).json({
                    message:
                        "Order not found"
                });

            }


            const oldStatus =
                orders[0].status;


            if (
                oldStatus === "cancelled" &&
                status !== "cancelled"
            ) {

                await connection.rollback();
                connection.release();

                return res.status(400).json({
                    message:
                        "Cancelled order cannot be reopened"
                });

            }


            // Restore stock only when cancelling
            if (
                status === "cancelled" &&
                oldStatus !== "cancelled"
            ) {

                const [items] =
                    await connection.query(
                        `SELECT
                            product_id,
                            quantity
                         FROM order_items
                         WHERE order_id = ?`,
                        [orderId]
                    );


                for (const item of items) {

                    await connection.query(
                        `UPDATE products
                         SET stock_quantity =
                             stock_quantity + ?
                         WHERE id = ?`,
                        [
                            item.quantity,
                            item.product_id
                        ]
                    );

                }

            }


            await connection.query(
                `UPDATE orders
                 SET status = ?
                 WHERE id = ?`,
                [
                    status,
                    orderId
                ]
            );


            await connection.commit();

            connection.release();


            res.json({
                message:
                    "Order status updated successfully"
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error(
                    "Rollback error:",
                    rollbackError
                );
            }

            connection.release();


            console.error(
                "Order status error:",
                error
            );


            res.status(500).json({
                message:
                    "Failed to update order status"
            });

        }

    }
);


// =====================================================
// ADMIN USERS
// =====================================================

app.get(
    "/api/admin/users",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [rows] = await db.query(
                `SELECT
                    id,
                    name,
                    mobile,
                    email,
                    role,
                    created_at
                 FROM users
                 ORDER BY created_at DESC`
            );


            res.json(rows);

        } catch (error) {

            console.error(
                "Admin users error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load users"
            });

        }

    }
);


// =====================================================
// ADMIN ALL ORDERS
// =====================================================

app.get(
    "/api/admin/orders",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {

        try {

            const [orders] = await db.query(
                `SELECT
                    o.*,
                    u.name AS customer_name,
                    u.email AS customer_email
                 FROM orders o
                 LEFT JOIN users u
                 ON o.customer_id = u.id
                 ORDER BY o.created_at DESC`
            );


            for (const order of orders) {

                const [items] =
                    await db.query(
                        `SELECT
                            oi.*,
                            p.name,
                            p.image_url,
                            p.unit,
                            p.seller_id,
                            s.name AS seller_name
                         FROM order_items oi
                         LEFT JOIN products p
                         ON oi.product_id = p.id
                         LEFT JOIN users s
                         ON p.seller_id = s.id
                         WHERE oi.order_id = ?`,
                        [order.id]
                    );


                order.items = items;

            }


            res.json(orders);

        } catch (error) {

            console.error(
                "Admin orders error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load admin orders"
            });

        }

    }
);


// =====================================================
// SELLER EARNINGS
// =====================================================

app.get(
    "/api/sellers/:sellerId/earnings",
    verifyToken,
    requireRole("seller", "admin"),
    async (req, res) => {

        try {

            const sellerId =
                Number(req.params.sellerId);


            const [rows] =
                await db.query(
                    `SELECT
                        o.id AS order_id,
                        o.status,
                        o.created_at,
                        oi.quantity,
                        oi.price,
                        p.name AS product_name
                     FROM orders o
                     INNER JOIN order_items oi
                     ON o.id = oi.order_id
                     INNER JOIN products p
                     ON oi.product_id = p.id
                     WHERE p.seller_id = ?
                     AND o.status = 'completed'
                     ORDER BY o.created_at DESC`,
                    [sellerId]
                );


            let totalEarnings = 0;


            rows.forEach(row => {

                totalEarnings +=
                    Number(row.price) *
                    Number(row.quantity);

            });


            res.json({

                totalEarnings,

                completedOrders:
                    rows.length,

                records:
                    rows

            });

        } catch (error) {

            console.error(
                "Seller earnings error:",
                error
            );

            res.status(500).json({
                message:
                    "Failed to load earnings"
            });

        }

    }
);


// =====================================================
// 404 API
// =====================================================

app.use("/api", (req, res) => {

    res.status(404).json({
        message:
            "API endpoint not found",
        path:
            req.originalUrl
    });

});


// =====================================================
// GLOBAL ERROR HANDLER
// =====================================================

app.use((error, req, res, next) => {

    console.error(
        "Global server error:",
        error
    );


    res.status(500).json({
        message:
            error.message ||
            "Internal server error"
    });

});


// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {

    console.log(
        `MaalSetu server running on port ${PORT}`
    );

});