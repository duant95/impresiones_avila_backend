const express = require('express');
const mysql = require('mysql2');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const multer = require('multer'); 
const moment = require('moment');
const fetch = require('node-fetch'); 
const paypal = require('@paypal/checkout-server-sdk'); 
require('dotenv').config();  


const { PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PORT = 8888 } = process.env;
const app = express();
const base = "https://api-m.sandbox.paypal.com";
const SECRET_KEY = 'amovertele';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'client')));

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
    host: 'batrulnfgqs2kypiowvz-mysql.services.clever-cloud.com',
    user: 'urlvnsfntvnqaneu',
    password: 'mp0cZF1PL0B9o8RMyPYB',
    database: 'batrulnfgqs2kypiowvz',
    port: '3306'


});

db.connect(err => {
    if (err) {
        console.error('Database connection error:', err);
        return;
    }
    console.log('Database connConnected to the MySQL database on Clever Cloudcted');
});

const Environment = process.env.NODE_ENV === 'production' ? paypal.core.LiveEnvironment : paypal.core.SandboxEnvironment;
const paypalClient = new paypal.core.PayPalHttpClient(new Environment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET));


// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'duant75@gmail.com',
        pass: 'vknj wvob whqs hvuv'
    }
});

const sendNotification = (userId, eventType, content) => {
    db.query('SELECT email FROM Users WHERE user_id = ?', [userId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error al obtener el correo del usuario:', err);
            return;
        }

        const userEmail = results[0].email;

        const mailOptions = {
            from: 'duant75@gmail.com',
            to: userEmail,
            subject: `Notificación de ${eventType}`,
            text: content
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error al enviar el correo:', error);
                return;
            }

            console.log('Correo enviado:', info.response);

            const query = 'INSERT INTO Notifications (user_id, event_type, content) VALUES (?, ?, ?)';
            db.query(query, [userId, eventType, content], (err, results) => {
                if (err) {
                    console.error('Error al registrar la notificación:', err);
                }
            });
        });
    });
};

async function generateAccessToken() {
    try {
        const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");

        const response = await fetch(`${base}/v1/oauth2/token`, {
            method: "POST",
            headers: {
                Authorization: `Basic ${auth}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: "client_credentials"
            }),
        });

        if (!response.ok) {
            throw new Error(`PayPal token request failed: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return data.access_token;
    } catch (error) {
        console.error('Error generating PayPal access token:', error);
        // Aquí puedes manejar el error, lanzar una excepción o devolver un valor específico
        throw error;  // Si quieres que el error se propague, de lo contrario maneja según tus necesidades
    }
}

const createOrder = async (req, res) => {
    try {
        const { total, currency_code } = req.body;
        const accessToken = await generateAccessToken();
        const url = `${base}/v2/checkout/orders`;

        const payload = {
            intent: "CAPTURE",
            purchase_units: [
                {
                    amount: {
                        currency_code: currency_code || "USD",
                        value: total
                    }
                }
            ]
        };

        console.log('Creating order with payload:', payload);

        const response = await fetch(url, {
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${accessToken}`
            },
            method: "POST",
            body: JSON.stringify(payload)
        });

        const orderData = await response.json();
        console.log('Order created:', orderData);

        if (!orderData.id) {
            throw new Error('Order creation failed: no order ID returned');
        }

        res.status(response.status).json(orderData);
    } catch (error) {
        console.error("Error creating PayPal order:", error);
        res.status(500).json({ error: "Error creating PayPal order." });
    }
};

const captureOrder = async (req, res) => {
    const { orderID } = req.body;
    const accessToken = await generateAccessToken();
    const url = `${base}/v2/checkout/orders/${orderID}/capture`;

    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`
        }
    });

    const captureData = await response.json();
    res.status(response.status).json(captureData);
};


const registerActivity = (userId, action, details) => {
    const query = 'INSERT INTO AuditLogs (user_id, action, details) VALUES (?, ?, ?)';
    db.query(query, [userId, action, details], (err, results) => {
        if (err) {
            console.error('Error al registrar la actividad:', err);
        }
    });
};

const verifySession = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    console.log('Token recibido:', token); 
    if (!token) {
        return res.status(401).json({ message: 'Access token is missing or invalid' });
    }
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.error('Error de verificación de token:', err);
            return res.status(401).json({ message: 'Access token is invalid or expired' });
        }
        const query = 'SELECT * FROM Sessions WHERE token = ? AND is_active = ?';
        db.query(query, [token, true], (sessionErr, sessionResults) => {
            if (sessionErr || sessionResults.length === 0) {
                console.error('Error de sesión o sesión no activa:', sessionErr);
                return res.status(401).json({ message: 'Session is not active' });
            }
            req.user = decoded;
            next();
        });
    });
};

app.post("/api/orders", createOrder);
app.post("/api/orders/:orderID/capture", captureOrder);

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM Users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: 'Invalid password' });

        const token = jwt.sign({ id: user.user_id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

        const sessionQuery = 'INSERT INTO Sessions (user_id, token, is_active) VALUES (?, ?, ?)';
        db.query(sessionQuery, [user.user_id, token, true], (sessionErr, sessionResult) => {
            if (sessionErr) {
                console.error('Error al registrar la sesión:', sessionErr);
                return res.status(500).json({ message: 'Error al registrar la sesión' });
            }

            // Lógica para mostrar el sidebar solo al admin
            const showSidebar = user.role === 'admin';

            registerActivity(user.user_id, 'Inicio de sesión', `Usuario ${username} inició sesión`);

            res.status(200).json({ 
                success: true, 
                token, 
                user: { 
                    username: user.username, 
                    role: user.role,
                    showSidebar  // Devuelve el flag para mostrar el sidebar
                } 
            });
        });
    });
});


app.post('/logout', verifySession, (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    const query = 'UPDATE Sessions SET is_active = ? WHERE token = ?';
    db.query(query, [false, token], (err, results) => {
        if (err) {
            console.error('Error al cerrar la sesión:', err);
            return res.status(500).json({ message: 'Error al cerrar la sesión' });
        }

        registerActivity(req.user.id, 'Cierre de sesión', `Usuario ${req.user.id} cerró sesión`);

        res.status(200).json({ success: true, message: 'Sesión cerrada exitosamente' });
    });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const tempPassword = crypto.randomBytes(4).toString('hex');  
    const token = crypto.randomBytes(20).toString('hex');

    const hashedTempPassword = bcrypt.hashSync(tempPassword, 10);

    const expires = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

    db.query('UPDATE Users SET reset_password_token = ?, reset_password_expires = ?, password = ? WHERE email = ?', 
    [token, expires, hashedTempPassword, email], (err, result) => {
        if (err || result.affectedRows === 0) {
            console.error('Error updating user with reset token:', err);
            return res.status(400).send({ message: 'Email no encontrado' });
        }

        const mailOptions = {
            from: 'tu_correo@gmail.com',
            to: email,
            subject: 'Restablecimiento de Contraseña',
            text: `Tu nueva contraseña temporal es: ${tempPassword}\n\n` +
                  `Usa esta contraseña temporal para iniciar sesión y luego cambia tu contraseña a una nueva.\n\n` +
                  `Haz clic en el siguiente enlace para completar el proceso:\n\n` +
                  `http://localhost:3000/reset-password/${token}\n\n` +
                  `Si no solicitaste esto, ignora este correo y tu contraseña permanecerá sin cambios.\n`
        };

        transporter.sendMail(mailOptions, (err, response) => {
            if (err) {
                console.error('Error sending reset email:', err);
                return res.status(500).send({ message: 'Error al enviar el correo' });
            }
            res.status(200).send({ message: 'Correo enviado con éxito con la contraseña temporal' });
        });
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    db.query('SELECT * FROM Users WHERE reset_password_token = ? AND reset_password_expires > ?', 
    [token, new Date().toISOString().slice(0, 19).replace('T', ' ')], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).send({ message: 'El token es inválido o ha expirado' });
        }

        const user = results[0];
        const isPasswordSame = bcrypt.compareSync(password, user.password);

        if (isPasswordSame) {
            return res.status(400).send({ message: 'La nueva contraseña no puede ser igual a la contraseña temporal' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        db.query('UPDATE Users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE reset_password_token = ?', 
        [hashedPassword, token], (err) => {
            if (err) {
                return res.status(500).send({ message: 'Error al restablecer la contraseña' });
            }
            res.status(200).send({ message: 'Contraseña restablecida con éxito' });
        });
    });
});

app.post('/register', async (req, res) => {
    const { username, firstName, lastName, email, birthDate, password, identificationType, identificationNumber } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const userQuery = 'INSERT INTO Users (username, first_name, last_name, email, birth_date, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)';
        const userValues = [username, firstName, lastName, email, birthDate, hashedPassword, 'user'];

        db.query(userQuery, userValues, (err, result) => {
            if (err) {
                console.error('Error al registrar el usuario en la base de datos:', err);
                res.status(500).json({ success: false, message: 'Error al registrar el usuario' });
                return;
            }
        
            const userId = result.insertId; 

            const clientQuery = 'INSERT INTO Clients (user_id, name, address, contact_info, client_type, identification_number, email, identification_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
            const clientValues = [
                userId,
                `${firstName} ${lastName}`,
                '', 
                email, 
                'individual', 
                identificationNumber,
                email,
                identificationType
            ];
            
            db.query(clientQuery, clientValues, (err, clientResult) => {
                if (err) {
                    console.error('Error al registrar el cliente en la base de datos:', err);
                    res.status(500).json({ success: false, message: 'Error al registrar el cliente' });
                    return;
                }
            
                res.status(201).json({ success: true, message: 'Usuario y cliente registrados con éxito' });
            }); 
        });
    } catch (error) {
        console.error('Error durante el proceso de registro:', error);
        res.status(500).json({ success: false, message: 'Error al registrar el usuario' });
    }
});

app.put('/update-profile', verifySession, (req, res) => {
    const { user_id } = req.user;
    const { newUsername, newEmail } = req.body;

    const query = 'UPDATE Users SET username = ?, email = ? WHERE user_id = ?';
    db.query(query, [newUsername, newEmail, user_id], (err, results) => {
        if (err) {
            console.error('Error al actualizar el perfil:', err);
            return res.status(500).json({ message: 'Error al actualizar el perfil' });
        }

        const details = `Usuario actualizó su perfil: username = ${newUsername}, email = ${newEmail}`;
        registerActivity(user_id, 'Cambio de perfil', details);

        res.status(200).json({ success: true, message: 'Perfil actualizado exitosamente' });
    });
});

app.post('/perform-action', verifySession, (req, res) => {
    const { user_id } = req.user;
    const { actionDetails } = req.body;

    registerActivity(user_id, 'Realizó una acción', `Detalles de la acción: ${actionDetails}`);

    res.status(200).json({ success: true, message: 'Acción realizada exitosamente' });
});

app.post('/system-update', verifySession, (req, res) => {
    const { updateDetails } = req.body;

    db.query('SELECT user_id FROM Users', (err, results) => {
        if (err) {
            console.error('Error al obtener usuarios:', err);
            return res.status(500).send('Server error');
        }

        results.forEach(user => {
            sendNotification(user.user_id, 'Actualización del Sistema', updateDetails);
        });

        res.status(200).send('Notificaciones enviadas');
    });
});

app.get('/notifications', verifySession, (req, res) => {
    const query = 'SELECT * FROM Notifications';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener notificaciones:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.post('/create-paypal-order', verifySession, async (req, res) => {
    console.log("create-paypal-order endpoint hit");
    console.log("Request Body:", req.body);
    
    try {
        // 1. Crear la orden en PayPal
        const request = new paypal.orders.OrdersCreateRequest();
        request.requestBody({
            intent: 'CAPTURE',
            purchase_units: [{
                amount: {
                    currency_code: 'USD',
                    value: req.body.total
                }
            }]
        });

        const order = await paypalClient.execute(request);
        console.log("PayPal Order Created:", order.result.id);

        // 2. Crear la orden en tu base de datos
        const { client_id, total, items, paymentMethod } = req.body;
        const formattedDate = moment().format('YYYY-MM-DD HH:mm:ss');

        const query = 'INSERT INTO Orders (client_id, total_amount, status, order_date) VALUES (?, ?, "processing", ?)';
        db.query(query, [client_id, total, formattedDate], (err, orderResults) => {
            if (err) {
                console.error('Error inserting order:', err);
                return res.status(500).send('Server error during order insertion');
            }

            const orderId = orderResults.insertId;

            items.forEach(item => {
                const itemQuery = 'INSERT INTO OrderItems (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)';
                db.query(itemQuery, [orderId, item.product_id, item.quantity, item.price], (err) => {
                    if (err) {
                        console.error('Error inserting order item:', err);
                        return res.status(500).send('Server error during order items insertion');
                    }
                });
            });

            // 3. Enviar la respuesta con el ID de la orden de PayPal y de la base de datos
            res.status(201).json({ orderID: order.result.id, localOrderId: orderId });
        });
    } catch (error) {
        console.error("Error creating PayPal order:", error);
        res.status(500).send('Error creating PayPal order');
    }
});


app.post('/capture-paypal-order', verifySession, async (req, res) => {
    console.log("capture-paypal-order endpoint hit");
    console.log("Order ID to Capture:", req.body.orderID);

    const { orderID } = req.body;
    const request = new paypal.orders.OrdersCaptureRequest(orderID);

    try {
        const capture = await paypalClient.execute(request);
        console.log("PayPal Order Captured:", capture.result);

        // Asume que el pago es exitoso
        const token = req.headers['authorization'].split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);

        const user_id = decoded.id;

        // Obtener el client_id usando el endpoint que ya tienes
        const clientResponse = await axios.get(`http://localhost:3001/client-by-user/${user_id}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const client_id = clientResponse.data.client_id;

        // Actualizar la orden en tu base de datos para marcarla como 'completed'
        const updateOrderQuery = `UPDATE orders SET status = 'completed' WHERE order_id = ?`;

        db.query(updateOrderQuery, [orderID], (err, result) => {
            if (err) {
                console.error('Error updating order status:', err);
                return res.status(500).json({ error: 'Error updating order status' });
            }

            res.status(200).json({ success: true, orderID });
        });

    } catch (error) {
        console.error("Error capturing PayPal order:", error);
        res.status(500).send('Error capturing PayPal order');
    }
});


app.post('/transactions', verifySession, (req, res) => {
    const { productId, quantity } = req.body;
    db.query('INSERT INTO Transactions (product_id, quantity) VALUES (?, ?)', [productId, quantity], (err, results) => {
        if (err) {
            console.error('Error creating transaction:', err);
            return res.status(500).send('Server error');
        }
        db.query('UPDATE Products SET stock = stock - ? WHERE product_id = ?', [quantity, productId], (updateErr) => {
            if (updateErr) {
                console.error('Error updating product stock:', updateErr);
                return res.status(500).send('Server error');
            }
            checkLowStock(productId);
            res.status(201).send('Transaction created and stock updated');
        });
    });
});

app.get('/transactions', verifySession, (req, res) => {
    const query = `
        SELECT t.*, c.pending_balance 
        FROM Transactions t
        JOIN Clients c ON t.client_id = c.client_id`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.get('/transactions/:clientId', verifySession, (req, res) => {
    const { clientId } = req.params;
    const query = 'SELECT * FROM Transactions WHERE client_id = ?';
    db.query(query, [clientId], (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.post('/transactions', verifySession, (req, res) => {
    const { client_id, order_date, item_description, quantity, unit_price } = req.body;
    const total_price = quantity * unit_price;
    const query = 'INSERT INTO Transactions (client_id, order_date, item_description, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [client_id, order_date, item_description, quantity, unit_price, total_price], (err, results) => {
        if (err) {
            console.error('Error al insertar transacción:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Transaction created');
    });
});

app.get('/generate-general-report', verifySession, (req, res) => {
    const query = `
        SELECT t.*, c.name AS client_name, c.pending_balance 
        FROM Transactions t
        JOIN Clients c ON t.client_id = c.client_id`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        const html = `
            <h1>Informe General de Transacciones</h1>
            <table border="1">
                <tr>
                    <th>ID Transacción</th>
                    <th>ID Cliente</th>
                    <th>Nombre del Cliente</th>
                    <th>Fecha del Pedido</th>
                    <th>Descripción del Artículo</th>
                    <th>Cantidad</th>
                    <th>Precio Unitario</th>
                    <th>Precio Total</th>
                    <th>Saldo Pendiente</th>
                </tr>
                ${results.map(transaction => `
                <tr>
                    <td>${transaction.transaction_id}</td>
                    <td>${transaction.client_id}</td>
                    <td>${transaction.client_name}</td>
                    <td>${transaction.order_date}</td>
                    <td>${transaction.item_description}</td>
                    <td>${transaction.quantity}</td>
                    <td>${transaction.unit_price}</td>
                    <td>${transaction.total_price}</td>
                    <td>${transaction.pending_balance}</td>
                </tr>`).join('')}
            </table>
        `;
        pdf.create(html).toStream((err, stream) => {
            if (err) {
                return res.status(500).send('Error generating PDF');
            }
            res.setHeader('Content-Type', 'application/pdf');
            stream.pipe(res);
        });
    });
});

app.get('/clients', verifySession, (req, res) => {
    db.query('SELECT * FROM Clients', (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send(results);
    });
});

app.get('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Clients WHERE client_id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('Client not found');
        res.status(200).send(results[0]);
    });
});

app.post('/clients', verifySession, (req, res) => {
    const { user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type } = req.body;

    db.query(
        'INSERT INTO Clients (user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
        [user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type], 
        (err, results) => {
            if (err) return res.status(500).send('Server error');
            res.status(201).send('Client added');
        }
    );
});

app.put('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type } = req.body;

    db.query(
        'UPDATE Clients SET name = ?, address = ?, contact_info = ?, client_type = ?, pending_balance = ?, identification_number = ?, email = ?, identification_type = ? WHERE client_id = ?', 
        [name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type, id], 
        (err, results) => {
            if (err) return res.status(500).send('Server error');
            res.status(200).send('Client updated');
        }
    );
});

app.delete('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM Clients WHERE client_id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send('Client deleted');
    });
});

app.get('/products', (req, res) => {
    const query = 'SELECT * FROM Products';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).send('Server error');
        }
        const products = results.map(product => ({
            ...product,
            image: product.image ? `http://localhost:3001/uploads/${product.image}` : null
        }));
        res.json(products);
    });
});

app.get('/products/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM Products WHERE product_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching product:', err);
            return res.status(500).send('Server error');
        }
        const product = results[0];
        product.image = product.image ? `http://localhost:3001/uploads/${product.image}` : null;
        res.json(product);
    });
});

app.post('/products', verifySession, (req, res) => {
    const { name, description, category, price, cost_price, stock, iva, discount } = req.body; // Añade cost_price

    let image = null;
    if (req.files && req.files.image) {
        const imageFile = req.files.image;
        image = Date.now() + path.extname(imageFile.name);
        imageFile.mv(path.join(__dirname, 'uploads', image), (err) => {
            if (err) {
                console.error('Error uploading image:', err);
                return res.status(500).send('Error uploading image');
            }
        });
    }

    const query = 'INSERT INTO Products (name, description, category, price, cost_price, stock, image, iva, discount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'; // Incluye cost_price en la consulta
    db.query(query, [name, description, category, price, cost_price, stock, image, iva, discount], (err, results) => { // Incluye cost_price en los valores
        if (err) {
            console.error('Error adding product:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Product added');
    });
});


app.put('/products/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, description, category, price, cost_price, stock, iva, discount } = req.body; // Añade cost_price

    let query = 'UPDATE Products SET name = ?, description = ?, category = ?, price = ?, cost_price = ?, stock = ?, iva = ?, discount = ?'; // Incluye cost_price en la consulta
    const values = [name, description, category, price, cost_price, stock, iva, discount]; // Incluye cost_price en los valores

    if (req.files && req.files.image) {
        const imageFile = req.files.image;
        const image = Date.now() + path.extname(imageFile.name);
        imageFile.mv(path.join(__dirname, 'uploads', image), (err) => {
            if (err) {
                console.error('Error uploading image:', err);
                return res.status(500).send('Error uploading image');
            }
        });
        query += ', image = ?';
        values.push(image);
    }

    query += ' WHERE product_id = ?';
    values.push(id);

    db.query(query, values, (err, results) => {
        if (err) {
            console.error('Error updating product:', err);
            return res.status(500).send('Server error');
        }
        res.send('Product updated');
    });
});


app.delete('/products/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Products WHERE product_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting product:', err);
            return res.status(500).send('Server error');
        }
        res.send('Product deleted');
    });
});

app.post('/orders', verifySession, (req, res) => {
    const { client_id, total_amount, items } = req.body;
    const query = 'INSERT INTO orders (client_id, order_date, status, total_amount) VALUES (?, NOW(), "pending", ?)';
    db.query(query, [client_id, total_amount], (err, results) => {
        if (err) {
            console.error('Error creating order:', err);
            return res.status(500).send('Server error');
        }
        const orderId = results.insertId;
        const orderItems = items.map(item => [orderId, item.product_id, item.description, item.quantity, item.unit_price]);
        const orderItemsQuery = 'INSERT INTO orderitems (order_id, product_id, description, quantity, unit_price) VALUES ?';
        db.query(orderItemsQuery, [orderItems], (err, results) => {
            if (err) {
                console.error('Error creating order items:', err);
                return res.status(500).send('Server error');
            }
            res.status(201).send('Order created');
        });
    });
});

app.get('/admin/orders', verifySession, (req, res) => {
    const query = 'SELECT * FROM orders';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching orders:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});



app.get('/users', verifySession, (req, res) => {
    const query = 'SELECT user_id, username, email, created_at, role FROM Users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.get('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'SELECT user_id, username, email, created_at, role FROM Users WHERE user_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results[0]);
    });
});

app.put('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { username, email, role } = req.body;
    const query = 'UPDATE Users SET username = ?, email = ?, role = ? WHERE user_id = ?';
    db.query(query, [username, email, role, id], (err, results) => {
        if (err) {
            console.error('Error al actualizar usuario:', err);
            return res.status(500).send('Server error');
        }
        res.send('User updated');
    });
});

app.delete('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Users WHERE user_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al eliminar usuario:', err);
            return res.status(500).send('Server error');
        }
        res.send('User deleted');
    });
});

app.get('/sales', verifySession, (req, res) => {
    const query = `
        SELECT 
            i.invoice_id AS sale_id, 
            i.issue_date AS sale_date, 
            i.total_amount 
        FROM 
            invoices i
        ORDER BY 
            i.issue_date DESC
    `;
    db.query(query, (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send(results);
    });
});

app.post('/sales', verifySession, (req, res) => {
    const { sale_date, total_amount, items } = req.body;

    db.query('INSERT INTO Sales (sale_date, total_amount) VALUES (?, ?)', [sale_date, total_amount], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }

        const sale_id = results.insertId;

        const saleItems = items.map(item => [sale_id, item.description, item.quantity, item.unit_price]);

        db.query('INSERT INTO SaleItems (sale_id, description, quantity, unit_price) VALUES ?', [saleItems], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Server error');
            }
            res.status(201).send('Sale added');
        });
    });
});

app.get('/generate-user-report', verifySession, (req, res) => {
    const { fields, filter } = req.query;

    const defaultFields = ['user_id', 'username', 'email', 'created_at', 'role'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM Users';
    if (filter) {
        query += ` WHERE ${filter}`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        const doc = new PDFDocument();
        const filePath = path.join(__dirname, 'user_report.pdf');
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        doc.fontSize(18).text('Informe de Usuarios', { align: 'center' });
        doc.moveDown();

        const tableTop = 100;
        const itemHeight = 20;

        doc.fontSize(12);
        selectedFields.forEach((field, index) => {
            doc.text(field.replace('_', ' ').toUpperCase(), 50 + index * 100, tableTop);
        });

        results.forEach((user, i) => {
            const y = tableTop + (i + 1) * itemHeight;
            selectedFields.forEach((field, index) => {
                doc.text(user[field], 50 + index * 100, y);
            });
        });

        doc.end();

        stream.on('finish', () => {
            res.download(filePath, 'user_report.pdf', (err) => {
                if (err) {
                    console.error('Error al descargar el archivo:', err);
                    res.status(500).send('Server error');
                } else {
                    fs.unlinkSync(filePath);
                }
            });
        });
    });
});

app.get('/generate-financial-report', verifySession, (req, res) => {
    const { start_date, end_date } = req.query;

    // Convertir las fechas actuales en objetos moment.js
    const startDate = moment(start_date);
    const endDate = moment(end_date);

    // Calcular las fechas del período anterior (en este caso, restando un mes)
    const previousPeriodStart = startDate.clone().subtract(1, 'month').format('YYYY-MM-DD');
    const previousPeriodEnd = endDate.clone().subtract(1, 'month').format('YYYY-MM-DD');

    console.log('Start Date:', start_date);
    console.log('End Date:', end_date);
    console.log('Previous Period Start:', previousPeriodStart);
    console.log('Previous Period End:', previousPeriodEnd);

    const revenueQuery = `
        SELECT SUM(i.total_amount) AS revenue
        FROM invoices i
        WHERE i.issue_date BETWEEN ? AND ?
    `;

    const costOfGoodsSoldQuery = `
        SELECT SUM(ii.quantity * p.cost_price) AS cost_of_goods_sold
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        WHERE ii.invoice_id IN (
            SELECT invoice_id FROM invoices WHERE issue_date BETWEEN ? AND ?
        )
    `;

    const operatingExpensesQuery = `
        SELECT SUM(amount) AS operating_expenses
        FROM expenses
        WHERE date BETWEEN ? AND ?
    `;

    const revenueByCategoryQuery = `
        SELECT p.category, SUM(ii.quantity * ii.unit_price) AS revenue
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        JOIN invoices i ON ii.invoice_id = i.invoice_id
        WHERE i.issue_date BETWEEN ? AND ?
        GROUP BY p.category
    `;

    const previousPeriodRevenueQuery = `
        SELECT SUM(i.total_amount) AS revenue
        FROM invoices i
        WHERE i.issue_date BETWEEN ? AND ?
    `;

    const previousPeriodCostOfGoodsSoldQuery = `
        SELECT SUM(ii.quantity * p.cost_price) AS cost_of_goods_sold
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        WHERE ii.invoice_id IN (
            SELECT invoice_id FROM invoices WHERE issue_date BETWEEN ? AND ?
        )
    `;

    const previousPeriodExpensesQuery = `
        SELECT SUM(amount) AS operating_expenses
        FROM expenses
        WHERE date BETWEEN ? AND ?
    `;

    const expensesByCategoryQuery = `
        SELECT category, SUM(amount) AS total_expense
        FROM expenses
        WHERE date BETWEEN ? AND ?
        GROUP BY category
    `;

    db.query(revenueQuery, [start_date, end_date], (err, revenueResults) => {
        if (err) return res.status(500).send('Error fetching revenue');

        db.query(costOfGoodsSoldQuery, [start_date, end_date], (err, cogsResults) => {
            if (err) return res.status(500).send('Error fetching cost of goods sold');

            db.query(operatingExpensesQuery, [start_date, end_date], (err, expensesResults) => {
                if (err) return res.status(500).send('Error fetching operating expenses');

                db.query(revenueByCategoryQuery, [start_date, end_date], (err, revenueByCategoryResults) => {
                    if (err) return res.status(500).send('Error fetching revenue by category');

                    db.query(expensesByCategoryQuery, [start_date, end_date], (err, expensesByCategoryResults) => {
                        if (err) return res.status(500).send('Error fetching expenses by category');

                        db.query(previousPeriodRevenueQuery, [previousPeriodStart, previousPeriodEnd], (err, previousRevenueResults) => {
                            if (err) return res.status(500).send('Error fetching previous revenue');

                            db.query(previousPeriodCostOfGoodsSoldQuery, [previousPeriodStart, previousPeriodEnd], (err, previousCogsResults) => {
                                if (err) return res.status(500).send('Error fetching previous cost of goods sold');

                                db.query(previousPeriodExpensesQuery, [previousPeriodStart, previousPeriodEnd], (err, previousExpensesResults) => {
                                    if (err) return res.status(500).send('Error fetching previous expenses');

                                    const revenue = revenueResults[0].revenue || 0;
                                    const costOfGoodsSold = cogsResults[0].cost_of_goods_sold || 0;
                                    const operatingExpenses = expensesResults[0].operating_expenses || 0;
                                    const grossProfit = revenue - costOfGoodsSold;
                                    const netIncome = grossProfit - operatingExpenses;

                                    const revenueByCategory = revenueByCategoryResults.map(row => ({
                                        category: row.category,
                                        revenue: row.revenue,
                                    }));

                                    const expensesByCategory = expensesByCategoryResults.map(row => ({
                                        category: row.category,
                                        total_expense: row.total_expense,
                                    }));

                                    const previousRevenue = previousRevenueResults[0].revenue || 0;
                                    const previousCostOfGoodsSold = previousCogsResults[0].cost_of_goods_sold || 0;
                                    const previousOperatingExpenses = previousExpensesResults[0].operating_expenses || 0;
                                    const previousGrossProfit = previousRevenue - previousCostOfGoodsSold;
                                    const previousNetIncome = previousGrossProfit - previousOperatingExpenses;

                                    const financialReport = {
                                        revenue,
                                        costOfGoodsSold,
                                        grossProfit,
                                        operatingExpenses,
                                        netIncome,
                                        revenueByCategory,
                                        expensesByCategory,
                                        previousRevenue,
                                        previousCostOfGoodsSold,
                                        previousOperatingExpenses,
                                        previousNetIncome,
                                    };

                                    res.json(financialReport);
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});


// Ruta para obtener todos los gastos operativos
app.get('/expenses', verifySession, (req, res) => {
    const query = 'SELECT * FROM expenses';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching expenses:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

// Ruta para agregar un nuevo gasto operativo
app.post('/expenses', verifySession, (req, res) => {
    const { description, amount, date, category } = req.body;
    const query = 'INSERT INTO expenses (description, amount, date, category) VALUES (?, ?, ?, ?)';
    db.query(query, [description, amount, date, category], (err, results) => {
        if (err) {
            console.error('Error adding expense:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Expense added');
    });
});


app.put('/expenses/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { description, amount, date, category } = req.body;
    const query = 'UPDATE expenses SET description = ?, amount = ?, date = ?, category = ? WHERE expense_id = ?';
    db.query(query, [description, amount, date, category, id], (err, results) => {
        if (err) {
            console.error('Error updating expense:', err);
            return res.status(500).send('Server error');
        }
        res.send('Expense updated');
    });
});

app.delete('/expenses/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM expenses WHERE expense_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting expense:', err);
            return res.status(500).send('Server error');
        }
        res.send('Expense deleted');
    });
});


app.get('/generate-client-report', verifySession, (req, res) => {
    const { start_date, end_date } = req.query;

    // Convertir las fechas en objetos moment.js
    const startDate = moment(start_date);
    const endDate = moment(end_date);

    console.log('Start Date:', start_date);
    console.log('End Date:', end_date);

    const clientQuery = `
        SELECT user_id, name, address, contact_info, client_type
        FROM Clients
        WHERE created_at BETWEEN ? AND ?
    `;

    const clientTypeQuery = `
        SELECT client_type, COUNT(*) AS count
        FROM Clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY client_type
    `;

    db.query(clientQuery, [start_date, end_date], (err, clientResults) => {
        if (err) return res.status(500).send('Error fetching clients');

        db.query(clientTypeQuery, [start_date, end_date], (err, clientTypeResults) => {
            if (err) return res.status(500).send('Error fetching client types');

            const clientReport = {
                clients: clientResults,
                clientTypes: clientTypeResults,
            };

            res.json(clientReport);
        });
    });
});

app.get('/generate-ventas-report', verifySession, (req, res) => {
    const { fields, description, start_date, end_date } = req.query;

    const defaultFields = ['i.invoice_id', 'ii.description', 'ii.quantity', 'ii.unit_price'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = `
        SELECT ${selectedFields.join(', ')}
        FROM invoiceitems ii
        JOIN invoices i ON ii.invoice_id = i.invoice_id
        WHERE 1=1
    `;

    if (description) {
        query += ` AND ii.description LIKE '%${description}%'`;
    }
    if (start_date) {
        query += ` AND i.issue_date >= '${start_date}'`;
    }
    if (end_date) {
        query += ` AND i.issue_date <= '${end_date}'`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        const doc = new PDFDocument();
        const filePath = path.join(__dirname, 'sales_report.pdf');
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        doc.fontSize(18).text('Informe de Ventas', { align: 'center' });
        doc.moveDown();

        const tableTop = 100;
        const itemHeight = 20;

        doc.fontSize(12);
        selectedFields.forEach((field, index) => {
            doc.text(field.replace('_', ' ').toUpperCase(), 50 + index * 100, tableTop);
        });

        results.forEach((item, i) => {
            const y = tableTop + (i + 1) * itemHeight;
            selectedFields.forEach((field, index) => {
                doc.text(item[field], 50 + index * 100, y);
            });
        });

        doc.end();

        stream.on('finish', () => {
            res.download(filePath, 'sales_report.pdf', (err) => {
                if (err) {
                    console.error('Error al descargar el archivo:', err);
                    res.status(500).send('Server error');
                } else {
                    fs.unlinkSync(filePath);
                }
            });
        });
    });
});

app.get('/generate-inventory-report', verifySession, (req, res) => {
    const { fields, name, category, price_min, price_max } = req.query;

    const selectedFields = fields ? fields.split(',') : ['product_id', 'name', 'stock', 'price'];

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM products WHERE 1=1';

    if (name) {
        query += ` AND name LIKE '%${name}%'`;
    }
    if (category) {
        query += ` AND category = '${category}'`;
    }
    if (price_min && price_max) {
        query += ` AND price BETWEEN ${price_min} AND ${price_max}`;
    }

    db.query(query, (err, products) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).send('Server error');
        }

        const doc = new PDFDocument();
        const filePath = path.join(__dirname, 'inventory_report.pdf');

        doc.pipe(fs.createWriteStream(filePath));

        doc.fontSize(25).text('Reporte de Inventario', {
            align: 'center'
        });

        doc.moveDown();

        products.forEach(product => {
            selectedFields.forEach(field => {
                doc.fontSize(12).text(`${field.replace('_', ' ').toUpperCase()}: ${product[field]}`);
            });
            doc.moveDown();
        });

        doc.end();

        doc.on('end', () => {
            res.download(filePath, 'inventory_report.pdf', (err) => {
                if (err) {
                    console.error('Error downloading the report:', err);
                    return res.status(500).send('Server error');
                }
                fs.unlinkSync(filePath); // Eliminar el archivo después de ser descargado
            });
        });
    });
});

app.get('/suppliers', verifySession, (req, res) => {
    db.query('SELECT * FROM Suppliers', (err, results) => {
        if (err) {
            console.error('Error fetching suppliers:', err);
            res.status(500).send('Server error');
            return;
        }
        res.json(results);
    });
});

app.get('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Suppliers WHERE supplier_id = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching supplier:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Supplier not found');
        }
        res.json(results[0]);
    });
});

app.post('/suppliers', verifySession, (req, res) => {
    const { name, contact, address, payment_terms } = req.body;
    const query = 'INSERT INTO Suppliers (name, contact, address, payment_terms) VALUES (?, ?, ?, ?)';
    db.query(query, [name, contact, address, payment_terms], (err, results) => {
        if (err) {
            console.error('Error adding supplier:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Supplier added');
    });
});

app.put('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, contact, address, payment_terms } = req.body;
    const query = 'UPDATE Suppliers SET name = ?, contact = ?, address = ?, payment_terms = ? WHERE supplier_id = ?';
    db.query(query, [name, contact, address, payment_terms, id], (err, results) => {
        if (err) {
            console.error('Error updating supplier:', err);
            return res.status(500).send('Server error');
        }
        res.send('Supplier updated');
    });
});

app.delete('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Suppliers WHERE supplier_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting supplier:', err);
            return res.status(500).send('Server error');
        }
        res.send('Supplier deleted');
    });
});




app.get('/admin/orders', verifySession, (req, res) => {
    const query = 'SELECT * FROM Orders';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching orders:', err);
            return res.status(500).send('Server error');
        }
        res.status(200).json(results);
    });
});

app.get('/admin/orders/:orderId', verifySession, (req, res) => {
    const orderId = req.params.orderId;
    
    const orderQuery = `
        SELECT orders.*, clients.name AS client_name, clients.address, clients.email, clients.contact_info
        FROM orders
        JOIN clients ON orders.client_id = clients.client_id
        WHERE orders.order_id = ?
    `;
    
    const itemsQuery = `
        SELECT orderitems.*, products.name AS product_name
        FROM orderitems
        JOIN products ON orderitems.product_id = products.product_id
        WHERE orderitems.order_id = ?
    `;
    
    db.query(orderQuery, [orderId], (err, orderResult) => {
        if (err) {
            console.error('Error fetching order details:', err);
            return res.status(500).send('Error fetching order details');
        }
        if (orderResult.length === 0) {
            return res.status(404).send('Order not found');
        }

        const order = orderResult[0];

        db.query(itemsQuery, [orderId], (err, itemsResult) => {
            if (err) {
                console.error('Error fetching order items:', err);
                return res.status(500).send('Error fetching order items');
            }
            order.items = itemsResult;
            res.json(order);
        });
    });
});


app.put('/admin/orders/:orderId/approve', verifySession, (req, res) => {
    const orderId = req.params.orderId;

    const updateOrderQuery = `UPDATE orders SET status = 'completed' WHERE order_id = ?`;

    db.query(updateOrderQuery, [orderId], (err, result) => {
        if (err) {
            console.error('Error updating order status:', err);
            return res.status(500).json({ error: 'Error updating order status' });
        }

        const getOrderDetailsQuery = `
            SELECT o.*, c.name AS client_name, c.email, c.address, c.contact_info,
                   oi.product_id, p.name AS product_name, oi.quantity, oi.unit_price, p.discount
            FROM orders o
            JOIN clients c ON o.client_id = c.client_id
            JOIN orderitems oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.product_id
            WHERE o.order_id = ?
        `;

        db.query(getOrderDetailsQuery, [orderId], (err, orderDetails) => {
            if (err) {
                console.error('Error fetching order details:', err);
                return res.status(500).json({ error: 'Error fetching order details' });
            }
            if (orderDetails.length === 0) {
                return res.status(404).send('Order not found');
            }

            const order = orderDetails[0];

            const createInvoiceQuery = `
                INSERT INTO invoices (client_id, order_id, issue_date, due_date, total_amount, status, payment_method)
                VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), ?, 'approved', ?)
            `;

            db.query(createInvoiceQuery, [order.client_id, orderId, order.total_amount, 'not specified'], (err, invoiceResult) => {
                if (err) {
                    console.error('Error creating invoice:', err);
                    return res.status(500).json({ error: 'Error creating invoice' });
                }

                const invoiceId = invoiceResult.insertId;

                const invoiceItems = orderDetails.map(item => [
                    invoiceId, item.product_id, item.product_name, item.quantity, item.unit_price, item.discount, (item.unit_price * item.quantity)
                ]);

                const insertInvoiceItemsQuery = `
                    INSERT INTO invoiceitems (invoice_id, product_id, description, quantity, unit_price, discount, subtotal)
                    VALUES ?
                `;

                db.query(insertInvoiceItemsQuery, [invoiceItems], (err) => {
                    if (err) {
                        console.error('Error inserting invoice items:', err);
                        return res.status(500).json({ error: 'Error inserting invoice items' });
                    }

                    // Generar el PDF de la factura
                    const doc = new PDFDocument();
                    const pdfPath = path.join(__dirname, `factura_${invoiceId}.pdf`);
                    doc.pipe(fs.createWriteStream(pdfPath));

                    doc.fontSize(25).text('Factura Electrónica', { align: 'center' });
                    doc.moveDown();
                    doc.fontSize(14).text(`Factura ID: ${invoiceId}`);
                    doc.text(`Fecha: ${new Date().toLocaleDateString()}`);
                    doc.moveDown();
                    doc.text(`Cliente: ${order.client_name}`);
                    doc.text(`Dirección: ${order.address}`);
                    doc.text(`Email: ${order.email}`);
                    doc.text(`Teléfono: ${order.contact_info}`);
                    doc.moveDown();
                    doc.text('Detalles de la Orden:', { underline: true });

                    invoiceItems.forEach((item, index) => {
                        doc.text(`${index + 1}. Producto: ${item[2]}`);
                        doc.text(`Cantidad: ${item[3]}`);
                        doc.text(`Precio Unitario: ${item[4]}`);
                        doc.text(`Descuento: ${item[5]}`);
                        doc.text(`Subtotal: ${item[6]}`);
                        doc.moveDown();
                    });

                    doc.text(`Total: ${order.total_amount}`, { align: 'right' });
                    doc.end();

                    const mailOptions = {
                        from: 'duant75@gmail.com',
                        to: order.email,
                        subject: `Factura de su orden #${orderId}`,
                        text: `Estimado ${order.client_name},\n\nAdjunto encontrará la factura de su orden.\n\nGracias por su compra.`,
                        attachments: [
                            {
                                filename: `Factura_${invoiceId}.pdf`,
                                path: pdfPath,
                                contentType: 'application/pdf'
                            }
                        ]
                    };                

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.error('Error sending email:', error);
                            return res.status(500).json({ error: 'Error sending email' });
                        }
                        console.log('Email sent: ' + info.response);
                        res.json({ success: true, invoiceId });
                    });
                });
            });
        });
    });
});


app.get('/admin/invoices', verifySession, (req, res) => {
    const query = `
        SELECT 
            i.invoice_id, 
            i.issue_date, 
            i.due_date, 
            i.total_amount, 
            i.status, 
            i.payment_method, 
            i.tax, 
            i.subtotal, 
            o.order_id, 
            c.name AS client_name, 
            c.email AS client_email
        FROM invoices i
        JOIN orders o ON i.order_id = o.order_id
        JOIN clients c ON i.client_id = c.client_id
        WHERE i.order_id IS NOT NULL
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching invoices:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.get('/invoice/:id', verifySession, (req, res) => {
    const invoiceId = req.params.id;

    const queryInvoiceDetails = `
    SELECT 
        i.invoice_id, 
        i.issue_date, 
        i.due_date, 
        i.total_amount, 
        i.status, 
        i.payment_method, 
        i.tax, 
        i.subtotal, 
        c.name AS client_name, 
        c.identification_number AS client_identification, 
        c.address, 
        c.contact_info
    FROM invoices i
    JOIN clients c ON i.client_id = c.client_id
    WHERE i.invoice_id = ?
`;


    const queryInvoiceItems = `
        SELECT 
            ii.item_id, 
            ii.description, 
            ii.quantity, 
            ii.unit_price, 
            ii.subtotal 
        FROM invoiceitems ii
        WHERE ii.invoice_id = ?
    `;

    db.query(queryInvoiceDetails, [invoiceId], (err, invoiceResult) => {
        if (err) {
            console.error('Error fetching invoice details:', err);
            return res.status(500).json({ error: 'Error fetching invoice details' });
        }

        if (invoiceResult.length === 0) {
            return res.status(404).send('Invoice not found');
        }

        const invoice = invoiceResult[0];

        db.query(queryInvoiceItems, [invoiceId], (err, itemsResult) => {
            if (err) {
                console.error('Error fetching invoice items:', err);
                return res.status(500).json({ error: 'Error fetching invoice items' });
            }

            res.json({ invoice, items: itemsResult });
        });
    });
});


app.get('/client-by-user/:user_id', async (req, res) => {  // Corregido: Se eliminó la coma innecesaria
    const { user_id } = req.params;
    db.query('SELECT * FROM Clients WHERE user_id = ?', [user_id], (err, results) => {
        if (err) {
            console.error('Error fetching client by user_id:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Client not found');
        }
        res.json(results[0]);
    });
});



app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
