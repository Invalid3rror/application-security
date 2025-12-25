require('dotenv').config(); // Load environment variables

const mongoose = require('mongoose');
const express = require('express');
const path = require('path');
const userRouter = require('./route/userRouter');

// Connecting to MongoDB
mongoose.connect(process.env.DB_CONNECT || process.env.DB_connect)
    .then(() => {
        console.log('MongoDB connected...');
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
    });

const app = express();
// Trust reverse proxy headers (needed for correct req.protocol on many hosts)
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));
app.use('', userRouter);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server started on ${PORT}`);
    if (process.env.PUBLIC_BASE_URL) {
        console.log(`Click here to access ${process.env.PUBLIC_BASE_URL}`);
    } else {
        console.log(`Click here to access http://localhost:${PORT}`);
    }
});
