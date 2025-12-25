const router = require('express').Router();
const jwt = require('jsonwebtoken'); // Import jsonwebtoken
const Member = require('../Database/member'); // Import your Member model
const {
   
    memberSignup, memberLogin, memberAuth, checkRole, storeOTP,verifyOTP
 
} = require("../Controller/authFunction");

// Route to generate OTP and send to user
router.post('/generate-otp', async (req, res) => {
    const { userId } = req.body;

    try {
        await storeOTP(userId);
        res.status(200).json({ message: 'OTP sent to user' });
    } catch (err) {
        res.status(500).json({ message: 'Failed to generate OTP', error: err.message });
    }
});

// Route to verify OTP
router.post('/verify-otp', async (req, res) => {
    const { userId, otp, role } = req.body;

    try {
        const isVerified = await verifyOTP(userId, otp);
        if (isVerified) {
            // Generate a new token for the verified user
            const member = await Member.findById(userId);
            if (!member) {
                return res.status(404).json({ message: 'User not found' });
            }

            const token = jwt.sign(
                {
                    role: member.role,
                    name: member.name,
                    email: member.email
                },
                process.env.APP_SECRET,
                { expiresIn: "1h" }
            );

            res.status(200).json({ 
                message: 'OTP verified',
                token: token,
                role: member.role,
                name: member.name,
                email: member.email
            });
        } else {
            res.status(400).json({ message: 'Invalid or expired OTP' });
        }
    } catch (err) {
        res.status(500).json({ message: 'Failed to verify OTP', error: err.message });
    }
});

//routes to register
router.post("/register-member", (req,res) => {
    memberSignup(req, "member", res);
});
 
router.post ("/register-admin", async (req,res) => {
    await memberSignup(req, "admin", res);
});

router.post ("/register-logistic", async (req,res) => {
    await memberSignup(req, "logistic", res);
});

router.post ("/register-merchant", async (req,res) => {
    await memberSignup(req, "merchant", res);
});
 
// routes to login
router.post("/login-member", async (req, res) => {
    await memberLogin(req.body, "member", res);
});
 
router.post("/login-admin", async (req,res) => {
    await memberLogin(req.body, "admin", res);
});
 
router.post("/login-logistic", async (req,res) => {
    await memberLogin(req.body, "logistic", res);
});

router.post("/login-merchant", async (req, res) => {
    await memberLogin(req.body, "merchant", res);
});

router.get(
    "/public", (req, res) => {
        return res.status(200).json("Public Domian");
    });

// routes for protected resources
router.get(
    "/member-protected",
    memberAuth,
    checkRole(["member"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);
router.get(
    "/admin-protected",
    memberAuth,
    checkRole(["admin"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);
router.get(
    "/logistic-protected",
    memberAuth,
    checkRole(["logistic"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);
router.get(
    "/merchant-protected",
    memberAuth,
    checkRole(["merchant"]),
    async (req, res) => {
        return res.json(`welcome ${req.name}`);
    }
);
router.get('/verify/:token', async (req, res) => {
    const token = req.params.token;

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.VERIFICATION_SECRET);
        console.log(`Token decoded: ${JSON.stringify(decoded)}`); // Add logging

        // Find member by email and update verified status
        const member = await Member.findOneAndUpdate(
            { email: decoded.email },
            { verified: true, verificationToken: null }, // Mark user as verified and remove verification token
            { new: true }
        );

        if (!member) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        return res.redirect('/login.html'); // Redirect to login page or send success message
    } catch (err) {
            console.error(`Token verification error: ${err.message}`); // Add logging
    }
});


module.exports = router;



