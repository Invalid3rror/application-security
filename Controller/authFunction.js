const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require('crypto');
require('dotenv').config();
const Member = require("../Database/member");
const FailedLogin = require("../Database/antibruteforce");

// All URLs for emails/links are now built from PUBLIC_BASE_URL only.
// getRequestBaseUrl is no longer needed.

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        // Gmail App Passwords are often shown with spaces (e.g. "abcd efgh ijkl mnop").
        // Strip whitespace so either format works.
        pass: (process.env.EMAIL_PASS || '').replace(/\s+/g, '')
    }
});

const memberSignup = async (req, role, res) => {
    try{
        const body = (req && req.body) ? req.body : req;
        // No longer needed: const requestBaseUrl = getRequestBaseUrl(req);

        // preventing null values
        if (!body?.name || !body?.email || !body?.password) {
            return res.status(400).json({
                message: "Name, email, and password are required."
            });
        }

        if (!/^.{5,30}$/.test(body.name)){
            return res.status(400).json({
                message: `Username must be between 5 and 30 characters long.`
            });
        }

        const isStrongPassword = await validateStrongPassword(body.password);
        if (!isStrongPassword.valid) {
            return res.status(400).json({
                message: isStrongPassword.message
            });
        }

        let nameNotTaken = await validateMemberName(body.name);
        if (!nameNotTaken) {
            return res.status(400).json({
                message: `Member is already registered.`
            });
        }

        let emailValidation = await validateEmail(body.email);
        if (!emailValidation.valid) {
            return res.status(400).json({
                message: emailValidation.message
            })
        }


        // Generate verification token
        const verificationToken = jwt.sign(
            { email: body.email },
            process.env.VERIFICATION_SECRET,
            { expiresIn: "1d" } // Token expires in 1 day
        );

        // Create new member instance
        const newMember = new Member({
            ...body,
            password: await bcrypt.hash(body.password, 12),
            role,
            verificationToken
        });

        // Save new member to database
        await newMember.save();

        // Send verification email
        await sendVerificationEmail(newMember.email, verificationToken);

        return res.status(201).json({
            message: "Please verify your email address to complete registration."
        });
    } catch (err) {
        return res.status(500).json({
            message: `Error: ${err.message}`
        });
    }
};

const validateStrongPassword = async (password) => {
    // Define password strength criteria
    const minLength = 8;

    if (password.length < minLength) {
        return { valid: false, message: "Password must be at least 8 characters long."};
    }
    if (/\s/.test(password)) {
        return { valid: false, message: "Password must not contain any whitespace characters." };
    }

    //check character types
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSpecialChars =/[^a-zA-Z0-9]/.test(password);

    if (!(hasUppercase && hasLowercase && hasDigits && hasSpecialChars)) {
        const missingTypes = [];
        if (!hasUppercase) missingTypes.push("uppercase letters");
        if (!hasLowercase) missingTypes.push("lowercase letters");
        if (!hasDigits) missingTypes.push("digits");
        if (!hasSpecialChars) missingTypes.push("special characters");

        return { valid: false, message: `Password is not strong enough. Please include ${missingTypes.join(", ")} in your password.`};
    }

    return {valid: true};
};

const validateMemberName = async name => {
    let member = await Member.findOne({name});
    return member ? false : true;
};

const validateEmail = async email => {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailPattern.test(email)) {
        return { valid: false, message: "Email is not valid. Please enter a valid email address." };
    }
    let member = await Member.findOne({ email });
    if (member) {
        return { valid: false, message: "Email is already registered." };
    }
    return { valid: true };
};

const sendVerificationEmail = async (email, token) => {
    const baseUrl = process.env.PUBLIC_BASE_URL;
    if (!baseUrl) throw new Error('PUBLIC_BASE_URL must be set in environment for email links.');
    const verificationLink = `${baseUrl}/verify/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Verify Your Email Address",
        html: `<p>Please click <a href="${verificationLink}">here</a> to verify your email address.</p>`
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
};

const maxFailedAttempts = 5;
const lockoutDuration = 10 * 60; // 10 minutes
const maxIncorrectRoleAttempts = 3; // Set the allowed limit for incorrect role attempts

const handleLockout = async (memberName, incorrectRoleAttempts, failedAttempts) => {
    let lockoutExpiration = Date.now() + lockoutDuration * 1000; // Convert lockout duration to milliseconds
    await FailedLogin.findOneAndUpdate(
        { memberName },
        { incorrectRoleAttempts, failedAttempts, lockoutExpiration },
        { upsert: true, new: true }
    );
};

const updateAttempts = async (memberName, field, value) => {
    await FailedLogin.findOneAndUpdate(
        { memberName },
        { [field]: value },
        { upsert: true, new: true }
    );
};

const memberLogin = async (req, role, res) => {
    let { identifier, password } = req; // Change 'name' to 'identifier' to handle both name and email

    // Preventing null values
    if (!identifier || !password) {
        return res.status(400).json({
            message: "Name or email and password are required."
        });
    }
    console.log(identifier, password);

    // Determine if identifier is an email or a name
    let member;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) {
        member = await Member.findOne({ email: identifier });
    } else {
        member = await Member.findOne({ name: identifier });
    }

    // Check if member exists
    if (!member) {
        return res.status(404).json({
            message: "Login failed; Invalid user ID or password."
        });
    }
        // Check if email is verified
        if (!member.verified) {
            return res.status(403).json({
                message: "Email not verified. Please check your email for the verification link."
            });
        }
        
    // Find failed login attempt record by member name
    const failedLogin = await FailedLogin.findOne({ memberName: member.name });

    // Check if account is locked
    if (failedLogin && failedLogin.lockoutExpiration && Date.now() < failedLogin.lockoutExpiration) {
        return res.status(429).json({
            message: "Account locked. Please try again later."
        });
    }

    // Check if role matches
    if (member.role !== role) {
        // Increment incorrect role attempts
        let incorrectRoleAttempts = failedLogin ? failedLogin.incorrectRoleAttempts + 1 : 1;
        if (incorrectRoleAttempts >= maxIncorrectRoleAttempts) {
            await handleLockout(member.name, incorrectRoleAttempts, failedLogin ? failedLogin.failedAttempts : 0);
            return res.status(429).json({
                message: `Account locked due to incorrect role selection. Please try again in ${lockoutDuration} seconds.`
            });
        } else {
            await updateAttempts(member.name, 'incorrectRoleAttempts', incorrectRoleAttempts);
            return res.status(403).json({
                message: "Please make sure you are logging in from the right role."
            });
        }
    }

    // Compare passwords
    let isMatch = await bcrypt.compare(password, member.password);
    if (isMatch) {
        // Reset failed login attempts and lockout expiration
        await FailedLogin.findOneAndUpdate(
            { memberName: member.name },
            { failedAttempts: 0, incorrectRoleAttempts: 0, lockoutExpiration: null },
            { upsert: true, new: true }
        );

        // Require OTP after password check.
        // This flag represents "OTP pending" for the next step.
        await Member.findByIdAndUpdate(member._id, { requiresOTPVerification: true });

        return res.status(200).json({
            message: "OTP required",
            userId: member._id
        });
    } else {
        // Update failed login attempts
        let failedAttempts = failedLogin ? failedLogin.failedAttempts + 1 : 1;
        if (failedAttempts >= maxFailedAttempts) {
            await handleLockout(member.name, failedLogin ? failedLogin.incorrectRoleAttempts : 0, failedAttempts);
            return res.status(429).json({
                message: `Account locked. Please try again in ${lockoutDuration} seconds.`
            });
        } else {
            await updateAttempts(member.name, 'failedAttempts', failedAttempts);
            return res.status(403).json({
                message: "Incorrect username or password"
            });
        }
    }
};

const memberAuth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({
            message: "Missing Token"
        });
    const token = authHeader.split(' ')[1];
    jwt.verify(
        token,
        process.env.APP_SECRET,
        (err, decoded) => {
            if (err) return res.status(403).json({
                    message: "Wrong Token"
                });
            console.log(decoded.name);
            req.name = decoded.name;
            next();
        },
    );
}

const checkRole = roles => async (req, res, next) => {
    let { name } = req;
    const member = await Member.findOne({ name });
    !roles.includes(member.role)
        ? res.status(401).json("Sorry you do not have access to this route")
        : next();
}

// OTP Functions
const generateOTP = () => {
    return Math.floor(1000 + Math.random() * 9000).toString();
};

const hashOTP = (otp) => {
    return crypto.createHash('sha256').update(otp).digest('hex');
};

const storeOTP = async (userId) => {
    try {
        const otp = generateOTP();
        const hashedOTP = hashOTP(otp);
        const otpExpires = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes from now

        const member = await Member.findByIdAndUpdate(userId, {
            otp: hashedOTP,
            otpExpires: otpExpires,
            requiresOTPVerification: true
        }, { new: true });

        if (!member) {
            throw new Error('User not found');
        }

        console.log(`Generated OTP: ${otp} for user: ${member.email}`);
        await sendOTPEmail(member.email, otp);
        console.log(`OTP sent to email: ${member.email}`);
    } catch (err) {
        console.error(`Error in storeOTP: ${err.message}`);
        throw err;
    }
};

const sendOTPEmail = async (email, otp) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It will expire in 2 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to: ${email}`);
    } catch (err) {
        console.error(`Error in sendOTPEmail: ${err.message}`);
        throw err;
    }
};

const verifyOTP = async (userId, otp, role, token) => {
    const member = await Member.findById(userId);
    if (!member) {
        return false; // User not found
    }

    const hashedOTP = hashOTP(otp);
    if (member.otp !== hashedOTP || new Date() > member.otpExpires) {
        return false; // Invalid or expired OTP
    }

    // Clear OTP fields after successful verification
    await Member.findByIdAndUpdate(userId, {
        otp: null,
        otpExpires: null,
        requiresOTPVerification: false
    });

    return true;
};

module.exports = {
    memberSignup,
    memberLogin,
    checkRole,
    memberAuth,
    generateOTP,
    storeOTP,
    verifyOTP
};