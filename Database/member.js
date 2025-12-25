// const { verify } = require("jsonwebtoken");
const { Schema, model } = require("mongoose");

const MemberSchema = new Schema(
    {
        name: {
            type: String,
            required: true
        },
        email: {
            type: String,
            required: true
        },
        role: {
            type: String,
            enum: ["admin", "merchant", "logistic", "member"]
        },
        password: {
            type: String,
            required: true
        },
        verified: {
            type: Boolean,
            default: false
        },
        verificationToken: {
            type: String
        },
        otp: {
            type: String,
            default: null
        },
        otpExpires: {
            type: Date,
            default: null
        },
        requiresOTPVerification: {
            type: Boolean,
            default: false
        }
    },
    { timestamps: true }
);

module.exports = model("member", MemberSchema)