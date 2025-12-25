const { Schema, model } = require("mongoose");

const failedLoginSchema = new Schema({
    memberName: {
        type: String,
        required: true,
        unique: true
    },
    failedAttempts: {
        type: Number,
        default: 0
    },
    incorrectRoleAttempts: { 
        type: Number,
        default: 0 
    },

    lockoutExpiration: {
        type: Date,
        default: null
    }
});

module.exports = model("FailedLogin", failedLoginSchema)