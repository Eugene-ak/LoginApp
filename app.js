const express = require("express");
const mongoose = require("mongoose");
const validator = require("validator");
const dotenv = require("dotenv").config();
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Database Connection
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true })
.then(() => {
    app.listen(3001, () => {
        console.log("Login App running on port 3001");
    });
})
.catch((err) => {
    console.log(err);
});

// User Model
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "Please enter your email"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, "Please enter a valid email"]
    },
    password: {
        type: String,
        required: [true, "Please enter your password"],
        minlength: 6
    },
    photo: String
});

// Execute a function using mongoose hooks before saving document to database
userSchema.pre("save", async function (next) {

    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);

    next();

});

// Static function to login users
userSchema.statics.login = async function(email, password) {

    const user = await this.findOne({email});
    if (user) {

        const auth = await bcrypt.compare(password, user.password);
        if (auth) {
            return user;
        }
        throw Error("Incorrect password");

    }
    throw Error("Incorrect email");
}

// Create user model
const User = mongoose.model("user", userSchema);

// Create token function
const createToken = (id) => {
    return jwt.sign({id}, process.env.SECRET_STRING, {
        expiresIn: 60 * 60 * 12
    });
}

// Handle errors
const handleErrors = (err) => {
    console.log(err.message, err.code);
    let errors = { email: "", password: "" };

    // Incorrect emails
    if (err.message === "Incorrect email") {
        errors.email = "Email not registered. Please try signing up";
    }

    // Incorrect passwords
    if (err.message === "Incorrect password") {
        errors.password = "Incorrect password";
    }

    // Duplicate error code
    if (err.code === 11000) {
        errors.email = "That email is already registered";
    }

    // Validation errors
    if(err.message.includes("user validation failed")) {
        Object.values(err.errors).forEach(({properties}) => {
            errors[properties.path] = properties.mesasage;
        });
    }

    return errors;
}

// Function to protect routes
const requireAuth = (req, res, next) => {
    const token = req.cookies.jwt;

    if (token) {
        jwt.verify(token, process.env.SECRET_STRING, (err, decodedToken) => {
            if (err) {
                console.log(err.message);
                res.redirect("/login");
            } else {
                console.log(decodedToken);
                next();
            }
        });
    } else {
        res.redirect("/login");
    }

}

// Routes
app.get("/signup", (req, res) => {
    res.status(200).send("Sign Up page");
});

app.post("/signup", async (req, res) => {

    const { email, password } = req.body;

    try {

        const newUser = await User.create({email, password});
        const token = createToken(newUser._id);
        res.cookie("jwt", token, {httpOnly: true, maxAge: (60 * 60 * 12) * 1000})

        res.status(201).json({user: newUser._id});

    } catch (err) {

        res.send(err.message);

    }

});

app.get("/login", (req, res) => {
    res.send("Please log in");
});

app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    try {
        const user = await User.login(email, password);
        const token = createToken(user._id);
        res.cookie("jwt", token, {
            maxAge: (60 * 60 * 12) * 1000,
            httpOnly: true
        });
        res.status(200).json({user: user._id});
    } catch (err) {
        const errors = handleErrors(err);
        res.status(400).json({errors});
    }
});

app.get("/resetPassword", requireAuth, (req, res) => {
    res.send("Resetting password page");
});

app.get("/changePassword", requireAuth, (req, res) => {
    res.send("Change password page");
});

app.patch("/changePassword", requireAuth, async (req, res) => {
    let { email, newPassword } = req.body;

    try {

        let user = await User.findOne({ email });
        
        const p = await bcrypt.compare(newPassword, user.password);
        if (p) {

            res.send("Password already in use");

        } else {

            const salt = await bcrypt.genSalt();
            newPassword = await bcrypt.hash(newPassword, salt);
            user = await User.updateOne({email}, {$set: {password: newPassword}});
            res.status(201).send("Password changed successfully");

        }
        
    } catch (err) {

        res.send("Password not updated. Perhaps user record couldn't be found.");

    }
    
});

app.get("/uploadPhoto", requireAuth, (req, res) => {
    res.send("Page to upload profile picture");
});

app.put("/uploadPhoto", requireAuth, async (req, res) => {
    const { email, photo } = req.body;

    try {

    let user = await User.findOne({email});
    if (user) {
        user = await User.updateOne({email}, {$set: {photo: photo}});
        res.status(200).send("Uploaded photo successfully");
    } else {
        res.send("Record of user not found");
    }

    } catch (err) {

        console.log(err.message);
        res.send("Couldn't upload profile picture");

    }

});

app.get("/logout", (req, res) => {
    res.cookie("jwt", "", { maxAge: 1 });
    res.send("Logged out");
});
