import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from "../config/emailtEmplates.js";


export const register = async (req, res) => {

    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: "All fields are required" });

    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: "user already exists" })
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new userModel({ name, email, password: hashedPassword })
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        //? welcomr mail
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to our app",
            text: `Hello ${name}, welcome to our app. We are glad to have you`
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: "Account created successfylly" });


    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.json({ success: false, message: "All fields are required" });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Invalid email" });
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            return res.json({ success: false, message: "Invalid password" });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true, message: "Login successful" });

    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }
}

export const logout = async (req, res) => {

    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });

        return res.json({ success: true, message: "Logged out" });
    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });
    }

}

export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);
        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account is already verified" });
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyotp = otp;
        user.verifyotpExpireAt = Date.now() + 24 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account verification",
            // text: `Your otp is ${otp}`
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)

        }
        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "Otp sent" });

    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }
}


export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;
    if (!userId || !otp) {
        return res.json({ success: false, message: "All fields are required" });

    }
    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({ success: false, message: "user not found" });
        }
        if (user.verifyotp === '' || user.verifyotp !== otp) {
            return res.json({ success: false, message: "Invalid otp" });

        }
        if (user.verifyotpExpireAt < Date.now()) {
            return res.json({ success: false, message: "Otp expired" });

        }
        user.isAccountVerified = true;
        user.verifyotp = '';
        user.verifyotpExpireAt = 0;
        await user.save();
        return res.json({ success: true, message: "Account verified" });




    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }

}

export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true, });
    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }
}

//? Send reset otp

export const sendResetOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.json({ success: false, message: "Email is required" });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Email not found" });
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Reset password",
            // text: `Your otp is ${otp}`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)

        }
        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "resetOtp sent" });

    } catch (error) {

        res.json({ success: false, message: "Something went wrong" });
    }
}

//?Reset password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "All fields are required" });

    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Email not found" });
        }
        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid otp" });

        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "Otp expired" });

        }
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();
        return res.json({ success: true, message: "Password reset successfull" });


    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }
}


