import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ success: false, message: "Not authorized. Please login again." });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        if (tokenDecode && tokenDecode.id) {
            req.body.userId = tokenDecode.id;
            next();
        } else {
            return res.status(401).json({ success: false, message: "Not authorized. Please login again." });
        }
    } catch (error) {
        res.status(401).json({ success: false, message: "Invalid or expired token." });
    }
};

export default userAuth;