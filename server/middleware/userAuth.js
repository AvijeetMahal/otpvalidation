import jwt from "jsonwebtoken";


const userAuth = async (req, res, next) => {
 console.log("Cookies: ", req.cookies);
    const { token } = req.cookies;
    if (!token) {
        return res.json({ success: false, message: "Not authorized Please login again" })
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        if (tokenDecode.id) {
            req.body.userId = tokenDecode.id;
        } else {
            return res.json({ success: false, message: "Not authorized Please login again" })
        }
        next();

    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });

    }


};

export default userAuth;