import userModel from "../models/userModel.js";

export const getUsers = async (req, res) => {
    try {

        const { userId } = req.body;
        const users = await userModel.findById(userId);
        if (!users) {
            return res.json({ success: false, message: "No user found" });
        }
      res.json({
         success: true,
         userData:{
                name:users.name,
                isAccountVerified:users.isAccountVerified
         }

      });
    } catch (error) {
        res.json({ success: false, message: "Something went wrong" });
    }
}