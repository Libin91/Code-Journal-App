import jwt from "jsonwebtoken";

const verifyToken = (res, req, next) => {
    let token = req.headers["x-access-token"];

    if(!token) {
        return res.status(403).send({ message: "No token provided!" });
    }
    jwt.verify(token, "segretissimo", (err, decoded) => {
        if (err) {
            return res.status(401).send({ message:"Unauthorised!" });
        }
        req.userId = decoded.id;
        next();
    });
};

export default verifyToken;