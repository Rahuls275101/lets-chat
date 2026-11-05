import auth from "../config/firebase-config.js";

// HTTP Middleware (API Routes ke liye)
export const VerifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // Header missing ya format galat hone par crash hone ki jagah 401 Unauthorized return karein
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Authorization token missing or invalid" });
    }

    const token = authHeader.split(" ")[1];

    const decodeValue = await auth.verifyIdToken(token);
    if (decodeValue) {
      req.user = decodeValue;
      return next();
    } else {
      return res.status(401).json({ message: "Unauthorized access" });
    }
  } catch (e) {
    console.error("HTTP Auth Verification Error:", e.message);
    return res.status(401).json({ message: "Invalid or expired token", error: e.message });
  }
};

// WebSockets Middleware (Socket.io Connections ke liye)
export const VerifySocketToken = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Authentication token missing"));
    }

    const decodeValue = await auth.verifyIdToken(token);

    if (decodeValue) {
      socket.user = decodeValue;
      return next();
    } else {
      return next(new Error("Authentication failed"));
    }
  } catch (e) {
    console.error("Socket Auth Verification Error:", e.message);
    return next(new Error("Unauthorized socket connection"));
  }
};