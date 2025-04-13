const express = require("express");
const mongoose = require("mongoose");
const shortid = require("shortid");
const validUrl = require("valid-url");
const useragent = require("useragent");
const cors = require("cors");
const geoip = require("geoip-lite");
const jwt = require("jsonwebtoken"); // Add JWT
const bcrypt = require("bcryptjs"); // Add bcrypt for password hashing

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "your_jwt_secret_key"; // Replace with env variable in production

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// MongoDB Connection
mongoose
  .connect("mongodb://localhost:27017/url-shortener", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// URL Schema
const urlSchema = new mongoose.Schema({
  originalUrl: { type: String, required: true },
  shortUrl: String,
  urlCode: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // Add userId
  clicks: [
    {
      timestamp: { type: Date, default: Date.now },
      deviceType: { type: String, enum: ["PC", "Mobile", "Unknown"] },
      country: { type: String, default: "Unknown" },
    },
  ],
});

const Url = mongoose.model("Url", urlSchema);
const initializeUser = async () => {
  const email = "intern@dacoid.com";
  const password = "Test123";
  try {
    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ email, password: hashedPassword });
      await user.save();
      console.log("Hardcoded user created:", email);
    }
  } catch (err) {
    console.error("Error initializing user:", err);
  }
};
initializeUser();

const baseUrl = "http://localhost:3000";

// Middleware to Verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// Login Endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Create Short URL (Authenticated)
app.post("/api/shorten", authenticateToken, async (req, res) => {
  const { originalUrl } = req.body;

  if (!validUrl.isUri(originalUrl)) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    let url = await Url.findOne({ originalUrl, userId: req.user.userId });

    if (url) {
      return res.json(url);
    }

    const urlCode = shortid.generate();
    const shortUrl = `${baseUrl}/${urlCode}`;

    url = new Url({
      originalUrl,
      shortUrl,
      urlCode,
      userId: req.user.userId, // Store userId
    });

    await url.save();
    res.json(url);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Redirect and Log Click (No Auth)
app.get("/:code", async (req, res) => {
  try {
    const url = await Url.findOne({ urlCode: req.params.code });
    if (!url) return res.status(404).json({ error: "URL not found" });

    const agent = useragent.parse(req.headers["user-agent"]);
    const isMobile =
      agent.isMobile || agent.isAndroid || agent.isiPhone || agent.isiPad;
    const deviceType = isMobile ? "Mobile" : "PC";

    const ip = req.ip === "::1" ? "127.0.0.1" : req.ip;
    const geo = geoip.lookup(ip);
    const country = geo ? geo.country : "Unknown";

    Url.updateOne(
      { _id: url._id },
      {
        $push: {
          clicks: {
            timestamp: new Date(),
            deviceType,
            country,
          },
        },
      }
    ).exec();

    res.redirect(url.originalUrl);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Analytics for a URL (No Auth)
app.get("/api/urls/:id/analytics", async (req, res) => {
  try {
    const url = await Url.findById(req.params.id);
    if (!url) return res.status(404).json({ error: "URL not found" });

    const totalClicks = url.clicks.length;
    const deviceBreakdown = url.clicks.reduce(
      (acc, click) => {
        acc[click.deviceType] = (acc[click.deviceType] || 0) + 1;
        return acc;
      },
      { PC: 0, Mobile: 0, Unknown: 0 }
    );
    const locationBreakdown = url.clicks.reduce(
      (acc, click) => {
        acc[click.country] = (acc[click.country] || 0) + 1;
        return acc;
      },
      { Unknown: 0 }
    );

    res.json({
      totalClicks,
      deviceBreakdown,
      locationBreakdown,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get All URLs for Authenticated User
app.get("/api/urls", authenticateToken, async (req, res) => {
  const { page = 1, limit = 10, search = "" } = req.query;

  try {
    const query = {
      originalUrl: { $regex: search, $options: "i" },
      userId: req.user.userId, // Filter by userId
    };

    const urls = await Url.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await Url.countDocuments(query);

    res.json({
      urls,
      totalPages: Math.ceil(total / limit),
      currentPage: page * 1,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
