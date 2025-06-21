// Peace Lover Backend API
// A comprehensive Node.js/Express backend for the peace lover website

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/peacelover', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 30,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Invalid email address']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  avatar: {
    type: String,
    default: null
  },
  role: {
    type: String,
    enum: ['user', 'moderator', 'admin'],
    default: 'user'
  },
  peacePoints: {
    type: Number,
    default: 0
  },
  joinedAt: {
    type: Date,
    default: Date.now
  },
  lastActive: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  },
  bio: {
    type: String,
    maxlength: 500
  },
  location: {
    type: String,
    maxlength: 100
  }
}, {
  timestamps: true
});

const User = mongoose.model('User', userSchema);

// Peace Message Schema
const messageSchema = new mongoose.Schema({
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: 1000
  },
  category: {
    type: String,
    enum: ['inspiration', 'story', 'quote', 'action', 'gratitude'],
    required: true
  },
  tags: [{
    type: String,
    maxlength: 50
  }],
  likes: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    likedAt: {
      type: Date,
      default: Date.now
    }
  }],
  comments: [{
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    content: {
      type: String,
      maxlength: 500
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  featured: {
    type: Boolean,
    default: false
  },
  image: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

const PeaceMessage = mongoose.model('PeaceMessage', messageSchema);

// Event Schema
const eventSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    maxlength: 200
  },
  description: {
    type: String,
    required: true,
    maxlength: 2000
  },
  organizer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  date: {
    type: Date,
    required: true
  },
  location: {
    address: String,
    city: String,
    country: String,
    coordinates: {
      lat: Number,
      lng: Number
    }
  },
  category: {
    type: String,
    enum: ['meditation', 'workshop', 'march', 'fundraiser', 'community', 'online'],
    required: true
  },
  maxAttendees: {
    type: Number,
    default: null
  },
  attendees: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    registeredAt: {
      type: Date,
      default: Date.now
    }
  }],
  image: {
    type: String,
    default: null
  },
  isVirtual: {
    type: Boolean,
    default: false
  },
  meetingLink: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

const Event = mongoose.model('Event', eventSchema);

// Middleware for authentication
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'peaceful_secret_key');
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid or inactive user' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Authorization middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Peace Lover API is running',
    timestamp: new Date().toISOString()
  });
});

// User Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, bio, location } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or username already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      bio,
      location,
      peacePoints: 10 // Welcome bonus
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'peaceful_secret_key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        peacePoints: user.peacePoints,
        bio: user.bio,
        location: user.location
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'peaceful_secret_key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        peacePoints: user.peacePoints,
        bio: user.bio,
        location: user.location,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Profile Routes
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { username, bio, location } = req.body;
    const userId = req.user._id;

    const updateData = {};
    if (username) updateData.username = username;
    if (bio !== undefined) updateData.bio = bio;
    if (location !== undefined) updateData.location = location;

    const user = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: 'Username already taken' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

app.post('/api/users/avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.user._id;
    const avatarPath = `/uploads/${req.file.filename}`;

    await User.findByIdAndUpdate(userId, { avatar: avatarPath });

    res.json({ 
      message: 'Avatar updated successfully', 
      avatar: avatarPath 
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Peace Messages Routes
app.get('/api/messages', async (req, res) => {
  try {
    const { page = 1, limit = 10, category, featured } = req.query;
    const skip = (page - 1) * limit;

    const filter = {};
    if (category) filter.category = category;
    if (featured === 'true') filter.featured = true;

    const messages = await PeaceMessage.find(filter)
      .populate('author', 'username avatar peacePoints')
      .populate('comments.author', 'username avatar')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await PeaceMessage.countDocuments(filter);

    res.json({
      messages,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/messages', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { content, category, tags } = req.body;

    if (!content || !category) {
      return res.status(400).json({ error: 'Content and category are required' });
    }

    const messageData = {
      author: req.user._id,
      content,
      category,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : []
    };

    if (req.file) {
      messageData.image = `/uploads/${req.file.filename}`;
    }

    const message = new PeaceMessage(messageData);
    await message.save();

    // Award peace points
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { peacePoints: 5 }
    });

    const populatedMessage = await PeaceMessage.findById(message._id)
      .populate('author', 'username avatar peacePoints');

    res.status(201).json({
      message: 'Peace message created successfully',
      data: populatedMessage
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/messages/:id/like', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const userId = req.user._id;

    const message = await PeaceMessage.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const existingLike = message.likes.find(like => like.user.toString() === userId.toString());

    if (existingLike) {
      // Unlike
      message.likes = message.likes.filter(like => like.user.toString() !== userId.toString());
    } else {
      // Like
      message.likes.push({ user: userId });
      
      // Award peace points to message author
      await User.findByIdAndUpdate(message.author, {
        $inc: { peacePoints: 1 }
      });
    }

    await message.save();

    res.json({
      message: existingLike ? 'Message unliked' : 'Message liked',
      likesCount: message.likes.length,
      isLiked: !existingLike
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/messages/:id/comment', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Comment content is required' });
    }

    const message = await PeaceMessage.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    message.comments.push({
      author: req.user._id,
      content
    });

    await message.save();

    // Award peace points
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { peacePoints: 2 }
    });

    const updatedMessage = await PeaceMessage.findById(messageId)
      .populate('comments.author', 'username avatar');

    res.json({
      message: 'Comment added successfully',
      comments: updatedMessage.comments
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Events Routes
app.get('/api/events', async (req, res) => {
  try {
    const { page = 1, limit = 10, category, upcoming } = req.query;
    const skip = (page - 1) * limit;

    const filter = {};
    if (category) filter.category = category;
    if (upcoming === 'true') filter.date = { $gte: new Date() };

    const events = await Event.find(filter)
      .populate('organizer', 'username avatar')
      .populate('attendees.user', 'username avatar')
      .sort(upcoming === 'true' ? { date: 1 } : { createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Event.countDocuments(filter);

    res.json({
      events,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/events', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, location, category, maxAttendees, isVirtual, meetingLink } = req.body;

    if (!title || !description || !date || !category) {
      return res.status(400).json({ error: 'Title, description, date, and category are required' });
    }

    const eventData = {
      title,
      description,
      organizer: req.user._id,
      date: new Date(date),
      category,
      maxAttendees: maxAttendees ? parseInt(maxAttendees) : null,
      isVirtual: isVirtual === 'true',
      meetingLink
    };

    if (location) {
      try {
        eventData.location = JSON.parse(location);
      } catch {
        eventData.location = { address: location };
      }
    }

    if (req.file) {
      eventData.image = `/uploads/${req.file.filename}`;
    }

    const event = new Event(eventData);
    await event.save();

    // Award peace points
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { peacePoints: 10 }
    });

    const populatedEvent = await Event.findById(event._id)
      .populate('organizer', 'username avatar');

    res.status(201).json({
      message: 'Event created successfully',
      event: populatedEvent
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/events/:id/join', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user._id;

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const alreadyJoined = event.attendees.find(
      attendee => attendee.user.toString() === userId.toString()
    );

    if (alreadyJoined) {
      return res.status(400).json({ error: 'Already joined this event' });
    }

    if (event.maxAttendees && event.attendees.length >= event.maxAttendees) {
      return res.status(400).json({ error: 'Event is full' });
    }

    event.attendees.push({ user: userId });
    await event.save();

    // Award peace points
    await User.findByIdAndUpdate(userId, {
      $inc: { peacePoints: 3 }
    });

    res.json({
      message: 'Successfully joined the event',
      attendeesCount: event.attendees.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const userCount = await User.countDocuments({ isActive: true });
    const messageCount = await PeaceMessage.countDocuments();
    const eventCount = await Event.countDocuments();
    const upcomingEvents = await Event.countDocuments({ date: { $gte: new Date() } });

    res.json({
      users: userCount,
      messages: messageCount,
      events: eventCount,
      upcomingEvents
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/messages/:id/feature', authenticateToken, authorize(['admin', 'moderator']), async (req, res) => {
  try {
    const messageId = req.params.id;
    const { featured } = req.body;

    const message = await PeaceMessage.findByIdAndUpdate(
      messageId,
      { featured: featured === true },
      { new: true }
    ).populate('author', 'username avatar');

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json({
      message: `Message ${featured ? 'featured' : 'unfeatured'} successfully`,
      data: message
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size too large' });
    }
  }
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🕊️ Peace Lover API server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;