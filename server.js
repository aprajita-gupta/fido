const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

app.use(helmet());
app.use(morgan('tiny'));
app.use(rateLimit({ windowMs: 60_000, max: 120 })); // tweak as needed

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['owner', 'doctor', 'hospital'], required: true },
  phone: String,
  location: {
    latitude: Number,
    longitude: Number,
    address: String,
    pincode: String
  },
  registeredAt: { type: Date, default: Date.now }
});

const hospitalSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: String,
  address: String,
  pincode: String,
  latitude: Number,
  longitude: Number,
  contact: String,
  openingTime: String,
  closingTime: String,
  bloodInventory: {
    A: { type: Number, default: 0 },
    B: { type: Number, default: 0 },
    AB: { type: Number, default: 0 },
    O: { type: Number, default: 0 }
  },
  lastUpdated: { type: Date, default: Date.now }
});

const clinicSchema = new mongoose.Schema({
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  clinicName: String,
  address: String,
  pincode: String,
  latitude: Number,
  longitude: Number,
  contact: String,
  openingTime: String,
  closingTime: String,
  lastUpdated: { type: Date, default: Date.now }
});

const appointmentSchema = new mongoose.Schema({
  patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  providerType: { type: String, enum: ['hospital', 'doctor'] },
  petName: String,
  appointmentDate: Date,
  appointmentTime: String,
  description: String,
  status: { type: String, enum: ['pending', 'confirmed', 'completed', 'cancelled'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const emergencyRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  dogName: String,
  bloodType: String,
  description: String,
  location: {
    latitude: Number,
    longitude: Number
  },
  timestamp: { type: Date, default: Date.now },
  status: { type: String, default: 'pending' },
  notifiedHospitals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Hospital' }]
});

const User = mongoose.model('User', userSchema);
const Hospital = mongoose.model('Hospital', hospitalSchema);
const Clinic = mongoose.model('Clinic', clinicSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const EmergencyRequest = mongoose.model('EmergencyRequest', emergencyRequestSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.sendStatus(401);
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Helper functions
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

function isOpen(openingTime, closingTime) {
  if (!openingTime || !closingTime) return 'Unknown';
  
  const now = new Date();
  const currentTime = now.getHours() * 60 + now.getMinutes();
  
  const [openHour, openMin] = openingTime.split(':').map(Number);
  const [closeHour, closeMin] = closingTime.split(':').map(Number);
  
  const openTime = openHour * 60 + openMin;
  const closeTime = closeHour * 60 + closeMin;
  
  if (closeTime > openTime) {
    return currentTime >= openTime && currentTime <= closeTime ? 'Open' : 'Closed';
  } else {
    return currentTime >= openTime || currentTime <= closeTime ? 'Open' : 'Closed';
  }
}

function validatePhone(phone) {
  const phoneRegex = /^\d{10}$/;
  return phoneRegex.test(phone);
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePincode(pincode) {
  const pincodeRegex = /^\d{6}$/;
  return pincodeRegex.test(pincode);
}

// Routes

// User Routes
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password, role, phone, location } = req.body;
    
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    if (!validatePhone(phone)) {
      return res.status(400).json({ error: 'Phone number must be exactly 10 digits' });
    }
    
    if ((role === 'hospital' || role === 'doctor') && location?.pincode && !validatePincode(location.pincode)) {
      return res.status(400).json({ error: 'Pincode must be exactly 6 digits' });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role,
      phone,
      location
    });
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        location: user.location
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        location: user.location
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update user profile
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, location, currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (phone && !validatePhone(phone)) {
      return res.status(400).json({ error: 'Phone number must be exactly 10 digits' });
    }
    
    if ((user.role === 'hospital' || user.role === 'doctor') && location?.pincode && !validatePincode(location.pincode)) {
      return res.status(400).json({ error: 'Pincode must be exactly 6 digits' });
    }
    
    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (location) user.location = { ...user.location, ...location };
    
    if (currentPassword && newPassword) {
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      user.password = await bcrypt.hash(newPassword, 10);
    }
    
    await user.save();
    
    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        location: user.location
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Hospital Routes
app.post('/api/hospitals', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'hospital') {
      return res.status(403).json({ error: 'Only hospital admins can manage hospitals' });
    }
    
    const { pincode } = req.body;
    if (pincode && !validatePincode(pincode)) {
      return res.status(400).json({ error: 'Pincode must be exactly 6 digits' });
    }
    
    const existing = await Hospital.findOne({ adminId: req.user.userId });
    if (existing) {
      const updated = await Hospital.findByIdAndUpdate(existing._id, {
        ...req.body,
        adminId: req.user.userId
      }, { new: true });
      return res.json(updated);
    }
    
    const hospital = new Hospital({
      ...req.body,
      adminId: req.user.userId
    });
    await hospital.save();
    res.status(201).json(hospital);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/hospitals', async (req, res) => {
  try {
    const hospitals = await Hospital.find().populate('adminId', 'name email phone');
    res.json(hospitals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/hospitals/my', authenticateToken, async (req, res) => {
  try {
    const hospital = await Hospital.findOne({ adminId: req.user.userId });
    res.json(hospital);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get nearest hospitals
app.get('/api/hospitals/nearest', async (req, res) => {
  try {
    const { latitude, longitude } = req.query;
    
    if (!latitude || !longitude) {
      return res.status(400).json({ error: 'Location coordinates required' });
    }
    
    const userLat = parseFloat(latitude);
    const userLon = parseFloat(longitude);
    
    const hospitals = await Hospital.find().populate('adminId', 'name phone');
    
    const hospitalsWithDistance = hospitals
      .filter(hospital => {
        const totalBlood = hospital.bloodInventory.A + hospital.bloodInventory.B + 
                          hospital.bloodInventory.AB + hospital.bloodInventory.O;
        return totalBlood > 0;
      })
      .map(hospital => {
        const distance = calculateDistance(
          userLat, userLon, 
          hospital.latitude || 0, 
          hospital.longitude || 0
        );
        
        return {
          ...hospital.toObject(),
          distance: distance.toFixed(1),
          status: isOpen(hospital.openingTime, hospital.closingTime)
        };
      })
      .sort((a, b) => parseFloat(a.distance) - parseFloat(b.distance));
    
    res.json(hospitalsWithDistance);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Clinic Routes
app.post('/api/clinics', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'doctor') {
      return res.status(403).json({ error: 'Only veterinarians can create clinics' });
    }
    
    const { pincode } = req.body;
    if (pincode && !validatePincode(pincode)) {
      return res.status(400).json({ error: 'Pincode must be exactly 6 digits' });
    }
    
    const existing = await Clinic.findOne({ doctorId: req.user.userId });
    if (existing) {
      const updated = await Clinic.findByIdAndUpdate(existing._id, {
        ...req.body,
        doctorId: req.user.userId
      }, { new: true });
      return res.json(updated);
    }
    
    const clinic = new Clinic({
      ...req.body,
      doctorId: req.user.userId
    });
    await clinic.save();
    res.status(201).json(clinic);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/clinics', async (req, res) => {
  try {
    const clinics = await Clinic.find().populate('doctorId', 'name email phone');
    const clinicsWithStatus = clinics.map(clinic => ({
      ...clinic.toObject(),
      status: isOpen(clinic.openingTime, clinic.closingTime)
    }));
    res.json(clinicsWithStatus);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/clinics/my', authenticateToken, async (req, res) => {
  try {
    const clinic = await Clinic.findOne({ doctorId: req.user.userId });
    res.json(clinic);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Appointment Routes
app.post('/api/appointments', authenticateToken, async (req, res) => {
  try {
    const appointment = new Appointment({
      ...req.body,
      patientId: req.user.userId
    });
    await appointment.save();
    res.status(201).json(appointment);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/appointments/my', authenticateToken, async (req, res) => {
  try {
    let appointments;
    
    if (req.user.role === 'owner') {
      appointments = await Appointment.find({ patientId: req.user.userId })
        .populate('providerId', 'name phone')
        .sort({ appointmentDate: 1 });
    } else {
      appointments = await Appointment.find({ providerId: req.user.userId })
        .populate('patientId', 'name phone')
        .sort({ appointmentDate: 1 });
    }
    
    res.json(appointments);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/appointments/:id', authenticateToken, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    
    if (appointment.providerId.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const updated = await Appointment.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    ).populate('patientId', 'name phone');
    
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Emergency Routes
app.post('/api/emergency', authenticateToken, async (req, res) => {
  try {
    const emergency = new EmergencyRequest({
      ...req.body,
      userId: req.user.userId
    });
    await emergency.save();
    
    // Notify nearby hospitals
    const hospitals = await Hospital.find({
      [`bloodInventory.${req.body.bloodType}`]: { $gt: 0 }
    }).populate('adminId', 'name phone email');
    
    // In a real application, you would send actual notifications here
    // For now, we'll just log the notifications
    hospitals.forEach(hospital => {
      console.log(`EMERGENCY NOTIFICATION: ${hospital.name} - Contact ${hospital.adminId.phone} for ${req.body.bloodType} blood for ${req.body.dogName}`);
    });
    
    res.status(201).json({
      ...emergency.toObject(),
      notifiedHospitals: hospitals.length
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/emergency', authenticateToken, async (req, res) => {
  try {
    const requests = await EmergencyRequest.find().populate('userId', 'name email phone');
    res.json(requests);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get user contact info for emergency calls
app.get('/api/users/:id/contact', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('name phone email');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT || 5000, () => {
      console.log(`Server running on port ${process.env.PORT || 5000}`);
      console.log(`Open http://localhost:${process.env.PORT || 5000} in your browser`);
    });
  })
  .catch((err) => console.error('Database connection error:', err));
