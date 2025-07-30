// README.md
# Blood Bank Management System

## Setup Instructions

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local installation or MongoDB Atlas)

### Installation Steps

1. **Create project directory:**
   ```bash
   mkdir blood-bank-system
   cd blood-bank-system
   ```

2. **Initialize the project:**
   ```bash
   npm init -y
   ```

3. **Install dependencies:**
   ```bash
   npm install express mongoose cors dotenv bcryptjs jsonwebtoken
   npm install -D nodemon
   ```

4. **Create folder structure:**
   ```
   blood-bank-system/
   ├── server.js
   ├── package.json
   ├── .env
   ├── public/
   │   └── index.html
   └── README.md
   ```

5. **Setup MongoDB:**
   - **Local MongoDB:** Install MongoDB and start the service
   - **MongoDB Atlas:** Create a cluster and get connection string

6. **Configure environment variables (.env):**
   ```
   MONGO_URI=mongodb://localhost:27017/bloodbank
   JWT_SECRET=your_secret_key_here
   PORT=5000
   ```

7. **Start the application:**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

8. **Access the application:**
   Open your browser and go to `http://localhost:5000`

### Features

- **User Authentication:** Register and login with JWT tokens
- **Role-based Access:** Pet owners, veterinarians, and hospital admins
- **Emergency Requests:** Submit urgent blood requests
- **Hospital Management:** Manage blood inventory
- **Search Functionality:** Find hospitals with available blood types
- **Responsive Design:** Works on desktop and mobile devices

### User Roles

1. **Pet Owner:** Can submit emergency blood requests
2. **Veterinarian:** Can view requests and manage hospital data
3. **Hospital Admin:** Can manage hospital information and blood inventory

### API Endpoints

- `POST /api/users/register` - User registration
- `POST /api/users/login` - User login
- `GET /api/hospitals` - Get all hospitals
- `POST /api/hospitals` - Create/update hospital
- `POST /api/emergency` - Submit emergency request
- `GET /api/emergency` - Get all emergency requests
- `GET /api/emergency/search` - Search hospitals by blood type

### Database Schema

#### Users
- name, email, password (hashed)
- role (owner/doctor/hospital)
- phone, location, registeredAt

#### Hospitals
- name, address, latitude, longitude
- contact, bloodInventory (A, B, AB, O)
- lastUpdated

#### Emergency Requests
- userId (ref to User), dogName, bloodType
- description, location, timestamp, status

### Security Features

- Password hashing with bcryptjs
- JWT token authentication
- CORS enabled
- Input validation
- Protected routes

### Troubleshooting

1. **MongoDB Connection Issues:**
   - Check if MongoDB service is running
   - Verify connection string in .env file
   - For Atlas, check network access and database user permissions

2. **Port Already in Use:**
   - Change PORT in .env file
   - Kill existing processes: `lsof -ti:5000 | xargs kill -9`

3. **JWT Errors:**
   - Ensure JWT_SECRET is set in .env
   - Check token expiration (24h default)

### Development Notes

- Frontend is served from `/public/index.html`
- API routes are prefixed with `/api`
- Authentication required for creating hospitals and emergency requests
- Responsive design works on all screen sizes
- Local storage used for session persistence 