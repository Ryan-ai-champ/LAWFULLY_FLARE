# Immigration Case Management System

A comprehensive web application for managing immigration cases, built with React, Node.js, and MongoDB.

## Features

### Case Management
- Create, view, update, and delete immigration cases
- Filter and sort cases by type, status, priority
- Document upload and management
- Case status tracking and notifications

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (Admin, Attorney, Paralegal, Client)
- Two-factor authentication
- Password reset functionality

### User Interface
- Modern, responsive design using Material-UI
- Real-time notifications
- Dashboard with case analytics
- Document preview and download

## Tech Stack

### Frontend
- React 18
- Redux Toolkit for state management
- Material-UI for components
- React Router for navigation
- Axios for API calls

### Backend
- Node.js with Express
- MongoDB with Mongoose
- JWT for authentication
- Redis for caching
- Multer for file uploads

### DevOps
- Docker and Docker Compose
- GitHub Actions for CI/CD
- Jest for testing
- ESLint and Prettier for code quality

## Getting Started

### Prerequisites
- Node.js (v16 or higher)
- MongoDB
- Redis
- Docker (optional)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Ryan-ai-champ/New_Team_Flare_Hackathon.git
   cd New_Team_Flare_Hackathon
   ```

2. Install dependencies:
   ```bash
   # Install backend dependencies
   cd backend
   npm install

   # Install frontend dependencies
   cd ../frontend
   npm install
   ```

3. Set up environment variables:
   Create .env files in both backend and frontend directories using the provided .env.example files.

4. Start the development servers:
   ```bash
   # Start backend server (from backend directory)
   npm run dev

   # Start frontend server (from frontend directory)
   npm start
   ```

### Docker Setup

1. Build and run with Docker Compose:
   ```bash
   docker-compose up --build
   ```

## API Documentation

The API documentation is available at `/api/docs` when running the backend server.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## License

This project is licensed under the MIT License.

## Contact

Ryan Ford - rfor@iu.edu
Project Link: https://github.com/Ryan-ai-champ/New_Team_Flare_Hackathon
