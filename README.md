# LAWFULLY_FLARE - Immigration Case Management System

## Table of Contents
1. [Project Overview](#project-overview)
2. [Prerequisites](#prerequisites)
3. [Environment Setup](#environment-setup)
4. [Installation](#installation)
5. [Running Locally](#running-locally)
6. [Deployment](#deployment)
7. [Testing](#testing)
8. [Production Best Practices](#production-best-practices)

## Project Overview
This application is a case management system for immigration law services, providing both backend API services and a frontend user interface.

## Prerequisites
Before you begin, ensure you have the following installed:
- Node.js (v16.x or later)
- npm (v8.x or later)
- Python (v3.9 or later)
- PostgreSQL (v12 or later)
- Git

## Environment Setup

### Backend
1. Create a `.env` file in the backend directory:
   ```bash
   cd backend
   touch .env
   ```
2. Add the following environment variables to `.env`:
   ```
   DATABASE_URL=postgres://username:password@localhost:5432/lawfully_flare
   SECRET_KEY=your-secret-key
   DEBUG=True
   ```

### Frontend
1. Create a `.env` file in the frontend directory:
   ```bash
   cd frontend
   touch .env
   ```
2. Add the following environment variables to `.env`:
   ```
   REACT_APP_API_URL=http://localhost:5001
   ```

## Installation

### Backend
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Frontend
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

## Running Locally

### Backend
1. Run migrations:
   ```bash
   python manage.py migrate
   ```
2. Start the development server:
   ```bash
   python manage.py runserver
   ```

### Frontend
1. Start the development server:
   ```bash
   npm start
   ```

## Deployment

### Deployment with PM2

1. Start the backend server with PM2:
   ```bash
   cd backend
   pm2 start index.js --name backend --watch --port 5002
   ```

2. Start the frontend server with PM2:
   ```bash
   cd frontend
   pm2 start npm --name frontend -- start -- --port 5001
   ```

3. Save the PM2 process list to ensure processes are restored on restart:
   ```bash
   pm2 save
   ```

4. To monitor the running processes:
   ```bash
   pm2 list
   ```

5. Access the application:
   - Frontend: http://localhost:5001
   - Backend API: http://localhost:5002

### Backend
1. Prepare static files:
   ```bash
   python manage.py collectstatic
   ```
2. Deploy using your preferred platform (e.g., Heroku, AWS, DigitalOcean).

### Frontend
1. Build the production files:
   ```bash
   npm run build
   ```
2. Deploy using your preferred platform (e.g., Netlify, Vercel, AWS).

## Testing

### Backend
1. Run unit tests:
   ```bash
   python manage.py test
   ```

### Frontend
1. Run unit tests:
   ```bash
   npm test
   ```

## Production Best Practices
1. Use HTTPS for all API and frontend endpoints.
2. Set up proper logging and monitoring.
3. Regularly update dependencies and apply security patches.
4. Use environment variables for sensitive data.
5. Implement rate limiting and other security measures.

# LAWFULLY_FLARE - Immigration Case Management System

## Overview

The LAWFULLY_FLARE Immigration Case Management System is a comprehensive solution designed to streamline the management, processing, and tracking of immigration cases. Built with a modern tech stack, this application provides legal professionals, clients, and administrators with a robust platform to handle complex immigration workflows, document management, and case communications.

## Features

### Core Functionality
- **Case Management Dashboard**: Centralized overview of all active cases with status tracking
- **Document Management**: Secure storage, organization, and retrieval of case-related documents
- **Client Portal**: Self-service access for clients to view case status and submit information
- **Automated Notifications**: Email and in-app alerts for case updates, deadlines, and appointments
- **Task Management**: Assignment and tracking of case-related tasks
- **Calendar Integration**: Schedule and manage appointments, deadlines, and reminders
- **Form Generation**: Auto-filling and generation of standard immigration forms

### Advanced Logging System
The application implements a robust logging system across all components:

#### Logger Configuration (src/config/logger.js)
- Configures Winston logger with multiple log levels (error, warn, info, http, debug)
- Implements colorized console output for development environments
- Sets up file transport for production environments:
  - `error.log` for error-level logs
  - `combined.log` for all logs
- Includes timestamps and consistent formatting for all log messages

#### Logger Utilities (src/utils/loggerUtils.js)
- Provides specialized utility functions for different logging needs:
  - `logError`: Captures error details with context and stack traces
  - `logInfo`: Records general application information and events
  - `logWarning`: Documents potential issues requiring attention
  - `logDebug`: Stores detailed debugging information for development
- Implements context-aware logging with metadata for effective troubleshooting

## Technology Stack

### Frontend
- **React**: Component-based UI library
- **Redux**: State management
- **Material-UI**: Component library for consistent design
- **Axios**: HTTP client for API calls
- **Jest & React Testing Library**: Testing framework
- **Winston**: Logging library

### Backend
- **Node.js**: JavaScript runtime
- **Express**: Web application framework
- **MongoDB**: Document database for case data
- **Mongoose**: MongoDB object modeling
- **JWT**: Authentication and authorization
- **Multer**: File upload handling
- **Winston**: Logging infrastructure

### DevOps
- **Docker**: Containerization
- **GitHub Actions**: CI/CD pipeline
- **Automated Testing**: Integrated test suite
- **AWS**: Deployment infrastructure

## Setup Instructions

### Prerequisites
- Node.js (v14+)
- MongoDB (v4.4+)
- npm or yarn
- Git

### Development Environment Setup
1. Clone the repository:
   ```
   git clone https://github.com/Ryan-ai-champ/LAWFULLY_FLARE.git
   cd LAWFULLY_FLARE
   ```

2. Install dependencies:
   ```
   # Install backend dependencies
   npm install
   
   # Install frontend dependencies
   cd frontend
   npm install
   cd ..
   ```

3. Set up environment variables:
   - Create a `.env` file in the root directory
   - Add necessary variables (reference `.env.example` for required fields)

4. Start the development servers:
   ```
   # Start backend server
   npm run dev
   
   # In a separate terminal, start frontend
   cd frontend
   npm start
   ```

5. The application will be available at:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5002

### Production Deployment
Refer to the deployment documentation in `docs/deployment.md` for detailed instructions on setting up a production environment.

## Architecture Overview

The Immigration Case Management System follows a microservices architecture pattern:

### System Components
- **Authentication Service**: Handles user registration, login, and session management
- **Case Management Service**: Core business logic for case processing
- **Document Service**: Manages document uploads, storage, and retrieval
- **Notification Service**: Handles emails, alerts, and reminders
- **Client Portal**: User interface for clients
- **Admin Dashboard**: Interface for staff and administrators

### Data Flow
1. Requests from clients/admin interfaces are authenticated by the Auth Service
2. Validated requests are routed to appropriate microservices
3. Services process requests and interact with the database layer
4. Responses are returned through the API gateway
5. All significant events are captured by the logging system

## Contributing Guidelines

### Development Workflow
1. Create a feature branch from `main`:
   ```
   git checkout -b feature/your-feature-name
   ```

2. Implement your changes with appropriate tests
3. Follow the code style guidelines in `.eslintrc`
4. Submit a pull request against the `main` branch
5. Ensure CI checks pass before requesting review

### Code Standards
- Use TypeScript for type safety
- Follow established naming conventions
- Write unit tests for all new features
- Document API endpoints using JSDoc
- Use the logging utilities for all error handling

## Security Measures

The Immigration Case Management System implements various security features:

- **Authentication**: JWT-based with refresh token rotation
- **Authorization**: Role-based access control system
- **Data Encryption**: Sensitive data encrypted at rest and in transit
- **Input Validation**: Server-side validation for all user inputs
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Comprehensive logging of security events
- **Regular Updates**: Dependency monitoring and updates
- **Secure Headers**: Implementation of security-related HTTP headers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support or questions, please contact the development team at support@lawfullyflare.com or open an issue in the repository.

---

© 2023 LAWFULLY_FLARE. All rights reserved.
