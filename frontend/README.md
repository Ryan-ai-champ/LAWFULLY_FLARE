# Lawfully Flare - Immigration Case Management System

## Project Overview
Lawfully Flare is a comprehensive immigration case management web application designed to streamline the handling of immigration cases. It provides features for case management, document handling, search functionality, and more, all in a user-friendly interface.

## Installation Instructions

### Prerequisites
- Node.js (v16 or higher)
- npm (v8 or higher)
- PostgreSQL (v12 or higher)

### Step-by-Step Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repository/LAWFULLY_FLARE.git
   ```
2. Navigate to the project directory:
   ```bash
   cd LAWFULLY_FLARE
   ```
3. Install backend dependencies:
   ```bash
   cd backend && npm install
   ```
4. Install frontend dependencies:
   ```bash
   cd ../frontend && npm install
   ```
5. Set up the database:
   ```bash
   cd ../backend
   npx sequelize-cli db:create
   npx sequelize-cli db:migrate
   npx sequelize-cli db:seed:all
   ```

## Feature Documentation
- **Case Management**: Create, edit, and manage immigration cases with detailed tracking.
- **Document Handling**: Upload, download, and manage case-related documents.
- **Search Functionality**: Advanced search across cases and documents with filtering options.
- **PDF Viewer**: View and annotate PDF documents with advanced features like text search, zooming, and thumbnail navigation.

## Usage Examples

### Adding a New Case
1. Navigate to the "Cases" section.
2. Click "Add New Case".
3. Fill in the case details and upload any relevant documents.
4. Click "Save" to create the case.

### Searching for a Case
1. Go to the "Search" section.
2. Enter search terms or use advanced filters like date range or page range.
3. Click "Search" to view results.

### Viewing a PDF Document
1. Navigate to a case and click "Documents".
2. Click on a PDF file to open the viewer.
3. Use features like text search, zooming, or annotations as needed.

## API References
The backend API is documented using Swagger. Access the API documentation at:
`http://localhost:3000/api-docs`

Key endpoints include:
- `GET /cases`: Retrieve a list of cases
- `POST /cases`: Create a new case
- `GET /cases/:id`: Get details of a specific case
- `POST /documents/upload`: Upload a document

## Contribution Guidelines
We welcome contributions from the community! Here's how you can help:
1. Fork the repository
2. Create a new branch for your feature/fix
3. Commit your changes
4. Push to the branch
5. Submit a pull request

Please ensure your code follows our coding standards and includes appropriate tests.

## License Information
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

