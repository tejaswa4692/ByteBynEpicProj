# RepodoGG

A comprehensive vulnerability scanning platform for GitHub repositories. RepodoGG helps developers and organizations identify, analyze, and mitigate security vulnerabilities in their open-source dependencies.

## Features

- **Automated Vulnerability Scanning**: Scan GitHub repositories for known vulnerabilities using the Open Source Vulnerabilities (OSV) database
- **User Authentication**: Secure login system using OAuth
- **Repository Management**: Add, scan, and monitor multiple repositories
- **PDF Report Generation**: Generate detailed vulnerability reports in PDF format
- **Certification System**: Certify repositories as secure or compliant
- **Verification Portal**: Verify the authenticity and security status of repositories
- **Blast Radius Analysis**: Analyze the impact and spread of vulnerabilities across dependencies
- **Download Center**: Access generated reports and certificates
- **VS Code Extension**: Integrate vulnerability scanning directly into your development workflow
- **Webhook Integration**: Automated scanning triggered by GitHub events

## Tech Stack

### Backend
- **Python 3.11**
- **FastAPI**: Modern, fast web framework for building APIs
- **Supabase**: PostgreSQL database with real-time capabilities
- **JWT**: Secure authentication
- **FPDF**: PDF report generation

### Frontend
- **React 18**: User interface library
- **Vite**: Fast build tool and development server
- **Tailwind CSS**: Utility-first CSS framework
- **React Router**: Client-side routing
- **Recharts**: Data visualization
- **Radix UI**: Accessible UI components

### Scrapers & Tools
- **Python**: Data scraping and processing
- **OSV API**: Vulnerability database integration
- **GitHub API**: Repository data fetching

### Deployment
- **Render**: Cloud platform for hosting web services

## Installation

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher
- Git

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with the required environment variables:
   ```
   JWT_SECRET=your_jwt_secret
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_key
   GITHUB_TOKEN=your_github_token
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   SMTP_EMAIL=your_smtp_email
   SMTP_PASSWORD=your_smtp_password
   GITHUB_WEBHOOK_SECRET=your_webhook_secret
   WEBHOOK_URL=your_webhook_url
   PINATA_API_KEY=your_pinata_api_key
   PINATA_SECRET_API_KEY=your_pinata_secret_key
   PINATA_JWT=your_pinata_jwt
   ```

4. Run the database setup:
   ```bash
   python setup.sql
   ```

5. Start the backend server:
   ```bash
   uvicorn main:app --reload
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

### VS Code Extension Setup

1. Navigate to the vscode-extension directory:
   ```bash
   cd vscode-extension
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the extension in development mode (requires VS Code Extension Development Host).

## Usage

1. **Login**: Login using your github account
2. **Add Repository**: Enter a GitHub repository URL to scan
3. **View Results**: Browse vulnerability reports and details
4. **Generate Reports**: Download PDF reports of scan results
5. **Certify Repositories**: Mark repositories as certified secure
6. **Verify Certificates**: Check the validity of repository certificates

### API Endpoints

The backend provides RESTful API endpoints for:
- User authentication (`/auth/login`, `/auth/register`)
- Repository management (`/repos`)
- Scanning operations (`/scan`)
- Report generation (`/reports`)
- Certification (`/certify`)

## Deployment

The project is configured for deployment on Render using the provided `render.yaml` file:

1. Connect your GitHub repository to Render
2. Use the `render.yaml` configuration for automatic deployment
3. Set environment variables in Render dashboard
4. Deploy both backend and frontend services

## Project Structure

```
ByteBynEpicProj/
├── AbsoluteMain/          # Standalone scanning script
├── backend/               # FastAPI backend
├── frontend/              # React frontend
├── client/                # Additional client (legacy?)
├── server/                # Node.js server (legacy?)
├── Scraper/               # Data scraping utilities
├── vscode-extension/      # VS Code extension
├── old_backend/           # Previous backend version
└── render.yaml            # Render deployment config
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use ESLint for JavaScript/React code
- Write tests for new features
- Update documentation as needed

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue on GitHub or contact the development team.

## Roadmap

- [ ] Enhanced AI-powered vulnerability analysis
- [ ] Integration with additional vulnerability databases
- [ ] Real-time monitoring and alerts
- [ ] Team collaboration features
- [ ] Mobile application
